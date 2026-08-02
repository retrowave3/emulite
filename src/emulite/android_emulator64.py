from __future__ import annotations

import os
import struct

from emulite._rootfs import resolve_android_rootfs
from emulite.android.android_file_system import AndroidFileSystem
from emulite.android.arm64.android_libc_hooks64 import AndroidLibcHooks64
from emulite.android.arm64.android_syscall_handler64 import AndroidSyscallHandler64
from emulite.android.enums.auxv import Auxv
from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.lang.java_string import JavaString
from emulite.android.java_vm import JavaVM
from emulite.android.jni.enums.jni_version import JNIVersion
from emulite.android.jni.jni_env import JNIEnv
from emulite.android.jni.jni_handler import JniHandler
from emulite.android.jni.jni_mangler import JniMangler
from emulite.android.linker_debug import LinkerDebug
from emulite.android_device import AndroidDevice
from emulite.android_emulator import AndroidEmulatorBase
from emulite.android_profile import AndroidProfile
from emulite.common.errors import (
    EmulatorCrashed,
    JavaExceptionThrown,
    NestedExecution,
    SymbolMissing,
)
from emulite.common.log import LogCategory, Logger, LogLevel
from emulite.cpu.arch.arm64 import Arm64Arch
from emulite.cpu.backend import Backend
from emulite.cpu.registers.arm64_reg import Arm64Reg
from emulite.cpu.unicorn_backend import UnicornBackend
from emulite.hooks.disassembler import Disassembler
from emulite.hooks.hook_manager import HookManager
from emulite.hooks.svc_trap import SvcTrap
from emulite.hooks.unwinder import Unwinder
from emulite.loader import NativeModule, Symbol
from emulite.loader.elf_loader import ElfLoader
from emulite.memory import MemoryLayout, MemoryManager
from emulite.memory.native_pointer import NativePointer


class AndroidEmulator64(AndroidEmulatorBase):
    _VALID_JNI_VERSIONS = frozenset(JNIVersion)

    def __init__(
        self,
        rootfs: str | os.PathLike[str] | None = None,
        *,
        log: LogCategory | Logger = LogCategory.Default,
        profile: AndroidProfile | None = None,
        device: AndroidDevice | None = None,
        jni_handler: JniHandler | None = None,
        search_paths: tuple[str, ...] = (),
        backend: type[Backend] = UnicornBackend,
        strict_syscalls: bool = True,
        syscall_handler: type[AndroidSyscallHandler64] = AndroidSyscallHandler64,
        jni_env: type[JNIEnv] = JNIEnv,
        java_vm: type[JavaVM] = JavaVM,
    ):
        rootfs = resolve_android_rootfs(rootfs)
        self.rootfs = rootfs
        self.log = log if isinstance(log, Logger) else Logger(categories=log)

        self.profile = profile or AndroidProfile()
        root_properties = AndroidDevice.load_build_prop(rootfs)
        self.device = AndroidDevice(root_properties) if device is None else device
        if device is not None:
            self.device.merge(root_properties)
        self.jni_handler = jni_handler or JniHandler()
        self._executing = False
        self._closed = False

        self.arch = Arm64Arch()
        self.backend = backend(self.arch.cpu_arch)
        self.arch.enable_fpu(self.backend)
        self.arch.seed_system_registers(self.backend, self.device)

        self.mem = MemoryManager(self.backend, self.arch, self.log)
        self.linker_debug = LinkerDebug(self)
        self.linker_debug.install()
        self.auxv = self.mem.setup_stack(*self._initial_stack())
        self.mem.setup_tls(self.profile.stack_guard)

        self.trap = SvcTrap(self.backend, self.mem, self.log)
        self._setup_android(rootfs, strict_syscalls, syscall_handler, jni_env, java_vm)

        self.loader = ElfLoader(
            self.backend, self.mem, self.log, rootfs=rootfs, search_paths=search_paths
        )
        self.loader.emu = self
        self.hooks = HookManager(self)
        self.disassembler = Disassembler(self)
        self.loader.resolve_override = self.libc.resolve_override
        self.loader.resolve_fallback = self.libc.resolve_fallback
        self.loader.after_load = (
            self.linker_debug.rebuild
        )  # refresh the r_debug/link_map chain post-load
        self.log.loader(
            "AndroidEmulator64 ready (arm64): %s on %s, rootfs=%s",
            self.profile.package_name,
            self.device.get("ro.product.model"),
            rootfs,
        )

    def _initial_stack(self) -> tuple[list[str], list[str], list[tuple[int, int]], int]:
        p = self.profile
        argv = [p.program_name]
        envp = [f"{key}={value}" for key, value in p.environment_variables.items()]
        auxv = [
            (Auxv.AT_PHDR, self.linker_debug.phdr_addr),
            (Auxv.AT_PHENT, self.linker_debug.phent),
            (Auxv.AT_PHNUM, self.linker_debug.phnum),
            (Auxv.AT_ENTRY, self.linker_debug.entry),
            (Auxv.AT_PAGESZ, MemoryLayout.PAGE_SIZE),
            (Auxv.AT_HWCAP, self.device.HWCAP_ARM64),
            (Auxv.AT_HWCAP2, self.device.HWCAP2_ARM64),
            (Auxv.AT_CLKTCK, 100),
            (Auxv.AT_UID, p.process_uid),
            (Auxv.AT_EUID, p.process_uid),
            (Auxv.AT_GID, p.process_gid),
            (Auxv.AT_EGID, p.process_gid),
            (Auxv.AT_SECURE, 0),
        ]
        return argv, envp, auxv, p.stack_guard

    def _setup_android(
        self,
        rootfs: str,
        strict_syscalls: bool,
        syscall_handler: type[AndroidSyscallHandler64],
        jni_env: type[JNIEnv],
        java_vm: type[JavaVM],
    ) -> None:
        self.vfs = AndroidFileSystem(rootfs, self)
        self.device.bind_memory(self.mem)
        self.syscalls = syscall_handler(self, strict=strict_syscalls)
        self.libc = AndroidLibcHooks64(self)
        self.jni = jni_env(self)
        self.javavm = java_vm(self)

    def load(self, path_or_name: str, scan_only: bool = False) -> NativeModule:
        return self.loader.load(path_or_name, scan_only=scan_only)

    def call_jni_onload(self, module: NativeModule) -> int:
        self.run_pending_init()
        onload = module.find_symbol("JNI_OnLoad")
        if onload is None:
            self.log.jni("%s has no JNI_OnLoad", module.name)
            return self.jni.version
        version = self.call(onload, self.javavm.pointer, 0)
        if version not in self._VALID_JNI_VERSIONS:
            self.log.jni(
                "JNI_OnLoad(%s) => %#x is not a valid JNI version",
                module.name,
                version,
                level=LogLevel.WARN,
            )
        else:
            self.log.jni("JNI_OnLoad(%s) => %#x", module.name, version)
        return version

    def find_symbol(self, name: str) -> int | None:
        return self.loader.find_export(name)

    def find_symbol_or_throw(self, name: str) -> int:
        address = self.loader.find_export(name)
        if address is None:
            raise SymbolMissing(name)
        return address

    def call_symbol(self, name: str, *args: int, **kwargs: object):
        return self.call(self.find_symbol_or_throw(name), *args, **kwargs)

    def get_module(self, name_or_path: str) -> NativeModule | None:
        return self.loader.modules.get(os.path.basename(name_or_path.replace("\\", "/")))

    def module_at(self, address: int) -> NativeModule | None:
        return self.loader.module_at(address)

    @property
    def modules(self) -> list[NativeModule]:
        return list(self.loader.modules.values())

    loaded_modules = modules

    def add_library_path(self, path: str) -> None:
        self.loader._search.append(path)

    def describe_address(self, address: int) -> str:
        module = self.module_at(address)
        if module is None:
            region = self.mem.find_region(address)
            tag = region.label if region and region.label else "unmapped"
            return f"{address:#x} [{tag}]"
        text = f"{module.name}+{module.offset_of(address):#x}"
        hit = module.symbol_at(address)
        if hit is not None:
            sym, delta = hit
            text += f" {sym.name}" + (f"+{delta:#x}" if delta else "")
        return text

    def _symbolize_crash(self, exc: EmulatorCrashed) -> EmulatorCrashed:
        if getattr(exc, "_symbolized", False):
            return exc
        message = f"{exc}  [{self.describe_address(self.pc)}]"
        frames = self.backtrace()
        if len(frames) > 1:
            message += "\n  backtrace:\n" + "\n".join("    " + frame.format() for frame in frames)
        enriched = EmulatorCrashed(message)
        enriched._symbolized = True
        return enriched

    def backtrace(self, max_depth: int = 64) -> list:
        return Unwinder(self).frames(max_depth)

    def add_data_symbol(self, name: str, address: int) -> None:
        self.loader.add_data_symbol(name, address)

    def create_virtual_module(self, name: str, symbols: "dict[str, int] | None" = None):
        return self.loader.create_virtual_module(name, symbols)

    def reg(self, reg_id: int) -> int:
        return self.backend.reg_read(reg_id)

    def set_reg(self, reg_id: int, value: int) -> None:
        self.backend.reg_write(reg_id, value)

    def arg(self, index: int) -> int:
        if index < len(Arm64Reg.ARG_REGS):
            return self.backend.reg_read(Arm64Reg.ARG_REGS[index])
        return self.mem.read_u64(self.sp + (index - len(Arm64Reg.ARG_REGS)) * 8)

    def set_arg(self, index: int, value: int) -> None:
        if index < len(Arm64Reg.ARG_REGS):
            self.backend.reg_write(Arm64Reg.ARG_REGS[index], value & 0xFFFFFFFFFFFFFFFF)
        else:
            self.mem.write_u64(
                self.sp + (index - len(Arm64Reg.ARG_REGS)) * 8, value & 0xFFFFFFFFFFFFFFFF
            )

    @property
    def sp(self) -> int:
        return self.backend.reg_read(Arm64Reg.SP)

    @sp.setter
    def sp(self, value: int) -> None:
        self.backend.reg_write(Arm64Reg.SP, value)

    @property
    def pc(self) -> int:
        return self.backend.reg_read(Arm64Reg.PC)

    @pc.setter
    def pc(self, value: int) -> None:
        self.backend.reg_write(Arm64Reg.PC, value)

    @property
    def lr(self) -> int:
        return self.backend.reg_read(Arm64Reg.LR)

    @lr.setter
    def lr(self, value: int) -> None:
        self.backend.reg_write(Arm64Reg.LR, value)

    @property
    def ret(self) -> int:
        return self.backend.reg_read(Arm64Reg.RET_REG)

    @ret.setter
    def ret(self, value: int) -> None:
        self.backend.reg_write(Arm64Reg.RET_REG, value)

    def hook_address(self, address: int, callback):
        return self.hooks.hook_address(address, callback)

    def hook_symbol(self, symbol: str, on_call, post_call=None, module_name: str | None = None):
        return self.hooks.hook_symbol(symbol, on_call, post_call, module_name)

    def hook_code(self, callback, start: int | None = None, end: int | None = None):
        return self.hooks.hook_code(callback, start, end)

    def hook_module(self, callback, module_name: str | None = None):
        return self.hooks.hook_module(callback, module_name)

    def trace_code(self, callback, start: int | None = None, end: int | None = None):
        return self.hooks.trace_code(callback, start, end)

    def trace_module(self, callback, module_name: str | None = None):
        return self.hooks.trace_module(callback, module_name)

    def replace(self, address: int, on_call, post_call=None):
        return self.hooks.replace(address, on_call, post_call)

    def hook_memory(
        self,
        callback,
        start: int | None = None,
        end: int | None = None,
        reads: bool = True,
        writes: bool = True,
    ):
        return self.hooks.hook_memory(callback, start, end, reads, writes)

    def watchpoint(
        self, address: int, callback, length: int = 8, reads: bool = True, writes: bool = True
    ):
        return self.hooks.watchpoint(address, callback, length, reads, writes)

    def hook_mem_fault(self, callback):
        return self.hooks.hook_mem_fault(callback)

    def call_trace(
        self,
        callback,
        module_name: str | None = None,
        *,
        start: int | None = None,
        end: int | None = None,
    ):
        return self.hooks.call_trace(callback, module_name, start=start, end=end)

    def disassemble(self, address: int, count: int = 1, thumb: bool | None = None):
        return self.disassembler.disassemble(address, count, thumb)

    def run(self, start: int, until: int, count: int = 0) -> None:
        self._enter_guest()
        try:
            self.backend.emu_start(start, until, count=count)
        except EmulatorCrashed as e:
            raise self._symbolize_crash(e) from e
        finally:
            self._executing = False

    def stop(self) -> None:
        self.backend.emu_stop()

    def close(self) -> None:
        if self._closed:
            return
        if self._executing:
            self.backend.emu_stop()
        self.backend.destroy()
        self._executing = False
        self._closed = True

    def __enter__(self) -> AndroidEmulator64:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def finish(self, return_value: int = 0) -> None:
        self.backend.reg_write(Arm64Reg.RET_REG, return_value & 0xFFFFFFFFFFFFFFFF)
        self.backend.reg_write(Arm64Reg.PC, self.backend.reg_read(Arm64Reg.LR))

    def add_file(self, path: str, data: bytes) -> None:
        self.vfs.add_file(path, data)

    def register_socket(self, path: str, handler) -> None:
        self.vfs.register_socket(path, handler)

    def register_libc(self, name: str, fn, override: bool = True) -> int:
        return self.libc.register(name, fn, override)

    def ptr(self, address: int) -> NativePointer:
        return NativePointer(self.mem, address)

    def malloc(self, size: int) -> NativePointer:
        return self.ptr(self.libc.heap.malloc(size))

    def calloc(self, count: int, size: int) -> NativePointer:
        return self.ptr(self.libc.heap.calloc(count, size))

    def realloc(self, pointer: int | NativePointer, size: int) -> NativePointer:
        return self.ptr(self.libc.heap.realloc(int(pointer), size))

    def free(self, pointer: int | NativePointer) -> None:
        self.libc.heap.free(int(pointer))

    def alloc(self, data: bytes | bytearray) -> NativePointer:
        raw = bytes(data)
        pointer = self.malloc(len(raw))
        if raw:
            pointer.write(raw)
        return pointer

    def alloc_str(self, text: str) -> NativePointer:
        pointer = self.malloc(len(text.encode("utf-8")) + 1)
        pointer.write_cstr(text)
        return pointer

    def read_string(self, address: int | NativePointer) -> str:
        return self.mem.read_cstr(int(address))

    @property
    def dvm(self):
        return self.jni.dvm

    def get_object(self, ref: int) -> object | None:
        return self.jni.dvm.get(ref)

    def _enter_guest(self) -> None:
        if self._executing:
            raise NestedExecution(
                "cannot run guest code (emu.call/run) from inside a hook/handler — "
                "redirect control with emu.pc / emu.finish instead"
            )
        self._executing = True

    def call(
        self, target: "int | Symbol | NativePointer", *args: object, return_pointer: bool = False
    ):
        addr = int(getattr(target, "address", target))
        values = [self._to_native_arg(v) for v in args]
        self._enter_guest()
        saved = self.backend.context_save()
        try:
            for i, value in enumerate(values[:8]):
                self.backend.reg_write(Arm64Reg.ARG_REGS[i], value & 0xFFFFFFFFFFFFFFFF)
            if len(values) > 8:
                self._spill_stack_args(values[8:])

            self.backend.reg_write(Arm64Reg.LR, MemoryLayout.RETURN_SENTINEL)
            self.backend.emu_start(addr, MemoryLayout.RETURN_SENTINEL)
            result = self.backend.reg_read(Arm64Reg.RET_REG)
        except EmulatorCrashed as e:
            raise self._symbolize_crash(e) from e
        finally:
            self.backend.context_restore(saved)
            self._executing = False
        return self.ptr(result) if return_pointer else result

    def _to_native_arg(self, value: object) -> int:
        if isinstance(value, str):
            return self.mem.alloc_cstr(value)
        if isinstance(value, (bytes, bytearray)):
            return self.mem.alloc(bytes(value))
        return int(value)

    def run_pending_irelative(self) -> None:
        while self.loader.pending_irelative:
            where, resolver = self.loader.pending_irelative.pop(0)
            result = self.call(resolver)
            self.mem.write_u64(where, result)
            self.log.loader("ifunc @ %#x resolved via %#x => %#x", where, resolver, result)

    def run_pending_init(self) -> None:
        self.run_pending_irelative()
        argc, argv, envp = self.mem.argc, self.mem.argv_ptr, self.mem.envp_ptr
        while self.loader.pending_init:
            module = self.loader.pending_init.pop(0)
            for entry in module.init_functions():
                self.log.loader("run init %s @ %#x", module.name, entry)
                self.call(entry, argc, argv, envp)

    def _spill_stack_args(self, extra: list[int]) -> None:
        sp = self.backend.reg_read(Arm64Reg.SP)
        sp = (sp - len(extra) * 8) & ~0xF
        for i, value in enumerate(extra):
            self.mem.write_u64(sp + i * 8, value & 0xFFFFFFFFFFFFFFFF)
        self.backend.reg_write(Arm64Reg.SP, sp)

    def _resolve_native(
        self, class_name: str, method_name: str, signature: str, is_static: bool
    ) -> int:
        dvm = self.jni.dvm
        klass = dvm.find_class(class_name)
        method = dvm.member(dvm.method_id(klass, method_name, signature, is_static))
        fn = getattr(method, "native_addr", 0)
        parent = klass.getSuperclass()
        while not fn and parent is not None:
            inherited = dvm.member(dvm.method_id(parent, method_name, signature, is_static))
            fn = getattr(inherited, "native_addr", 0)
            parent = parent.getSuperclass()
        if not fn:
            for candidate in dvm.get_all_classes():
                if candidate.name != class_name and dvm.is_in_hierarchy(class_name, candidate):
                    derived = dvm.member(
                        dvm.method_id(candidate, method_name, signature, is_static)
                    )
                    fn = getattr(derived, "native_addr", 0)
                    if fn:
                        break
        if not fn:
            fn = self.loader.find_export(
                JniMangler.mangle(class_name, method_name)
            ) or self.loader.find_export(JniMangler.overloaded(class_name, method_name, signature))
        if not fn:
            raise SymbolMissing(f"native method {class_name}.{method_name}{signature}")
        return fn

    def java_class(self, name: str) -> JavaClass:
        return self.jni.dvm.class_for(name)

    def registered_natives(self) -> list:
        return self.jni.dvm.registered_natives()

    def call_static_native(
        self, class_name: str, method_name: str, signature: str, *args: object
    ) -> object:
        fn = self._resolve_native(class_name, method_name, signature, is_static=True)
        return self.call_native(
            fn, self.jni.dvm.add_local(self.jni.dvm.find_class(class_name)), signature, list(args)
        )

    def call_instance_native(
        self, instance: object, class_name: str, method_name: str, signature: str, *args: object
    ) -> object:
        fn = self._resolve_native(class_name, method_name, signature, is_static=False)
        return self.call_native(fn, self.jni.dvm.add_local(instance), signature, list(args))

    def call_native(self, fn: int, this_ref: int, signature: str, args: list) -> object:
        arg_types = JNIEnv.parse_arg_types(signature)
        return_type = signature[signature.index(")") + 1]
        self._enter_guest()
        saved = self.backend.context_save()
        ref_mark = self.jni.dvm.local_mark()
        try:
            self._marshal_native(int(this_ref), arg_types, args)
            self.backend.reg_write(Arm64Reg.LR, MemoryLayout.RETURN_SENTINEL)
            self.backend.emu_start(int(fn), MemoryLayout.RETURN_SENTINEL)
            result = self._read_native_return(return_type)
        except EmulatorCrashed as e:
            raise self._symbolize_crash(e) from e
        finally:
            self.backend.context_restore(saved)
            self.jni.dvm.local_release(ref_mark)
            self._executing = False
        pending = self.jni.take_pending_exception()
        if pending is not None:
            raise JavaExceptionThrown(pending)
        return result

    def _marshal_native(self, this_ref: int, arg_types: list[str], args: list) -> None:
        self.backend.reg_write(Arm64Reg.X[0], self.jni.pointer)
        self.backend.reg_write(Arm64Reg.X[1], this_ref & 0xFFFFFFFFFFFFFFFF)
        gp_index, fp_index, stack = 0, 0, []
        for letter, value in zip(arg_types, args):
            if letter in "FD":
                bits = (
                    struct.unpack("<Q", struct.pack("<d", float(value)))[0]
                    if letter == "D"
                    else struct.unpack("<I", struct.pack("<f", float(value)))[0]
                )
                if fp_index < 8:
                    self.backend.reg_write(Arm64Reg.Q[fp_index], bits)
                    fp_index += 1
                else:
                    stack.append(bits)
            else:
                guest = self._to_guest(letter, value)
                if gp_index < 6:
                    self.backend.reg_write(Arm64Reg.X[2 + gp_index], guest)
                    gp_index += 1
                else:
                    stack.append(guest)
        if stack:
            sp = (self.backend.reg_read(Arm64Reg.SP) - len(stack) * 8) & ~0xF
            for i, word in enumerate(stack):
                self.mem.write_u64(sp + i * 8, word & 0xFFFFFFFFFFFFFFFF)
            self.backend.reg_write(Arm64Reg.SP, sp)

    def _to_guest(self, letter: str, value: object) -> int:
        if letter == "L":
            if isinstance(value, str):
                return self.jni.dvm.add_local(JavaString(value))
            if isinstance(value, (bytes, bytearray)):
                return self.jni.dvm.add_local(
                    JavaObject(
                        JavaClass("[B"), value if isinstance(value, bytearray) else bytearray(value)
                    )
                )
            if isinstance(value, (JavaObject, JavaClass)):
                return self.jni.dvm.add_local(value)
            return int(value) & 0xFFFFFFFFFFFFFFFF
        if letter == "Z":
            return 1 if value else 0
        return int(value) & 0xFFFFFFFFFFFFFFFF

    def _read_native_return(self, return_type: str) -> object:
        if return_type == "V":
            return None
        if return_type == "F":
            return struct.unpack(
                "<f", struct.pack("<I", self.backend.reg_read(Arm64Reg.Q[0]) & 0xFFFFFFFF)
            )[0]
        if return_type == "D":
            return struct.unpack(
                "<d", struct.pack("<Q", self.backend.reg_read(Arm64Reg.Q[0]) & 0xFFFFFFFFFFFFFFFF)
            )[0]
        value = self.backend.reg_read(Arm64Reg.RET_REG)
        if return_type in ("L", "["):
            return self._unwrap_return(self.jni.dvm.get(value))
        if return_type == "Z":
            return bool(value & 1)
        return value

    @staticmethod
    def _unwrap_return(obj: object) -> object:
        if isinstance(obj, JavaString):
            return obj.value
        if (
            isinstance(obj, JavaObject)
            and obj.java_class is not None
            and obj.java_class.name == "[B"
        ):
            return bytes(obj.value)
        return obj
