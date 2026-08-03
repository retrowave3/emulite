from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import Callable
from types import TracebackType
from typing import TYPE_CHECKING, Literal, SupportsInt, TypeVar, cast, overload

import capstone

from emulite.android.dalvik_vm import DalvikVM
from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.lang.java_string import JavaString
from emulite.android.jni.enums.jni_version import JNIVersion
from emulite.android.jni.jni_env import JNIEnv
from emulite.android.jni.jni_mangler import JniMangler
from emulite.common.errors import EmulatorCrashed, JavaExceptionThrown, NestedExecution, SymbolMissing
from emulite.common.log import LogLevel
from emulite.hooks.unwinder import Unwinder
from emulite.memory.native_pointer import NativePointer
from emulite.types import NativeArgument

if TYPE_CHECKING:
    from emulite.android.android_file_system import AndroidFileSystem
    from emulite.android.arm32.android_libc_hooks32 import AndroidLibcHooks32
    from emulite.android.arm32.android_syscall_handler32 import AndroidSyscallHandler32
    from emulite.android.arm64.android_libc_hooks64 import AndroidLibcHooks64
    from emulite.android.arm64.android_syscall_handler64 import AndroidSyscallHandler64
    from emulite.android.java.lang.reflect.java_method import JavaMethod
    from emulite.android.java_vm import JavaVM
    from emulite.android.jni.jni_handler import JniHandler
    from emulite.android_device import AndroidDevice
    from emulite.android_profile import AndroidProfile
    from emulite.common.log import Logger
    from emulite.cpu.arch.base import Arch
    from emulite.cpu.backend import Backend
    from emulite.hooks.disassembler import Disassembler
    from emulite.hooks.frame import Frame
    from emulite.hooks.hook_handle import HookHandle
    from emulite.hooks.hook_manager import HookManager
    from emulite.hooks.svc_trap import SvcTrap
    from emulite.hooks.types import AddressHook, CallTraceHook, CodeHook, MemoryFaultHook, MemoryHook, PostCallHook, ReplacementHook, TraceHook
    from emulite.loader.elf_loader import ElfLoader
    from emulite.loader.module.native_module import NativeModule
    from emulite.loader.module.symbol import Symbol
    from emulite.memory import MemoryManager


_EmulatorT = TypeVar("_EmulatorT", bound="AndroidEmulatorBase")


class AndroidEmulatorBase(ABC):
    """Architecture-independent Android emulator API and implementation."""

    _VALID_JNI_VERSIONS = frozenset(JNIVersion)
    _stack_alignment: int

    rootfs: str
    log: Logger
    profile: AndroidProfile
    device: AndroidDevice
    jni_handler: JniHandler
    arch: Arch
    backend: Backend
    mem: MemoryManager
    auxv: dict[int, int]
    trap: SvcTrap
    loader: ElfLoader
    hooks: HookManager
    disassembler: Disassembler
    vfs: AndroidFileSystem
    jni: JNIEnv
    javavm: JavaVM
    syscalls: AndroidSyscallHandler32 | AndroidSyscallHandler64
    libc: AndroidLibcHooks32 | AndroidLibcHooks64
    _executing: bool
    _closed: bool

    @property
    def memory(self) -> MemoryManager:
        return self.mem

    @property
    def filesystem(self) -> AndroidFileSystem:
        return self.vfs

    @property
    def java_vm(self) -> JavaVM:
        return self.javavm

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def _pointer_mask(self) -> int:
        return (1 << (self.arch.pointer_size * 8)) - 1

    def load(self, path_or_name: str | os.PathLike[str], scan_only: bool = False) -> NativeModule:
        return self.loader.load(path_or_name, scan_only=scan_only)

    def call_jni_onload(self, module: NativeModule) -> int:
        self.run_pending_init()
        onload = module.find_symbol("JNI_OnLoad")
        if onload is None:
            self.log.jni("%s has no JNI_OnLoad", module.name)
            return self.jni.version
        version = self.call(onload, self.java_vm.pointer, 0)
        if version not in self._VALID_JNI_VERSIONS:
            self.log.jni("JNI_OnLoad(%s) => %#x is not a valid JNI version", module.name, version, level=LogLevel.WARN)
        else:
            self.log.jni("JNI_OnLoad(%s) => %#x", module.name, version)
        return version

    def find_symbol(self, name: str) -> int | None:
        return self.loader.find_export(name)

    def require_symbol(self, name: str) -> int:
        address = self.find_symbol(name)
        if address is None:
            raise SymbolMissing(name)
        return address

    def find_symbol_or_throw(self, name: str) -> int:
        return self.require_symbol(name)

    @overload
    def call_symbol(self, name: str, *args: NativeArgument, return_pointer: Literal[False] = False) -> int: ...

    @overload
    def call_symbol(self, name: str, *args: NativeArgument, return_pointer: Literal[True]) -> NativePointer: ...

    @overload
    def call_symbol(self, name: str, *args: NativeArgument, return_pointer: bool) -> int | NativePointer: ...

    def call_symbol(self, name: str, *args: NativeArgument, return_pointer: bool = False) -> int | NativePointer:
        if return_pointer:
            return self.call(self.require_symbol(name), *args, return_pointer=True)
        return self.call(self.require_symbol(name), *args)

    def find_module(self, name_or_path: str) -> NativeModule | None:
        return self.loader.modules.get(os.path.basename(name_or_path.replace("\\", "/")))

    def get_module(self, name_or_path: str) -> NativeModule | None:
        return self.find_module(name_or_path)

    def module_at(self, address: int) -> NativeModule | None:
        return self.loader.module_at(address)

    @property
    def modules(self) -> list[NativeModule]:
        return list(self.loader.loaded_modules)

    loaded_modules = modules

    def add_library_path(self, path: str | os.PathLike[str]) -> None:
        self.loader.add_search_path(path)

    def describe_address(self, address: int) -> str:
        module = self.module_at(address)
        if module is None:
            region = self.mem.find_region(address)
            tag = region.label if region and region.label else "unmapped"
            return f"{address:#x} [{tag}]"
        text = f"{module.name}+{module.offset_of(address):#x}"
        hit = module.symbol_at(address)
        if hit is not None:
            symbol, delta = hit
            text += f" {symbol.name}" + (f"+{delta:#x}" if delta else "")
        return text

    def _symbolize_crash(self, exc: EmulatorCrashed) -> EmulatorCrashed:
        if exc.symbolized:
            return exc
        message = f"{exc}  [{self.describe_address(self.pc)}]"
        frames = self.backtrace()
        if len(frames) > 1:
            message += "\n  backtrace:\n" + "\n".join("    " + frame.format() for frame in frames)
        enriched = EmulatorCrashed(message)
        enriched.symbolized = True
        return enriched

    def backtrace(self, max_depth: int = 64) -> list[Frame]:
        return Unwinder(self).frames(max_depth)

    def add_data_symbol(self, name: str, address: int) -> None:
        self.loader.add_data_symbol(name, address)

    def create_virtual_module(self, name: str, symbols: dict[str, int] | None = None) -> NativeModule:
        return self.loader.create_virtual_module(name, symbols)

    def read_register(self, register: int) -> int:
        return self.backend.reg_read(register)

    def write_register(self, register: int, value: int) -> None:
        self.backend.reg_write(register, value)

    def reg(self, reg_id: int) -> int:
        return self.read_register(reg_id)

    def set_reg(self, reg_id: int, value: int) -> None:
        self.write_register(reg_id, value)

    def get_argument(self, index: int) -> int:
        self._validate_argument_index(index)
        registers = self.arch.registers.ARG_REGS
        if index < len(registers):
            return self.read_register(registers[index])
        return self.mem.read_ptr(self.sp + (index - len(registers)) * self.arch.pointer_size)

    def set_argument(self, index: int, value: int) -> None:
        self._validate_argument_index(index)
        registers = self.arch.registers.ARG_REGS
        value &= self._pointer_mask
        if index < len(registers):
            self.write_register(registers[index], value)
        else:
            self.mem.write_ptr(self.sp + (index - len(registers)) * self.arch.pointer_size, value)

    @staticmethod
    def _validate_argument_index(index: int) -> None:
        if index < 0:
            raise ValueError("argument index cannot be negative")

    def arg(self, index: int) -> int:
        return self.get_argument(index)

    def set_arg(self, index: int, value: int) -> None:
        self.set_argument(index, value)

    @property
    def sp(self) -> int:
        return self.read_register(self.arch.registers.SP)

    @sp.setter
    def sp(self, value: int) -> None:
        self.write_register(self.arch.registers.SP, value)

    @property
    def pc(self) -> int:
        return self.read_register(self.arch.registers.PC)

    @pc.setter
    def pc(self, value: int) -> None:
        self.write_register(self.arch.registers.PC, value)

    @property
    def lr(self) -> int:
        return self.read_register(self.arch.registers.LR)

    @lr.setter
    def lr(self, value: int) -> None:
        self.write_register(self.arch.registers.LR, value)

    def get_return_value(self) -> int:
        return self.read_register(self.arch.registers.RET_REG)

    def set_return_value(self, value: int) -> None:
        self.write_register(self.arch.registers.RET_REG, value & self._pointer_mask)

    @property
    def ret(self) -> int:
        return self.get_return_value()

    @ret.setter
    def ret(self, value: int) -> None:
        self.set_return_value(value)

    def hook_address(self, address: int, callback: AddressHook) -> HookHandle:
        return self.hooks.hook_address(address, callback)

    def hook_symbol(self, symbol: str, on_call: ReplacementHook, post_call: PostCallHook | None = None, module_name: str | None = None) -> HookHandle:
        return self.hooks.hook_symbol(symbol, on_call, post_call, module_name)

    def hook_code(self, callback: CodeHook, start: int | None = None, end: int | None = None) -> HookHandle:
        return self.hooks.hook_code(callback, start, end)

    def hook_module(self, callback: CodeHook, module_name: str | None = None) -> HookHandle:
        return self.hooks.hook_module(callback, module_name)

    def trace_code(self, callback: TraceHook, start: int | None = None, end: int | None = None) -> HookHandle:
        return self.hooks.trace_code(callback, start, end)

    def trace_module(self, callback: TraceHook, module_name: str | None = None) -> HookHandle:
        return self.hooks.trace_module(callback, module_name)

    def replace(self, address: int, on_call: ReplacementHook, post_call: PostCallHook | None = None) -> HookHandle:
        return self.hooks.replace(address, on_call, post_call)

    def hook_memory(self, callback: MemoryHook, start: int | None = None, end: int | None = None, reads: bool = True, writes: bool = True) -> HookHandle:
        return self.hooks.hook_memory(callback, start, end, reads, writes)

    def watchpoint(self, address: int, callback: MemoryHook, length: int = 8, reads: bool = True, writes: bool = True) -> HookHandle:
        return self.hooks.watchpoint(address, callback, length, reads, writes)

    def hook_mem_fault(self, callback: MemoryFaultHook) -> HookHandle:
        return self.hooks.hook_mem_fault(callback)

    def call_trace(self, callback: CallTraceHook, module_name: str | None = None, *, start: int | None = None, end: int | None = None) -> HookHandle:
        return self.hooks.call_trace(callback, module_name, start=start, end=end)

    def disassemble(self, address: int, count: int = 1, thumb: bool | None = None) -> list[capstone.CsInsn]:
        return self.disassembler.disassemble(address, count, thumb)

    def run(self, start: int, until: int, count: int = 0) -> None:
        self._enter_guest()
        try:
            self.backend.emu_start(start, until, count=count)
        except EmulatorCrashed as exc:
            raise self._symbolize_crash(exc) from exc
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

    def __enter__(self: _EmulatorT) -> _EmulatorT:  # noqa: PYI019 - Self requires Python 3.11
        self._ensure_open()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None) -> None:
        self.close()

    def return_from_function(self, return_value: int = 0) -> None:
        self.set_return_value(return_value)
        self.pc = self.lr

    def finish(self, return_value: int = 0) -> None:
        self.return_from_function(return_value)

    def add_file(self, path: str, data: bytes) -> None:
        self.vfs.add_file(path, data)

    def register_socket(self, path: str, handler: Callable[[bytes], bytes]) -> None:
        self.vfs.register_socket(path, handler)

    def register_libc(self, name: str, fn: Callable[[AndroidEmulatorBase], object], override: bool = True) -> int:
        return self.libc.register(name, fn, override)

    def pointer(self, address: int) -> NativePointer:
        return NativePointer(self.mem, address)

    def ptr(self, address: int) -> NativePointer:
        return self.pointer(address)

    def malloc(self, size: int) -> NativePointer:
        return self.pointer(self.libc.heap.malloc(size))

    def calloc(self, count: int, size: int) -> NativePointer:
        return self.pointer(self.libc.heap.calloc(count, size))

    def realloc(self, pointer: int | NativePointer, size: int) -> NativePointer:
        return self.pointer(self.libc.heap.realloc(int(pointer), size))

    def free(self, pointer: int | NativePointer) -> None:
        self.libc.heap.free(int(pointer))

    def allocate_bytes(self, data: bytes | bytearray) -> NativePointer:
        raw = bytes(data)
        pointer = self.malloc(len(raw))
        if raw:
            pointer.write(raw)
        return pointer

    def alloc(self, data: bytes | bytearray) -> NativePointer:
        return self.allocate_bytes(data)

    def allocate_string(self, text: str) -> NativePointer:
        pointer = self.malloc(len(text.encode("utf-8")) + 1)
        pointer.write_cstr(text)
        return pointer

    def alloc_str(self, text: str) -> NativePointer:
        return self.allocate_string(text)

    def read_string(self, address: int | NativePointer) -> str:
        return self.mem.read_cstr(int(address))

    @property
    def dvm(self) -> DalvikVM:
        return self.jni.dvm

    def get_object(self, ref: int) -> object | None:
        return self.dvm.get(ref)

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("emulator is closed")

    def _enter_guest(self) -> None:
        self._ensure_open()
        if self._executing:
            raise NestedExecution("cannot run guest code from inside a hook or handler; redirect control with emu.pc or emu.return_from_function()")
        self._executing = True

    @overload
    def call(self, target: int | Symbol | NativePointer, *args: NativeArgument, return_pointer: Literal[False] = False) -> int: ...

    @overload
    def call(self, target: int | Symbol | NativePointer, *args: NativeArgument, return_pointer: Literal[True]) -> NativePointer: ...

    @overload
    def call(self, target: int | Symbol | NativePointer, *args: NativeArgument, return_pointer: bool) -> int | NativePointer: ...

    def call(self, target: int | Symbol | NativePointer, *args: NativeArgument, return_pointer: bool = False) -> int | NativePointer:
        address = int(getattr(target, "address", target))
        values = [self._to_native_arg(value) for value in args]
        self._enter_guest()
        saved = self.backend.context_save()
        try:
            registers = self.arch.registers.ARG_REGS
            for register, value in zip(registers, values):
                self.write_register(register, value & self._pointer_mask)
            if len(values) > len(registers):
                self._spill_stack_args(values[len(registers) :])
            self.lr = self.arch.layout.RETURN_SENTINEL
            self.backend.emu_start(address, self.arch.layout.RETURN_SENTINEL)
            result = self.get_return_value()
        except EmulatorCrashed as exc:
            raise self._symbolize_crash(exc) from exc
        finally:
            self.backend.context_restore(saved)
            self._executing = False
        return self.pointer(result) if return_pointer else result

    def _to_native_arg(self, value: NativeArgument) -> int:
        if isinstance(value, str):
            return self.mem.alloc_cstr(value)
        if isinstance(value, (bytes, bytearray)):
            return self.mem.alloc(bytes(value))
        return int(cast(SupportsInt, value))

    def run_pending_irelative(self) -> None:
        while self.loader.pending_irelative:
            where, resolver = self.loader.pending_irelative.pop(0)
            result = self.call(resolver)
            self.mem.write_ptr(where, result)
            self.log.loader("ifunc @ %#x resolved via %#x => %#x", where, resolver, result)

    def run_pending_init(self) -> None:
        self.run_pending_irelative()
        argc, argv, envp = self.mem.argc, self.mem.argv_ptr, self.mem.envp_ptr
        while self.loader.pending_init:
            module = self.loader.pending_init.pop(0)
            for entry in module.init_functions():
                self.log.loader("run init %s @ %#x", module.name, entry)
                self.call(entry, argc, argv, envp)

    def _spill_stack_args(self, values: list[int]) -> None:
        width = self.arch.pointer_size
        sp = (self.sp - len(values) * width) & -self._stack_alignment
        for index, value in enumerate(values):
            self.mem.write_ptr(sp + index * width, value & self._pointer_mask)
        self.sp = sp

    def _resolve_native(self, class_name: str, method_name: str, signature: str, is_static: bool) -> int:
        klass = self.dvm.find_class(class_name)
        method = self.dvm.member(self.dvm.method_id(klass, method_name, signature, is_static))
        fn = getattr(method, "native_addr", 0)
        parent = klass.getSuperclass()
        while not fn and parent is not None:
            inherited = self.dvm.member(self.dvm.method_id(parent, method_name, signature, is_static))
            fn = getattr(inherited, "native_addr", 0)
            parent = parent.getSuperclass()
        if not fn:
            for candidate in self.dvm.get_all_classes():
                if candidate.name != class_name and self.dvm.is_in_hierarchy(class_name, candidate):
                    derived = self.dvm.member(self.dvm.method_id(candidate, method_name, signature, is_static))
                    fn = getattr(derived, "native_addr", 0)
                    if fn:
                        break
        if not fn:
            fn = self.loader.find_export(JniMangler.mangle(class_name, method_name)) or self.loader.find_export(JniMangler.overloaded(class_name, method_name, signature))
        if not fn:
            raise SymbolMissing(f"native method {class_name}.{method_name}{signature}")
        return fn

    def java_class(self, name: str) -> JavaClass:
        return self.dvm.class_for(name)

    def registered_natives(self) -> list[JavaMethod]:
        return self.dvm.registered_natives()

    def call_static_native(self, class_name: str, method_name: str, signature: str, *args: object) -> object:
        fn = self._resolve_native(class_name, method_name, signature, is_static=True)
        return self._call_jni_native(fn, self.dvm.add_local(self.dvm.find_class(class_name)), signature, list(args))

    def call_instance_native(self, instance: object, class_name: str, method_name: str, signature: str, *args: object) -> object:
        fn = self._resolve_native(class_name, method_name, signature, is_static=False)
        return self._call_jni_native(fn, self.dvm.add_local(instance), signature, list(args))

    def _call_jni_native(self, fn: int, receiver_ref: int, signature: str, args: list[object]) -> object:
        arg_types = JNIEnv.parse_arg_types(signature)
        if len(args) != len(arg_types):
            raise TypeError(f"native signature expects {len(arg_types)} arguments, got {len(args)}")
        return_type = signature[signature.index(")") + 1]
        self._enter_guest()
        saved = self.backend.context_save()
        ref_mark = self.dvm.local_mark()
        try:
            self._marshal_native(receiver_ref, arg_types, args)
            self.lr = self.arch.layout.RETURN_SENTINEL
            self.backend.emu_start(int(fn), self.arch.layout.RETURN_SENTINEL)
            result = self._read_native_return(return_type)
        except EmulatorCrashed as exc:
            raise self._symbolize_crash(exc) from exc
        finally:
            self.backend.context_restore(saved)
            self.dvm.local_release(ref_mark)
            self._executing = False
        pending = self.jni.take_pending_exception()
        if pending is not None:
            raise JavaExceptionThrown(pending)
        return result

    def _to_guest(self, letter: str, value: object) -> int:
        if letter == "L":
            if isinstance(value, str):
                return self.dvm.add_local(JavaString(value))
            if isinstance(value, (bytes, bytearray)):
                data = value if isinstance(value, bytearray) else bytearray(value)
                return self.dvm.add_local(JavaObject(JavaClass("[B"), data))
            if isinstance(value, (JavaObject, JavaClass)):
                return self.dvm.add_local(value)
        if letter == "Z":
            return 1 if value else 0
        return int(cast(SupportsInt, value)) & self._pointer_mask

    @abstractmethod
    def _marshal_native(self, receiver_ref: int, arg_types: list[str], args: list[object]) -> None:
        pass

    @abstractmethod
    def _read_native_return(self, return_type: str) -> object:
        pass

    @staticmethod
    def _unwrap_return(obj: object) -> object:
        if isinstance(obj, JavaString):
            return obj.value
        if isinstance(obj, JavaObject) and obj.java_class is not None and obj.java_class.name == "[B":
            return bytes(obj.value)
        return obj
