from __future__ import annotations

import os
import struct
from collections.abc import Callable
from typing import Any, cast

from emulite._rootfs import resolve_android_rootfs
from emulite.android.android_file_system import AndroidFileSystem
from emulite.android.arm64.android_libc_hooks64 import AndroidLibcHooks64
from emulite.android.arm64.android_syscall_handler64 import AndroidSyscallHandler64
from emulite.android.enums.auxv import Auxv
from emulite.android.java_vm import JavaVM
from emulite.android.jni.jni_env import JNIEnv
from emulite.android.jni.jni_handler import JniHandler
from emulite.android.linker_debug import LinkerDebug
from emulite.android_device import AndroidDevice
from emulite.android_emulator import AndroidEmulatorBase
from emulite.android_profile import AndroidProfile
from emulite.common.log import LogCategory, Logger
from emulite.cpu.arch.arm64 import Arm64Arch
from emulite.cpu.backend import Backend, CpuArch
from emulite.cpu.registers.arm64_reg import Arm64Reg
from emulite.cpu.unicorn_backend import UnicornBackend
from emulite.hooks.disassembler import Disassembler
from emulite.hooks.hook_manager import HookManager
from emulite.hooks.svc_trap import SvcTrap
from emulite.loader.elf_loader import ElfLoader
from emulite.memory import MemoryLayout, MemoryManager


class AndroidEmulator64(AndroidEmulatorBase):
    """Android emulator using the 64-bit ARM ABI."""

    _stack_alignment = 16

    def __init__(
        self,
        rootfs: str | os.PathLike[str] | None = None,
        *,
        log: LogCategory | Logger = LogCategory.Default,
        profile: AndroidProfile | None = None,
        device: AndroidDevice | None = None,
        jni_handler: JniHandler | None = None,
        search_paths: tuple[str, ...] = (),
        backend: Callable[[CpuArch], Backend] = UnicornBackend,
        strict_syscalls: bool = True,
        syscall_handler: type[AndroidSyscallHandler64] = AndroidSyscallHandler64,
        jni_env: type[JNIEnv] = JNIEnv,
        java_vm: type[JavaVM] = JavaVM,
    ):
        self.rootfs = resolve_android_rootfs(rootfs)
        self.log = log if isinstance(log, Logger) else Logger(categories=log)
        self.profile = profile or AndroidProfile()
        root_properties = AndroidDevice.load_build_prop(self.rootfs)
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
        self._setup_android(strict_syscalls, syscall_handler, jni_env, java_vm)

        self.loader = ElfLoader(self.mem, self.log, rootfs=self.rootfs, search_paths=search_paths)
        self.loader.emu = self
        self.hooks = HookManager(self)
        self.disassembler = Disassembler(self)
        self.loader.resolve_override = self.libc.resolve_override
        self.loader.resolve_fallback = self.libc.resolve_fallback
        self.loader.after_load = self.linker_debug.rebuild
        self.log.loader("AndroidEmulator64 ready (arm64): %s on %s, rootfs=%s", self.profile.package_name, self.device.get("ro.product.model"), self.rootfs)

    def _initial_stack(self) -> tuple[list[str], list[str], list[tuple[int, int]], int]:
        profile = self.profile
        argv = [profile.program_name or profile.package_name]
        envp = [f"{key}={value}" for key, value in profile.environment_variables.items()]
        auxv: list[tuple[int, int]] = [
            (Auxv.AT_PHDR, self.linker_debug.phdr_addr),
            (Auxv.AT_PHENT, self.linker_debug.phent),
            (Auxv.AT_PHNUM, self.linker_debug.phnum),
            (Auxv.AT_ENTRY, self.linker_debug.entry),
            (Auxv.AT_PAGESZ, MemoryLayout.PAGE_SIZE),
            (Auxv.AT_HWCAP, self.device.HWCAP_ARM64),
            (Auxv.AT_HWCAP2, self.device.HWCAP2_ARM64),
            (Auxv.AT_CLKTCK, 100),
            (Auxv.AT_UID, profile.process_uid),
            (Auxv.AT_EUID, profile.process_uid),
            (Auxv.AT_GID, profile.process_gid),
            (Auxv.AT_EGID, profile.process_gid),
            (Auxv.AT_SECURE, 0),
        ]
        return argv, envp, auxv, profile.stack_guard

    def _setup_android(self, strict_syscalls: bool, syscall_handler: type[AndroidSyscallHandler64], jni_env: type[JNIEnv], java_vm: type[JavaVM]) -> None:
        self.vfs = AndroidFileSystem(self.rootfs, self)
        self.device.bind_memory(self.mem)
        self.syscalls = syscall_handler(self, strict=strict_syscalls)
        self.libc = AndroidLibcHooks64(self)
        self.jni = jni_env(self)
        self.javavm = java_vm(self)

    def _marshal_native(self, receiver_ref: int, arg_types: list[str], args: list[object]) -> None:
        self.backend.reg_write(Arm64Reg.X[0], self.jni.pointer)
        self.backend.reg_write(Arm64Reg.X[1], receiver_ref & 0xFFFFFFFFFFFFFFFF)
        gp_index, fp_index, stack = 0, 0, []
        for letter, value in zip(arg_types, args):
            if letter in "FD":
                bits = struct.unpack("<Q", struct.pack("<d", float(cast(Any, value))))[0] if letter == "D" else struct.unpack("<I", struct.pack("<f", float(cast(Any, value))))[0]
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
            sp = (self.sp - len(stack) * 8) & ~0xF
            for index, word in enumerate(stack):
                self.mem.write_u64(sp + index * 8, word & 0xFFFFFFFFFFFFFFFF)
            self.sp = sp

    def _read_native_return(self, return_type: str) -> object:
        if return_type == "V":
            return None
        if return_type == "F":
            return struct.unpack("<f", struct.pack("<I", self.read_register(Arm64Reg.Q[0]) & 0xFFFFFFFF))[0]
        if return_type == "D":
            return struct.unpack("<d", struct.pack("<Q", self.read_register(Arm64Reg.Q[0]) & 0xFFFFFFFFFFFFFFFF))[0]
        value = self.get_return_value()
        if return_type in ("L", "["):
            return self._unwrap_return(self.dvm.get(value))
        if return_type == "Z":
            return bool(value & 1)
        return value
