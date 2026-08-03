from __future__ import annotations

import os
import struct
from collections.abc import Callable
from copy import copy
from typing import Any, cast

from emulite._rootfs import resolve_android_rootfs
from emulite.android.android_file_system import AndroidFileSystem
from emulite.android.arm32.android_libc_hooks32 import AndroidLibcHooks32
from emulite.android.arm32.android_syscall_handler32 import AndroidSyscallHandler32
from emulite.android.enums.auxv import Auxv
from emulite.android.java_vm import JavaVM
from emulite.android.jni.jni_env import JNIEnv
from emulite.android.jni.jni_handler import JniHandler
from emulite.android.linker_debug import LinkerDebug
from emulite.android_device import AndroidDevice
from emulite.android_emulator import AndroidEmulatorBase
from emulite.android_profile import AndroidProfile
from emulite.common.log import LogCategory, Logger
from emulite.cpu.arch.arm32 import Arm32Arch
from emulite.cpu.backend import Backend, CpuArch
from emulite.cpu.registers.arm32_reg import Arm32Reg
from emulite.cpu.unicorn_backend import UnicornBackend
from emulite.hooks.disassembler import Disassembler
from emulite.hooks.hook_manager import HookManager
from emulite.hooks.svc_trap import SvcTrap
from emulite.loader.elf_loader import ElfLoader
from emulite.memory import MemoryLayout32, MemoryManager


class AndroidEmulator32(AndroidEmulatorBase):
    """Android emulator using the 32-bit ARM ABI."""

    _stack_alignment = 8

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
        syscall_handler: type[AndroidSyscallHandler32] = AndroidSyscallHandler32,
        jni_env: type[JNIEnv] = JNIEnv,
        java_vm: type[JavaVM] = JavaVM,
    ):
        self.rootfs = resolve_android_rootfs(rootfs)
        self.log = log if isinstance(log, Logger) else Logger(categories=log)
        self.profile = copy(profile) if profile is not None else AndroidProfile()
        if self.profile.native_lib_dir and self.profile.native_lib_dir.endswith("/lib/arm64"):
            self.profile.native_lib_dir = self.profile.native_lib_dir[: -len("arm64")] + "arm"
        root_properties = AndroidDevice.load_build_prop(self.rootfs)
        self.device = AndroidDevice(root_properties) if device is None else device
        if device is not None:
            self.device.merge(root_properties)
        self.jni_handler = jni_handler or JniHandler()
        self._executing = False
        self._closed = False

        self.arch = Arm32Arch()
        self.backend = backend(self.arch.cpu_arch)
        self.arch.enable_fpu(self.backend)
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
        self.log.loader("AndroidEmulator32 ready (arm32): %s on %s, rootfs=%s", self.profile.package_name, self.device.get("ro.product.model"), self.rootfs)

    def _initial_stack(self) -> tuple[list[str], list[str], list[tuple[int, int]], int]:
        profile = self.profile
        argv = [profile.program_name or profile.package_name]
        envp = [f"{key}={value}" for key, value in profile.environment_variables.items()]
        auxv: list[tuple[int, int]] = [
            (Auxv.AT_PHDR, self.linker_debug.phdr_addr),
            (Auxv.AT_PHENT, self.linker_debug.phent),
            (Auxv.AT_PHNUM, self.linker_debug.phnum),
            (Auxv.AT_ENTRY, self.linker_debug.entry),
            (Auxv.AT_PAGESZ, MemoryLayout32.PAGE_SIZE),
            (Auxv.AT_HWCAP, self.device.HWCAP_ARM32),
            (Auxv.AT_HWCAP2, self.device.HWCAP2_ARM32),
            (Auxv.AT_CLKTCK, 100),
            (Auxv.AT_UID, profile.process_uid),
            (Auxv.AT_EUID, profile.process_uid),
            (Auxv.AT_GID, profile.process_gid),
            (Auxv.AT_EGID, profile.process_gid),
            (Auxv.AT_SECURE, 0),
        ]
        return argv, envp, auxv, profile.stack_guard

    def _setup_android(self, strict_syscalls: bool, syscall_handler: type[AndroidSyscallHandler32], jni_env: type[JNIEnv], java_vm: type[JavaVM]) -> None:
        self.vfs = AndroidFileSystem(self.rootfs, self)
        self.device.bind_memory(self.mem)
        self.syscalls = syscall_handler(self, strict=strict_syscalls)
        self.libc = AndroidLibcHooks32(self)
        self.jni = jni_env(self)
        self.javavm = java_vm(self)

    def _marshal_native(self, receiver_ref: int, arg_types: list[str], args: list[object]) -> None:
        self.backend.reg_write(Arm32Reg.R0, self.jni.pointer & 0xFFFFFFFF)
        self.backend.reg_write(Arm32Reg.R1, receiver_ref & 0xFFFFFFFF)
        next_register = 2
        stack: list[int] = []

        def spill(word: int) -> None:
            stack.append(word & 0xFFFFFFFF)

        for letter, value in zip(arg_types, args):
            if letter in "JD":
                bits = struct.unpack("<Q", struct.pack("<d", float(cast(Any, value))))[0] if letter == "D" else int(cast(Any, value)) & 0xFFFFFFFFFFFFFFFF
                low, high = bits & 0xFFFFFFFF, bits >> 32
                if next_register % 2:
                    next_register += 1
                if next_register + 1 <= 3:
                    self.backend.reg_write(Arm32Reg.R[next_register], low)
                    self.backend.reg_write(Arm32Reg.R[next_register + 1], high)
                    next_register += 2
                else:
                    next_register = 4
                    if len(stack) % 2:
                        spill(0)
                    spill(low)
                    spill(high)
            else:
                guest = struct.unpack("<I", struct.pack("<f", float(cast(Any, value))))[0] if letter == "F" else self._to_guest(letter, value)
                if next_register <= 3:
                    self.backend.reg_write(Arm32Reg.R[next_register], guest)
                    next_register += 1
                else:
                    spill(guest)
        if stack:
            sp = (self.sp - len(stack) * 4) & ~0x7
            for index, word in enumerate(stack):
                self.mem.write_u32(sp + index * 4, word)
            self.sp = sp

    def _read_native_return(self, return_type: str) -> object:
        if return_type == "V":
            return None
        value = self.get_return_value()
        if return_type == "F":
            return struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]
        if return_type in "DJ":
            bits = (value & 0xFFFFFFFF) | (self.read_register(Arm32Reg.R1) << 32)
            return struct.unpack("<d", struct.pack("<Q", bits))[0] if return_type == "D" else bits
        if return_type in ("L", "["):
            return self._unwrap_return(self.dvm.get(value))
        if return_type == "Z":
            return bool(value & 1)
        return value
