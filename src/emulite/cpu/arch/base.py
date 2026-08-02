from __future__ import annotations

from abc import ABC, abstractmethod

from emulite.cpu.arch.register_namespace import RegisterNamespace
from emulite.cpu.backend import Backend, CpuArch


class Arch(ABC):
    name: str  # "arm64" — how the ELF loader keys its machine/reloc tables
    pointer_size: int  # bytes per pointer (8 on arm64 / LP64, 4 on arm32 / ILP32)
    cpu_arch: CpuArch  # which ISA the backend runs (mapped to the engine's own selectors)
    platform_string: str  # the AT_PLATFORM string placed on the initial stack ("aarch64")
    uname_machine: str  # utsname.machine — the execution state ("aarch64" / "armv8l"), not the ABI
    registers: type[RegisterNamespace]
    layout: type  # the MemoryLayout subtype: the guest address map for this arch
    frame_pointer: int  # the frame-pointer register id (x29 on arm64, r11 on arm32) — for the FP-chain unwinder

    @property
    def syscall_nr_reg(self) -> int:
        return self.registers.SYSCALL_NR

    @property
    def syscall_arg_regs(self) -> list[int]:
        return self.registers.SYSCALL_ARG_REGS

    @abstractmethod
    def encode_svc(self, imm: int) -> int:
        pass

    @abstractmethod
    def trapped_svc(self, backend: Backend, mem: object, pc: int) -> int | None:
        pass

    @property
    @abstractmethod
    def ret_instruction(self) -> int:
        pass

    @abstractmethod
    def enable_fpu(self, backend: Backend) -> None:
        pass

    def seed_system_registers(self, backend: Backend, device: object) -> None:
        return None

    @abstractmethod
    def setup_tls(self, backend: Backend, mem: object, base: int, stack_guard: int, errno_addr: int) -> None:
        pass
