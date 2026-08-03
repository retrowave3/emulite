from __future__ import annotations

from typing import TYPE_CHECKING

from emulite.cpu.arch.architecture_memory import ArchitectureMemory
from emulite.cpu.arch.base import Arch
from emulite.cpu.backend import Backend, CpuArch
from emulite.cpu.registers.arm64_reg import Arm64Reg
from emulite.memory import MemoryLayout

if TYPE_CHECKING:
    from emulite.android_device import AndroidDevice


class Arm64Arch(Arch):
    name = "arm64"
    pointer_size = 8
    cpu_arch = CpuArch.ARM64
    platform_string = "aarch64"
    uname_machine = "aarch64"
    registers = Arm64Reg
    layout = MemoryLayout
    frame_pointer = Arm64Reg.FP

    _RET = 0xD65F03C0  # ret (x30)
    _SVC_BASE = 0xD4000001  # svc #0
    _SVC_MASK = 0xFFE0001F  # bits that must match for an `svc #imm16`
    _CPACR_FPEN = 0x3 << 20  # CPACR_EL1.FPEN = 0b11<<20 enables FP/SIMD at EL0 (else NEON traps)
    _MIDR_EL1 = (3, 0, 0, 0, 0)

    def encode_svc(self, imm: int) -> int:
        if not 0 <= imm <= 0xFFFF:
            raise ValueError(f"AArch64 svc immediate must fit in 16 bits: {imm}")
        return self._SVC_BASE | (imm << 5)

    def trapped_svc(self, backend: Backend, mem: ArchitectureMemory, pc: int) -> int | None:
        instr = mem.read_u32(pc - 4)
        if (instr & self._SVC_MASK) != self._SVC_BASE:
            return None
        return (instr >> 5) & 0xFFFF

    @property
    def ret_instruction(self) -> int:
        return self._RET

    def enable_fpu(self, backend: Backend) -> None:
        backend.reg_write(Arm64Reg.CPACR_EL1, backend.reg_read(Arm64Reg.CPACR_EL1) | self._CPACR_FPEN)

    def seed_system_registers(self, backend: Backend, device: AndroidDevice) -> None:
        backend.write_sysreg(*self._MIDR_EL1, device.midr_el1())

    def setup_tls(self, backend: Backend, mem: ArchitectureMemory, base: int, stack_guard: int, errno_addr: int) -> None:
        # bionic layout, 8-byte slots:
        mem.write_u64(base + 0 * 8, base)  # TLS_SLOT_SELF
        mem.write_u64(base + 1 * 8, base + 0x100)  # TLS_SLOT_THREAD_ID (pthread_internal*)
        mem.write_u64(base + 5 * 8, stack_guard)  # TLS_SLOT_STACK_GUARD (the value)
        mem.write_u64(base + 8 * 8, errno_addr)  # TLS_SLOT_BIONIC_TLS (holds errno)
        backend.reg_write(Arm64Reg.TPIDR_EL0, base)
