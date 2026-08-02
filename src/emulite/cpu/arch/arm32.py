from __future__ import annotations

from emulite.cpu.arch.base import Arch
from emulite.cpu.backend import Backend, CpuArch
from emulite.cpu.registers.arm32_reg import Arm32Reg
from emulite.memory import MemoryLayout32


class Arm32Arch(Arch):
    name = "arm"
    pointer_size = 4
    cpu_arch = CpuArch.ARM
    platform_string = "v7l"
    uname_machine = "armv8l"
    registers = Arm32Reg
    layout = MemoryLayout32
    frame_pointer = Arm32Reg.FP

    _SVC_A32 = 0xEF000000  # A32:   svc #imm24  (imm in the low 24 bits)
    _SVC_A32_MASK = 0xFF000000
    _SVC_T16 = 0xDF00  # Thumb: svc #imm8   (a 2-byte halfword)
    _SVC_T16_MASK = 0xFF00
    _BX_LR = 0xE12FFF1E  # A32 `bx lr` — the bridge-slot return
    _CPSR_T = 1 << 5  # CPSR.T — set when the core is in Thumb state
    _FPEXC_EN = 1 << 30  # FPEXC.EN — master enable for the VFP unit
    _CPACR_CP10_CP11 = 0xF << 20  # CPACR: full EL0/EL1 access to CP10/CP11 (VFP/NEON)

    def encode_svc(self, imm: int) -> int:
        return self._SVC_A32 | (imm & 0xFFFFFF)

    def trapped_svc(self, backend: Backend, mem: object, pc: int) -> int | None:
        if backend.reg_read(Arm32Reg.CPSR) & self._CPSR_T:
            instr = mem.read_u16(pc - 2)
            return (instr & 0xFF) if (instr & self._SVC_T16_MASK) == self._SVC_T16 else None
        instr = mem.read_u32(pc - 4)
        return (instr & 0xFFFFFF) if (instr & self._SVC_A32_MASK) == self._SVC_A32 else None

    @property
    def ret_instruction(self) -> int:
        return self._BX_LR

    def enable_fpu(self, backend: Backend) -> None:
        backend.reg_write(Arm32Reg.C1_C0_2, backend.reg_read(Arm32Reg.C1_C0_2) | self._CPACR_CP10_CP11)
        backend.reg_write(Arm32Reg.FPEXC, backend.reg_read(Arm32Reg.FPEXC) | self._FPEXC_EN)

    def setup_tls(self, backend: Backend, mem: object, base: int, stack_guard: int, errno_addr: int) -> None:
        # bionic-32 TLS: 4-byte slots read via the read-only thread register (TPIDRURO = CP15 c13,c0,3).
        # Slot indices mirror bionic (SELF=0, THREAD_ID=1, STACK_GUARD=5, BIONIC_TLS=8 holding errno).
        mem.write_u32(base + 0 * 4, base)  # TLS_SLOT_SELF
        mem.write_u32(base + 1 * 4, base + 0x100)  # TLS_SLOT_THREAD_ID (pthread_internal*)
        mem.write_u32(base + 5 * 4, stack_guard)  # TLS_SLOT_STACK_GUARD (the value)
        mem.write_u32(base + 8 * 4, errno_addr)  # TLS_SLOT_BIONIC_TLS (holds errno)
        backend.reg_write(Arm32Reg.C13_C0_3, base)  # TPIDRURO — what bionic reads for TLS
