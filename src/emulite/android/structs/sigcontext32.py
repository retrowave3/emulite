"""
asm/sigcontext.h

struct sigcontext {
    unsigned long trap_no;
    unsigned long error_code;
    unsigned long oldmask;
    unsigned long arm_r0;
    unsigned long arm_r1;
    unsigned long arm_r2;
    unsigned long arm_r3;
    unsigned long arm_r4;
    unsigned long arm_r5;
    unsigned long arm_r6;
    unsigned long arm_r7;
    unsigned long arm_r8;
    unsigned long arm_r9;
    unsigned long arm_r10;
    unsigned long arm_fp;
    unsigned long arm_ip;
    unsigned long arm_sp;
    unsigned long arm_lr;
    unsigned long arm_pc;
    unsigned long arm_cpsr;
    unsigned long fault_address;
};
"""

from __future__ import annotations


class Sigcontext32:
    NREGS = 16  # r0..r15 (r13=SP, r14=LR, r15=PC)

    UC_MCONTEXT = 20
    _REGS = UC_MCONTEXT + 12  # after trap_no/error_code/oldmask
    _CPSR = UC_MCONTEXT + 76
    _FAULT = UC_MCONTEXT + 80

    @classmethod
    def save(
        cls, mem: object, uctx: int, regs: "list[int]", cpsr: int, fault_addr: int = 0
    ) -> None:
        for i in range(cls.NREGS):
            mem.write_u32(uctx + cls._REGS + i * 4, regs[i])
        mem.write_u32(uctx + cls._CPSR, cpsr)
        mem.write_u32(uctx + cls._FAULT, fault_addr)

    @classmethod
    def restore(cls, mem: object, uctx: int) -> "tuple[list[int], int]":
        regs = [mem.read_u32(uctx + cls._REGS + i * 4) for i in range(cls.NREGS)]
        cpsr = mem.read_u32(uctx + cls._CPSR)
        return regs, cpsr
