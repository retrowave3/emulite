"""
asm/sigcontext.h

struct sigcontext {
    __u64 fault_address;
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
    __u8 __reserved[4096];
};
"""

from __future__ import annotations


class Sigcontext64:
    NREGS = 31  # x0..x30

    UC_MCONTEXT = 176
    _FAULT = UC_MCONTEXT
    _REGS = UC_MCONTEXT + 8
    _SP = _REGS + NREGS * 8
    _PC = _SP + 8
    _PSTATE = _PC + 8

    @classmethod
    def save(
        cls,
        mem: object,
        uctx: int,
        regs: "list[int]",
        sp: int,
        pc: int,
        pstate: int,
        fault_addr: int = 0,
    ) -> None:
        mem.write_u64(uctx + cls._FAULT, fault_addr)
        for i in range(cls.NREGS):
            mem.write_u64(uctx + cls._REGS + i * 8, regs[i])
        mem.write_u64(uctx + cls._SP, sp)
        mem.write_u64(uctx + cls._PC, pc)
        mem.write_u64(uctx + cls._PSTATE, pstate)

    @classmethod
    def restore(cls, mem: object, uctx: int) -> "tuple[list[int], int, int, int]":
        regs = [mem.read_u64(uctx + cls._REGS + i * 8) for i in range(cls.NREGS)]
        sp = mem.read_u64(uctx + cls._SP)
        pc = mem.read_u64(uctx + cls._PC)
        pstate = mem.read_u64(uctx + cls._PSTATE)
        return regs, sp, pc, pstate
