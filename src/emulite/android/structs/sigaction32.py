"""
asm/signal.h

struct sigaction {
    __sighandler_t sa_handler;
    sigset_t sa_mask;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
};
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Sigaction32:
    handler: int = 0
    flags: int = 0
    restorer: int = 0

    @classmethod
    def read_from(cls, mem: object, address: int) -> "Sigaction32":
        # ARM32 kernel layout: flags@8, restorer@12 (offset 4 is sa_mask, skipped).
        return cls(handler=mem.read_u32(address), flags=mem.read_u32(address + 8), restorer=mem.read_u32(address + 12))

    def write_to(self, mem: object, address: int) -> None:
        mem.write_u32(address, self.handler)
        mem.write_u32(address + 8, self.flags)
        mem.write_u32(address + 12, self.restorer)
