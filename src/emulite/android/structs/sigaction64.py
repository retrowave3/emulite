"""
asm/signal.h

struct sigaction {
    __sighandler_t sa_handler;
    unsigned long sa_flags;
    __sigrestore_t sa_restorer;
    sigset_t sa_mask;
};
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Sigaction64:
    handler: int = 0
    flags: int = 0
    restorer: int = 0

    @classmethod
    def read_from(cls, mem: object, address: int) -> "Sigaction64":
        return cls(
            handler=mem.read_u64(address),
            flags=mem.read_u64(address + 8),
            restorer=mem.read_u64(address + 16),
        )

    def write_to(self, mem: object, address: int) -> None:
        mem.write_u64(address, self.handler)
        mem.write_u64(address + 8, self.flags)
        mem.write_u64(address + 16, self.restorer)
