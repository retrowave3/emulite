"""
poll.h

struct pollfd {
    int fd;
    short events;
    short revents;
};
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Pollfd:
    SIZE = 8

    fd: int = 0
    events: int = 0
    revents: int = 0

    @classmethod
    def read_from(cls, mem: object, address: int) -> "Pollfd":
        return cls(fd=mem.read_s32(address), events=mem.read_u16(address + 4))

    @staticmethod
    def write_revents(mem: object, address: int, revents: int) -> None:
        mem.write_u16(address + 6, revents)
