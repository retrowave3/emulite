"""
sys/uio.h

struct iovec {
    void *iov_base;
    size_t iov_len;
};
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Iovec64:
    SIZE = 16

    base: int = 0
    length: int = 0

    @classmethod
    def read_from(cls, mem: object, address: int) -> "Iovec64":
        return cls(base=mem.read_u64(address), length=mem.read_u64(address + 8))

    @classmethod
    def read_array(cls, mem: object, address: int, count: int) -> "list[Iovec64]":
        return [cls.read_from(mem, address + i * cls.SIZE) for i in range(min(count, 1024))]
