"""
time.h

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class TimeSpec32(PackedStruct):
    SIZE = 8

    sec: int = 0
    nsec: int = 0

    @classmethod
    def from_ns(cls, total_ns: int) -> "TimeSpec32":
        return cls(sec=total_ns // 1_000_000_000, nsec=total_ns % 1_000_000_000)

    @classmethod
    def from_bytes(cls, data: bytes) -> "TimeSpec32":
        sec, nsec = struct.unpack_from("<ii", data)
        return cls(sec=sec, nsec=nsec)

    def total_ns(self) -> int:
        return self.sec * 1_000_000_000 + self.nsec

    def pack(self) -> bytes:
        return struct.pack("<ii", self.sec, self.nsec)
