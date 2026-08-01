"""
time.h

struct timeval {
    time_t tv_sec;
    suseconds_t tv_usec;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class Timeval32(PackedStruct):
    SIZE = 8

    sec: int = 0
    usec: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> "Timeval32":
        sec, usec = struct.unpack_from("<ii", data)
        return cls(sec=sec, usec=usec)

    def pack(self) -> bytes:
        return struct.pack("<ii", self.sec, self.usec)
