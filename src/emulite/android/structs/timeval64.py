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
class Timeval64(PackedStruct):
    SIZE = 16

    sec: int = 0
    usec: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> "Timeval64":
        sec, usec = struct.unpack_from("<qq", data)
        return cls(sec=sec, usec=usec)

    def pack(self) -> bytes:
        return struct.pack("<qq", self.sec, self.usec)
