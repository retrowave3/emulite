"""
sys/resource.h

struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class RLimit32(PackedStruct):
    SIZE = 8
    RLIM_INFINITY = 0xFFFFFFFF

    cur: int = 0
    max: int = 0

    @classmethod
    def unlimited(cls) -> "RLimit32":
        return cls(cur=cls.RLIM_INFINITY, max=cls.RLIM_INFINITY)

    @classmethod
    def from_bytes(cls, data: bytes) -> "RLimit32":
        cur, max = struct.unpack_from("<II", data)
        return cls(cur=cur, max=max)

    def pack(self) -> bytes:
        return struct.pack("<II", self.cur, self.max)
