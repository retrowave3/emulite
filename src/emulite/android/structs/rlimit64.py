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
class RLimit64(PackedStruct):
    SIZE = 16
    RLIM_INFINITY = 0xFFFFFFFFFFFFFFFF

    cur: int = 0
    max: int = 0

    @classmethod
    def unlimited(cls) -> "RLimit64":
        return cls(cur=cls.RLIM_INFINITY, max=cls.RLIM_INFINITY)

    @classmethod
    def from_bytes(cls, data: bytes) -> "RLimit64":
        cur, max = struct.unpack_from("<QQ", data)
        return cls(cur=cur, max=max)

    def pack(self) -> bytes:
        return struct.pack("<QQ", self.cur, self.max)
