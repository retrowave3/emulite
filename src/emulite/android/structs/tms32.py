"""
sys/times.h

struct tms {
    clock_t tms_utime;
    clock_t tms_stime;
    clock_t tms_cutime;
    clock_t tms_cstime;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class Tms32(PackedStruct):
    SIZE = 16

    utime: int = 0
    stime: int = 0
    cutime: int = 0
    cstime: int = 0

    def pack(self) -> bytes:
        return struct.pack("<IIII", self.utime, self.stime, self.cutime, self.cstime)
