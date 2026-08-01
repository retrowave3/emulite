"""
linux/sysinfo.h

struct sysinfo {
    long uptime;
    unsigned long loads[3];
    unsigned long totalram;
    unsigned long freeram;
    unsigned long sharedram;
    unsigned long bufferram;
    unsigned long totalswap;
    unsigned long freeswap;
    unsigned short procs;
    unsigned short pad;
    unsigned long totalhigh;
    unsigned long freehigh;
    unsigned int mem_unit;
    char _f[8];
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class Sysinfo32(PackedStruct):
    SIZE = 64

    uptime: int = 0
    loads: tuple[int, int, int] = (0, 0, 0)
    totalram: int = 0
    freeram: int = 0
    sharedram: int = 0
    bufferram: int = 0
    procs: int = 0
    mem_unit: int = 1

    def pack(self) -> bytes:
        buf = bytearray(self.SIZE)  # totalswap/freeswap/totalhigh/freehigh stay 0
        struct.pack_into("<I", buf, 0, self.uptime)
        struct.pack_into("<III", buf, 4, *self.loads)
        struct.pack_into("<I", buf, 16, self.totalram)
        struct.pack_into("<I", buf, 20, self.freeram)
        struct.pack_into("<I", buf, 24, self.sharedram)
        struct.pack_into("<I", buf, 28, self.bufferram)
        struct.pack_into("<H", buf, 40, self.procs & 0xFFFF)
        struct.pack_into("<I", buf, 52, self.mem_unit)
        return bytes(buf)
