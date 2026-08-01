"""
sys/resource.h

struct rusage {
    struct timeval ru_utime;
    struct timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class Rusage64(PackedStruct):
    SIZE = 144

    utime_sec: int = 0
    utime_usec: int = 0
    stime_sec: int = 0
    stime_usec: int = 0
    maxrss: int = 0
    nvcsw: int = 0
    nivcsw: int = 0

    def pack(self) -> bytes:
        buf = bytearray(self.SIZE)
        struct.pack_into("<qq", buf, 0, self.utime_sec, self.utime_usec)
        struct.pack_into("<qq", buf, 16, self.stime_sec, self.stime_usec)
        struct.pack_into("<q", buf, 32, self.maxrss)
        struct.pack_into("<q", buf, 128, self.nvcsw)
        struct.pack_into("<q", buf, 136, self.nivcsw)
        return bytes(buf)
