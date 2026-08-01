"""
time.h

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long tm_gmtoff;
    const char* tm_zone;
};
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class Tm64(PackedStruct):
    SIZE = 56

    sec: int = 0  # tm_sec  (0-60)
    min: int = 0  # tm_min  (0-59)
    hour: int = 0  # tm_hour (0-23)
    mday: int = 0  # tm_mday (1-31)
    mon: int = 0  # tm_mon  (0-11)
    year: int = 0  # tm_year (years since 1900)
    wday: int = 0  # tm_wday (0-6, Sunday = 0)
    yday: int = 0  # tm_yday (0-365)
    isdst: int = 0  # tm_isdst
    gmtoff: int = 0  # tm_gmtoff (seconds east of UTC)
    zone: int = 0  # tm_zone (guest pointer to the zone name, or 0)

    @classmethod
    def from_struct_time(cls, st: time.struct_time, gmtoff: int = 0, zone: int = 0) -> "Tm64":
        return cls(
            sec=st.tm_sec,
            min=st.tm_min,
            hour=st.tm_hour,
            mday=st.tm_mday,
            mon=st.tm_mon - 1,
            year=st.tm_year - 1900,
            wday=(st.tm_wday + 1) % 7,
            yday=st.tm_yday - 1,
            isdst=st.tm_isdst,
            gmtoff=gmtoff,
            zone=zone,
        )

    def pack(self) -> bytes:
        buf = bytearray(self.SIZE)
        for offset, value in (
            (0, self.sec),
            (4, self.min),
            (8, self.hour),
            (12, self.mday),
            (16, self.mon),
            (20, self.year),
            (24, self.wday),
            (28, self.yday),
            (32, self.isdst),
        ):
            struct.pack_into("<i", buf, offset, value)
        struct.pack_into("<q", buf, 40, self.gmtoff)  # 4 bytes padding at 36
        struct.pack_into("<Q", buf, 48, self.zone)
        return bytes(buf)
