"""
dirent.h

struct dirent64 {
    uint64_t d_ino;
    off64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class Dirent64(PackedStruct):
    HEADER_SIZE = 19  # d_ino + d_off + d_reclen + d_type, before the name

    ino: int
    off: int
    name: str
    d_type: int
    reclen: int = field(default=0)  # computed by create()

    @classmethod
    def create(cls, ino: int, off: int, name: str, d_type: int) -> "Dirent64":
        raw = len(name.encode("utf-8")) + 1  # + the NUL terminator
        reclen = (cls.HEADER_SIZE + raw + 7) & ~7  # 8-byte aligned, like the kernel
        return cls(ino=ino, off=off, name=name, d_type=d_type, reclen=reclen)

    def pack(self) -> bytes:
        buf = bytearray(self.reclen)
        struct.pack_into("<Q", buf, 0, self.ino)
        struct.pack_into("<Q", buf, 8, self.off)
        struct.pack_into("<H", buf, 16, self.reclen)
        buf[18] = self.d_type & 0xFF
        encoded = self.name.encode("utf-8")
        buf[19 : 19 + len(encoded)] = encoded  # NUL is implicit (buffer is zero-filled)
        return bytes(buf)
