"""
sys/statfs.h

struct statfs {
    uint64_t f_type;
    uint64_t f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    fsid_t   f_fsid;
    uint64_t f_namelen;
    uint64_t f_frsize;
    uint64_t f_flags;
    uint64_t f_spare[4];
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class StatFS64(PackedStruct):
    SIZE = 120

    fs_type: int = 0
    bsize: int = 0
    blocks: int = 0
    bfree: int = 0
    bavail: int = 0
    files: int = 0
    ffree: int = 0
    fsid0: int = 0
    fsid1: int = 0
    namelen: int = 0
    frsize: int = 0
    flags: int = 0

    def pack(self) -> bytes:
        buf = bytearray(self.SIZE)
        struct.pack_into("<q", buf, 0, self.fs_type)
        struct.pack_into("<q", buf, 8, self.bsize)
        struct.pack_into("<q", buf, 16, self.blocks)
        struct.pack_into("<q", buf, 24, self.bfree)
        struct.pack_into("<q", buf, 32, self.bavail)
        struct.pack_into("<q", buf, 40, self.files)
        struct.pack_into("<q", buf, 48, self.ffree)
        struct.pack_into("<i", buf, 56, self.fsid0)
        struct.pack_into("<i", buf, 60, self.fsid1)
        struct.pack_into("<q", buf, 64, self.namelen)
        struct.pack_into("<q", buf, 72, self.frsize)
        struct.pack_into("<q", buf, 80, self.flags)
        return bytes(buf)  # f_spare[4]@88 stays zero
