"""
sys/statfs.h

struct statfs {
    uint32_t f_type;
    uint32_t f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    fsid_t   f_fsid;
    uint32_t f_namelen;
    uint32_t f_frsize;
    uint32_t f_flags;
    uint32_t f_spare[4];
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class StatFS32(PackedStruct):
    SIZE = 88

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
        struct.pack_into("<I", buf, 0, self.fs_type)
        struct.pack_into("<I", buf, 4, self.bsize)
        struct.pack_into("<Q", buf, 8, self.blocks)
        struct.pack_into("<Q", buf, 16, self.bfree)
        struct.pack_into("<Q", buf, 24, self.bavail)
        struct.pack_into("<Q", buf, 32, self.files)
        struct.pack_into("<Q", buf, 40, self.ffree)
        struct.pack_into("<i", buf, 48, self.fsid0)
        struct.pack_into("<i", buf, 52, self.fsid1)
        struct.pack_into("<I", buf, 56, self.namelen)
        struct.pack_into("<I", buf, 60, self.frsize)
        struct.pack_into("<I", buf, 64, self.flags)
        return bytes(buf)  # f_spare@68 (16 bytes) + tail pad stay zero
