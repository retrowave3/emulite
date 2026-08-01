"""
linux/stat.h

struct statx {
    __u32 stx_mask;
    __u32 stx_blksize;
    __u64 stx_attributes;
    __u32 stx_nlink;
    __u32 stx_uid;
    __u32 stx_gid;
    __u16 stx_mode;
    __u16 __spare0[1];
    __u64 stx_ino;
    __u64 stx_size;
    __u64 stx_blocks;
    __u64 stx_attributes_mask;
    struct statx_timestamp stx_atime;
    struct statx_timestamp stx_btime;
    struct statx_timestamp stx_ctime;
    struct statx_timestamp stx_mtime;
    __u32 stx_rdev_major;
    __u32 stx_rdev_minor;
    __u32 stx_dev_major;
    __u32 stx_dev_minor;
    __u64 stx_mnt_id;
    __u32 stx_dio_mem_align;
    __u32 stx_dio_offset_align;
    __u64 __spare3[12];
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class Statx(PackedStruct):
    SIZE = 256
    blksize: int = 0x1000
    nlink: int = 1
    uid: int = 0
    gid: int = 0
    ino: int = 0
    mode: int = 0
    size: int = 0
    blocks: int = 0
    time_sec: int = 0  # written to all four statx_timestamp.tv_sec slots
    rdev_major: int = 0
    rdev_minor: int = 0
    mask: int = 0x7FF  # STATX_BASIC_STATS

    def pack(self) -> bytes:
        buf = bytearray(self.SIZE)
        struct.pack_into("<I", buf, 0, self.mask)
        struct.pack_into("<I", buf, 4, self.blksize)
        struct.pack_into("<I", buf, 16, self.nlink)
        struct.pack_into("<I", buf, 20, self.uid)
        struct.pack_into("<I", buf, 24, self.gid)
        struct.pack_into("<H", buf, 28, self.mode & 0xFFFF)
        struct.pack_into("<Q", buf, 32, self.ino)  # stx_ino
        struct.pack_into("<Q", buf, 40, self.size)
        struct.pack_into("<Q", buf, 48, self.blocks)
        for offset in (64, 80, 96, 112):  # atime / btime / ctime / mtime — tv_sec at each
            struct.pack_into("<Q", buf, offset, self.time_sec)
        struct.pack_into("<I", buf, 128, self.rdev_major)
        struct.pack_into("<I", buf, 132, self.rdev_minor)
        return bytes(buf)
