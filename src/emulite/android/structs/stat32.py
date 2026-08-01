"""
sys/stat.h

struct stat {
    unsigned long long st_dev;
    unsigned char      __pad0[4];
    unsigned long      __st_ino;
    unsigned int       st_mode;
    nlink_t            st_nlink;
    uid_t              st_uid;
    gid_t              st_gid;
    unsigned long long st_rdev;
    unsigned char      __pad3[4];
    long long          st_size;
    unsigned long      st_blksize;
    unsigned long long st_blocks;
    struct timespec    st_atim;
    struct timespec    st_mtim;
    struct timespec    st_ctim;
    unsigned long long st_ino;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct
from emulite.filesystem.structs.file_stat import FileStat


@dataclass
class Stat32(PackedStruct):
    SIZE = 104

    dev: int = 0
    ino: int = 0
    mode: int = 0
    nlink: int = 1
    uid: int = 0
    gid: int = 0
    rdev: int = 0
    size: int = 0
    blksize: int = 0x1000
    blocks: int = 0
    atime: int = 0
    mtime: int = 0
    ctime: int = 0

    @classmethod
    def from_file_stat(cls, stat: FileStat) -> "Stat32":
        return cls(
            dev=stat.dev,
            ino=stat.ino,
            mode=stat.mode,
            nlink=stat.nlink,
            uid=stat.uid,
            gid=stat.gid,
            rdev=stat.rdev,
            size=stat.size,
            blksize=stat.blksize,
            blocks=stat.blocks,
            atime=stat.atime,
            mtime=stat.mtime,
            ctime=stat.ctime,
        )

    def pack(self) -> bytes:
        buf = bytearray(self.SIZE)
        struct.pack_into("<Q", buf, 0, self.dev)
        struct.pack_into("<I", buf, 12, self.ino & 0xFFFFFFFF)  # legacy 32-bit __st_ino (truncated)
        struct.pack_into("<I", buf, 16, self.mode)
        struct.pack_into("<I", buf, 20, self.nlink)
        struct.pack_into("<I", buf, 24, self.uid)
        struct.pack_into("<I", buf, 28, self.gid)
        struct.pack_into("<Q", buf, 32, self.rdev)
        struct.pack_into("<q", buf, 48, self.size)
        struct.pack_into("<I", buf, 56, self.blksize)
        struct.pack_into("<Q", buf, 64, self.blocks)
        struct.pack_into("<i", buf, 72, self.atime)
        struct.pack_into("<i", buf, 80, self.mtime)
        struct.pack_into("<i", buf, 88, self.ctime)
        struct.pack_into("<Q", buf, 96, self.ino)  # real 64-bit st_ino
        return bytes(buf)
