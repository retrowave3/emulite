"""
asm-generic/stat.h

struct stat {
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned int  st_mode;
    unsigned int  st_nlink;
    unsigned int  st_uid;
    unsigned int  st_gid;
    unsigned long st_rdev;
    unsigned long __pad1;
    long          st_size;
    int           st_blksize;
    int           __pad2;
    long          st_blocks;
    long          st_atime;
    unsigned long st_atime_nsec;
    long          st_mtime;
    unsigned long st_mtime_nsec;
    long          st_ctime;
    unsigned long st_ctime_nsec;
    unsigned int  __unused4;
    unsigned int  __unused5;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct
from emulite.filesystem.structs.file_stat import FileStat


@dataclass
class Stat64(PackedStruct):
    SIZE = 128

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
    def from_file_stat(cls, stat: FileStat) -> "Stat64":
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
        struct.pack_into("<Q", buf, 8, self.ino)
        struct.pack_into("<I", buf, 16, self.mode)
        struct.pack_into("<I", buf, 20, self.nlink)
        struct.pack_into("<I", buf, 24, self.uid)
        struct.pack_into("<I", buf, 28, self.gid)
        struct.pack_into("<Q", buf, 32, self.rdev)
        struct.pack_into("<q", buf, 48, self.size)
        struct.pack_into("<I", buf, 56, self.blksize)
        struct.pack_into("<q", buf, 64, self.blocks)
        struct.pack_into("<q", buf, 72, self.atime)
        struct.pack_into("<q", buf, 88, self.mtime)
        struct.pack_into("<q", buf, 104, self.ctime)
        return bytes(buf)
