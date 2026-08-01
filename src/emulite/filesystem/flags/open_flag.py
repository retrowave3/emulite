from __future__ import annotations

from enum import IntFlag


class OpenFlag(IntFlag):
    O_RDONLY = 0x0
    O_WRONLY = 0x1
    O_RDWR = 0x2
    O_ACCMODE = 0x3  # mask for the access-mode bits above
    O_CREAT = 0x40
    O_EXCL = 0x80
    O_NOCTTY = 0x100
    O_TRUNC = 0x200
    O_APPEND = 0x400
    O_NONBLOCK = 0x800
    O_DSYNC = 0x1000
    O_ASYNC = 0x2000
    O_DIRECTORY = 0x4000
    O_NOFOLLOW = 0x8000
    O_DIRECT = 0x10000
    O_LARGEFILE = 0x20000
    O_NOATIME = 0x40000
    O_CLOEXEC = 0x80000
