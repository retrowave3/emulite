from __future__ import annotations

from enum import IntEnum


class StatType(IntEnum):
    S_IFIFO = 0x1000  # FIFO / named pipe
    S_IFCHR = 0x2000  # character device
    S_IFDIR = 0x4000  # directory
    S_IFBLK = 0x6000  # block device
    S_IFREG = 0x8000  # regular file
    S_IFLNK = 0xA000  # symbolic link
    S_IFSOCK = 0xC000  # socket


StatType.S_IFMT = (
    0xF000  # st_mode file-type mask (a non-member: mode & StatType.S_IFMT == a StatType)
)
