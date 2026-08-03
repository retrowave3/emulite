from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from emulite.filesystem.enums.stat_type import StatType


@dataclass
class FileStat:
    """Portable file metadata used to build architecture-specific stat structs."""

    _FIXED_MTIME: ClassVar[int] = 1677974400
    _BLKSIZE: ClassVar[int] = 0x1000
    REG_MODE: ClassVar[int] = StatType.S_IFREG | 0x1A4  # 0644
    DIR_MODE: ClassVar[int] = StatType.S_IFDIR | 0x16D  # 0755
    CHR_MODE: ClassVar[int] = StatType.S_IFCHR | 0x1B6  # 0666
    SOCK_MODE: ClassVar[int] = StatType.S_IFSOCK | 0x1FF  # 0777
    FIFO_MODE: ClassVar[int] = StatType.S_IFIFO | 0x1A4  # 0644
    ANON_MODE: ClassVar[int] = StatType.S_IFREG | 0x180  # 0600

    mode: int = 0
    size: int = 0
    rdev: int = 0
    nlink: int = 1
    uid: int = 0
    gid: int = 0
    ino: int = 0
    dev: int = 0
    blksize: int = _BLKSIZE
    atime: int = _FIXED_MTIME
    mtime: int = _FIXED_MTIME
    ctime: int = _FIXED_MTIME

    @property
    def blocks(self) -> int:
        return (self.size + 511) // 512

    @classmethod
    def for_file(cls, size: int, mode: int | None = None) -> FileStat:
        return cls(mode=cls.REG_MODE if mode is None else mode, size=size, nlink=1)

    @classmethod
    def for_directory(cls, mode: int | None = None) -> FileStat:
        return cls(mode=cls.DIR_MODE if mode is None else mode, size=cls._BLKSIZE, nlink=2)

    @classmethod
    def for_char_device(cls, rdev: int, mode: int | None = None) -> FileStat:
        return cls(mode=cls.CHR_MODE if mode is None else mode, size=0, rdev=rdev, nlink=1)

    @classmethod
    def for_socket(cls, mode: int | None = None) -> FileStat:
        return cls(mode=cls.SOCK_MODE if mode is None else mode, size=0, nlink=1)

    @classmethod
    def for_fifo(cls, mode: int | None = None) -> FileStat:
        return cls(mode=cls.FIFO_MODE if mode is None else mode, size=0, nlink=1)

    @classmethod
    def for_anon_inode(cls, mode: int | None = None) -> FileStat:
        return cls(mode=cls.ANON_MODE if mode is None else mode, size=0, nlink=1)
