from __future__ import annotations

from enum import IntFlag


class MmapFlag(IntFlag):
    """Common Linux ``mmap`` mapping flags."""

    MAP_SHARED = 0x01
    MAP_PRIVATE = 0x02
    MAP_SHARED_VALIDATE = 0x03
    MAP_FIXED = 0x10
    MAP_ANONYMOUS = 0x20
    MAP_FIXED_NOREPLACE = 0x100000
