from __future__ import annotations

from enum import IntFlag


class MmapFlag(IntFlag):
    MAP_FIXED = 0x10
    MAP_ANONYMOUS = 0x20
