from __future__ import annotations

from enum import IntFlag


class FdFlag(IntFlag):
    NONE = 0
    FD_CLOEXEC = 0x1
