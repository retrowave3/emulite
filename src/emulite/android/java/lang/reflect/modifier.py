from __future__ import annotations

from enum import IntFlag


class Modifier(IntFlag):
    PUBLIC = 0x0001
    STATIC = 0x0008
