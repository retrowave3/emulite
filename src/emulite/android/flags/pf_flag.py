from __future__ import annotations

from enum import IntFlag


class PfFlag(IntFlag):
    PF_X = 0x1
    PF_W = 0x2
    PF_R = 0x4
