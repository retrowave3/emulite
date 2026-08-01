from __future__ import annotations

from enum import IntFlag


class CloneFlag(IntFlag):
    CLONE_VM = 0x00000100
    CLONE_THREAD = 0x00010000
    CLONE_PARENT_SETTID = 0x00100000
    CLONE_CHILD_SETTID = 0x01000000
