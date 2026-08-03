from enum import IntFlag


class MemoryRemapFlag(IntFlag):
    """Linux ``mremap`` behavior flags."""

    MAY_MOVE = 0x1
    FIXED = 0x2
    DO_NOT_UNMAP = 0x4
