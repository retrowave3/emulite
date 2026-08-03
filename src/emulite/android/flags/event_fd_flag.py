from enum import IntFlag


class EventFdFlag(IntFlag):
    """Linux ``eventfd2`` creation flags."""

    SEMAPHORE = 0x1
    NONBLOCK = 0x800
    CLOSE_ON_EXEC = 0x80000
