from enum import IntFlag


class TimerFlag(IntFlag):
    """Linux timer operation flags."""

    ABSTIME = 0x1
