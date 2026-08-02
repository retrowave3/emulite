from enum import Enum, auto


class MemoryHookAction(Enum):
    """Control whether emulation should continue after a memory-hook event."""

    CONTINUE = auto()
    STOP_EMULATION = auto()
