from enum import Enum, auto


class MemoryFaultAction(Enum):
    """Report whether a memory fault was repaired by its callback."""

    UNHANDLED = auto()
    HANDLED = auto()
