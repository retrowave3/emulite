from enum import Enum, auto


class SymbolBinding(Enum):
    """ELF symbol visibility binding."""

    LOCAL = auto()
    GLOBAL = auto()
    WEAK = auto()
    GNU_UNIQUE = auto()
