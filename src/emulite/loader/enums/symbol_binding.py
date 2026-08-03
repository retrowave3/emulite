from enum import Enum, auto


class SymbolBinding(Enum):
    """ELF symbol linkage binding."""

    LOCAL = auto()
    GLOBAL = auto()
    WEAK = auto()
    GNU_UNIQUE = auto()
