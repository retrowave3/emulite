from enum import Enum, auto


class SymbolType(Enum):
    """ELF symbol kind."""

    NOTYPE = auto()
    OBJECT = auto()
    FUNC = auto()
    SECTION = auto()
    FILE = auto()
    COMMON = auto()
    TLS = auto()
    GNU_IFUNC = auto()
