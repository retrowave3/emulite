from dataclasses import dataclass

from emulite.loader.enums.symbol_binding import SymbolBinding
from emulite.loader.enums.symbol_type import SymbolType


@dataclass
class Symbol:
    """A native symbol and its absolute guest address."""

    name: str
    address: int
    size: int = 0
    sym_type: SymbolType = SymbolType.NOTYPE
    binding: SymbolBinding = SymbolBinding.GLOBAL
    undefined: bool = False

    @property
    def is_function(self) -> bool:
        return self.sym_type in (SymbolType.FUNC, SymbolType.GNU_IFUNC)

    # a Symbol IS its guest address: hex(sym), f"{sym:#x}", int(sym), emu.call(sym), sym + 4 all work
    def __index__(self) -> int:
        return self.address

    __int__ = __index__

    def __add__(self, offset: int) -> int:
        return self.address + offset

    __radd__ = __add__

    def __format__(self, spec: str) -> str:  # f"{sym:#x}" formats the address; f"{sym}" stays the repr
        return format(self.address, spec) if spec else str(self)
