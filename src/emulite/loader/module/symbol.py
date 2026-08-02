from dataclasses import dataclass


@dataclass
class Symbol:
    name: str
    address: int  # absolute guest address (0 for an undefined/imported symbol)
    size: int = 0  # st_size (0 if unknown)
    sym_type: str = "NOTYPE"  # ELF STT_*: FUNC / OBJECT / NOTYPE / SECTION / FILE / TLS / GNU_IFUNC
    binding: str = "GLOBAL"  # ELF STB_*: GLOBAL / LOCAL / WEAK
    undefined: bool = False  # an external symbol this module imports (resolved elsewhere)

    @property
    def is_function(self) -> bool:
        return self.sym_type in ("FUNC", "GNU_IFUNC")

    # a Symbol IS its guest address: hex(sym), f"{sym:#x}", int(sym), emu.call(sym), sym + 4 all work
    def __index__(self) -> int:
        return self.address

    __int__ = __index__

    def __add__(self, offset: int) -> int:
        return self.address + offset

    __radd__ = __add__

    def __format__(self, spec: str) -> str:  # f"{sym:#x}" formats the address; f"{sym}" stays the repr
        return format(self.address, spec) if spec else str(self)
