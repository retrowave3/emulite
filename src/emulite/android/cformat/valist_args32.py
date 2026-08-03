from __future__ import annotations

import struct
from typing import TYPE_CHECKING, ClassVar

from emulite.android.cformat.var_args import VarArgs

if TYPE_CHECKING:
    from emulite.android_emulator32 import AndroidEmulator32


class VaListArgs32(VarArgs):
    """Read an AArch32 ``va_list`` cursor using AAPCS alignment."""

    _WIDE_LENGTHS: ClassVar[frozenset[str]] = frozenset(("ll", "q", "j"))

    def __init__(self, emu: AndroidEmulator32, valist_ptr: int):
        super().__init__(emu)
        self._mem = emu.mem
        self._cursor = valist_ptr

    def integer(self, wide: bool = False) -> int:
        if wide:
            self._cursor = (self._cursor + 7) & ~7
            value = self._mem.read_u64(self._cursor)
            self._cursor += 8
            return value
        value = self._mem.read_u32(self._cursor)
        self._cursor += 4
        return value

    def real(self) -> float:
        return struct.unpack("<d", struct.pack("<Q", self.integer(True) & 0xFFFFFFFFFFFFFFFF))[0]
