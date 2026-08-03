from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from emulite.android.cformat.var_args import VarArgs

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class VaListArgs64(VarArgs):
    """Read an AArch64 ``va_list`` using the platform ABI layout."""

    def __init__(self, emu: AndroidEmulatorBase, valist_ptr: int):
        super().__init__(emu)
        self._mem = emu.mem
        self._stack = self._mem.read_u64(valist_ptr)
        self._gr_top = self._mem.read_u64(valist_ptr + 8)
        self._vr_top = self._mem.read_u64(valist_ptr + 16)
        self._gr = self._mem.read_s32(valist_ptr + 24)
        self._vr = self._mem.read_s32(valist_ptr + 28)

    def integer(self, wide: bool = False) -> int:
        if self._gr < 0:
            value = self._mem.read_u64(self._gr_top + self._gr)
            self._gr += 8
        else:
            value = self._mem.read_u64(self._stack)
            self._stack += 8
        return value

    def real(self) -> float:
        if self._vr < 0:
            raw = self._mem.read_u64(self._vr_top + self._vr)
            self._vr += 16
        else:
            raw = self._mem.read_u64(self._stack)
            self._stack += 8
        return struct.unpack("<d", struct.pack("<Q", raw & 0xFFFFFFFFFFFFFFFF))[0]
