from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from emulite.android.cformat.var_args import VarArgs
from emulite.cpu.registers.arm32_reg import Arm32Reg

if TYPE_CHECKING:
    from emulite.android_emulator32 import AndroidEmulator32


class RegisterArgs32(VarArgs):
    _WIDE_LENGTHS = ("ll", "q", "j")

    def __init__(self, emu: "AndroidEmulator32", gp_start: int):
        super().__init__(emu)
        self._core = gp_start
        self._stack = emu.sp

    def _core_word(self) -> int:
        value = self._emu.reg(Arm32Reg.R[self._core])
        self._core += 1
        return value

    def _stack_word(self) -> int:
        value = self._emu.mem.read_u32(self._stack)
        self._stack += 4
        return value

    def integer(self, wide: bool) -> int:
        if not wide:
            return self._core_word() if self._core < 4 else self._stack_word()
        if self._core % 2:
            self._core += 1
        if self._core + 2 <= 4:
            lo, hi = self._core_word(), self._core_word()
            return lo | (hi << 32)
        self._core = 4
        self._stack = (self._stack + 7) & ~7
        value = self._emu.mem.read_u64(self._stack)
        self._stack += 8
        return value

    def real(self) -> float:
        return struct.unpack("<d", struct.pack("<Q", self.integer(True) & 0xFFFFFFFFFFFFFFFF))[0]
