from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from emulite.android.cformat.var_args import VarArgs
from emulite.cpu.registers.arm64_reg import Arm64Reg

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class RegisterArgs(VarArgs):
    def __init__(self, emu: "AndroidEmulatorBase", gp_start: int):
        super().__init__(emu)
        self._gp = gp_start
        self._fp = 0

    def integer(self, wide: bool = False) -> int:
        value = self._emu.reg(Arm64Reg.X[self._gp])
        self._gp += 1
        return value

    def real(self) -> float:
        bits = self._emu.backend.reg_read(Arm64Reg.Q[self._fp])
        self._fp += 1
        return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]
