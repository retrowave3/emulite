from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from emulite.android.cformat.var_args import VarArgs
from emulite.cpu.registers.arm64_reg import Arm64Reg

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class RegisterArgs64(VarArgs):
    """Read AArch64 variadic arguments from registers and the stack."""

    def __init__(self, emu: AndroidEmulatorBase, gp_start: int):
        if not 0 <= gp_start <= 8:
            raise ValueError("gp_start must be between 0 and 8")
        super().__init__(emu)
        self._gp = gp_start
        self._fp = 0
        self._stack = emu.sp

    def integer(self, wide: bool = False) -> int:
        if self._gp < 8:
            value = self._emu.reg(Arm64Reg.X[self._gp])
            self._gp += 1
            return value
        value = self._emu.mem.read_u64(self._stack)
        self._stack += 8
        return value

    def real(self) -> float:
        if self._fp < 8:
            bits = self._emu.backend.reg_read(Arm64Reg.Q[self._fp])
            self._fp += 1
        else:
            bits = self._emu.mem.read_u64(self._stack)
            self._stack += 8
        return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]
