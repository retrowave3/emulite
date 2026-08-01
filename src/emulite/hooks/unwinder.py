from __future__ import annotations

from typing import TYPE_CHECKING

from emulite.common.errors import EmulatorCrashed
from emulite.cpu.backend import MemoryProtectionFlag
from emulite.hooks.frame import Frame

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class Unwinder:
    def __init__(self, emu: "AndroidEmulatorBase"):
        self._emu = emu
        self._pointer_size = emu.arch.pointer_size
        self._mask = (1 << (self._pointer_size * 8)) - 1
        self._fp_reg = emu.arch.frame_pointer
        self._read = emu.mem.read_u64 if self._pointer_size == 8 else emu.mem.read_u32

    def frames(self, max_depth: int = 64) -> list[Frame]:
        emu = self._emu
        regs = emu.arch.registers
        out = [Frame(0, emu.pc, emu.describe_address(emu.pc))]
        lr = emu.reg(regs.LR) & self._mask
        if self._is_code(lr):
            out.append(Frame(len(out), lr, emu.describe_address(lr)))
        fp = emu.reg(self._fp_reg) & self._mask
        for _ in range(max_depth):
            if not fp or fp % self._pointer_size:
                break
            try:
                saved_fp = self._read(fp) & self._mask
                saved_lr = self._read(fp + self._pointer_size) & self._mask
            except EmulatorCrashed:
                break
            if not self._is_code(saved_lr):
                break
            if saved_lr != out[-1].address:
                out.append(Frame(len(out), saved_lr, emu.describe_address(saved_lr)))
            if saved_fp <= fp:
                break
            fp = saved_fp
        return out

    def _is_code(self, address: int) -> bool:
        return bool(address) and bool(
            self._emu.mem.permission_at(address) & MemoryProtectionFlag.EXEC
        )
