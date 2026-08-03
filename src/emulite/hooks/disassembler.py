from __future__ import annotations

from typing import TYPE_CHECKING

import capstone

from emulite.cpu.backend import CpuArch
from emulite.cpu.registers.arm32_reg import Arm32Reg

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class Disassembler:
    _CPSR_T = 1 << 5
    _MAX_INSN = 4

    def __init__(self, emu: AndroidEmulatorBase) -> None:
        self._emu = emu
        self._regs = emu.arch.registers
        self._arm64 = emu.arch.cpu_arch is CpuArch.ARM64
        if self._arm64:
            self._cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            self._cs.detail = True
        else:
            self._cs_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            self._cs_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
            self._cs_arm.detail = self._cs_thumb.detail = True

    def engine(self, thumb: bool | None = None) -> capstone.Cs:
        if self._arm64:
            return self._cs
        if thumb is None:
            thumb = bool(self._emu.reg(Arm32Reg.CPSR) & self._CPSR_T)
        return self._cs_thumb if thumb else self._cs_arm

    def one(self, code: bytes, address: int, thumb: bool | None = None) -> capstone.CsInsn | None:
        for insn in self.engine(thumb).disasm(code, address, count=1):
            return insn
        return None

    def disassemble(self, address: int, count: int = 1, thumb: bool | None = None) -> list[capstone.CsInsn]:
        """Disassemble up to ``count`` instructions from guest memory."""
        if count < 0:
            raise ValueError("disassembly count must not be negative")
        thumb, address = self._resolve_mode(thumb, address)
        out: list[capstone.CsInsn] = []
        cursor = address
        for _ in range(count):
            insn = self.one(self._emu.mem.read(cursor, self._MAX_INSN), cursor, thumb)
            if insn is None:
                break
            out.append(insn)
            cursor += insn.size
        return out

    def disassemble_bytes(self, code: bytes, address: int = 0, thumb: bool | None = None) -> list[capstone.CsInsn]:
        """Disassemble an in-memory byte string without mapping it into the guest."""
        thumb, address = self._resolve_mode(thumb, address)
        return list(self.engine(thumb).disasm(code, address))

    def _resolve_mode(self, thumb: bool | None, address: int) -> tuple[bool | None, int]:
        if not self._arm64 and thumb is None:
            thumb = bool(address & 1)
        return thumb, address & ~1

    def resolve(self, name: str) -> tuple[int, int] | None:
        name = name.lower()
        if not name:
            return None
        regs = self._regs
        if name and name[0] in "vqdshb" and name[1:].isdigit():
            return None
        if self._arm64:
            if name in ("xzr", "wzr"):
                return None
            if name == "wsp":
                return (regs.SP, 0xFFFFFFFF)
            if name[0] == "w" and name[1:].isdigit() and hasattr(regs, "X" + name[1:]):
                return (getattr(regs, "X" + name[1:]), 0xFFFFFFFF)
            rid = getattr(regs, name.upper(), None)
            if isinstance(rid, int):
                return (rid, 0xFFFFFFFFFFFFFFFF)
        else:
            key = {"r13": "SP", "r14": "LR", "r15": "PC", "apsr": "CPSR"}.get(name, name.upper())
            rid = getattr(regs, key, None)
            if isinstance(rid, int):
                return (rid, 0xFFFFFFFF)
        return None
