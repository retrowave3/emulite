from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class VarArgs(ABC):
    _WIDE_LENGTHS = ("l", "ll", "q", "z", "j", "t")
    _SPEC = re.compile(
        r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|q|z|j|t)?([diouxXeEfFgGaAcspn%])"
    )

    def __init__(self, emu: "AndroidEmulatorBase"):
        self._emu = emu

    @abstractmethod
    def integer(self, wide: bool) -> int:
        pass

    @abstractmethod
    def real(self) -> float:
        pass

    @staticmethod
    def _signed(value: int, wide: bool) -> int:
        value &= 0xFFFFFFFFFFFFFFFF if wide else 0xFFFFFFFF
        limit = 1 << (64 if wide else 32)
        return value - limit if value >= limit // 2 else value

    def format(self, fmt: str) -> str:
        out, last = [], 0
        for match in self._SPEC.finditer(fmt):
            out.append(fmt[last : match.start()])
            last = match.end()
            flags, width, precision, length, conv = match.groups()
            if conv == "%":
                out.append("%")
                continue
            if width == "*":
                width = str(self.integer(False))
            if precision == "*":
                precision = str(self.integer(False))
            spec = (
                "%"
                + (flags or "")
                + (width or "")
                + ("." + precision if precision is not None else "")
            )
            wide = length in self._WIDE_LENGTHS
            if conv in "di":
                out.append((spec + "d") % self._signed(self.integer(wide), wide))
            elif conv in "ouxX":
                out.append(
                    (spec + conv)
                    % (self.integer(wide) & (0xFFFFFFFFFFFFFFFF if wide else 0xFFFFFFFF))
                )
            elif conv in "eEfFgGaA":
                out.append((spec + conv) % self.real())
            elif conv == "c":
                out.append((spec + "c") % (self.integer(False) & 0xFF))
            elif conv == "s":
                ptr = self.integer(False)
                out.append((spec + "s") % (self._emu.mem.read_cstr(ptr) if ptr else "(null)"))
            elif conv == "p":
                out.append("0x%x" % self.integer(False))
            elif conv == "n":
                self.integer(False)
        out.append(fmt[last:])
        return "".join(out)
