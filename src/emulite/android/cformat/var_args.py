from __future__ import annotations

import re
from abc import ABC, abstractmethod
from math import copysign, isfinite
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class VarArgs(ABC):
    """Consume ABI-specific variadic arguments and apply C printf formatting."""

    _WIDE_LENGTHS: ClassVar[frozenset[str]] = frozenset(("l", "ll", "q", "z", "j", "t"))
    _SPEC: ClassVar[re.Pattern[str]] = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|q|z|j|t)?([diouxXeEfFgGaAcspn%])")

    def __init__(self, emu: AndroidEmulatorBase):
        self._emu = emu

    @abstractmethod
    def integer(self, wide: bool = False) -> int:
        raise NotImplementedError

    @abstractmethod
    def real(self) -> float:
        raise NotImplementedError

    @staticmethod
    def _signed(value: int, bits: int) -> int:
        limit = 1 << bits
        value &= limit - 1
        return value - limit if value >= limit // 2 else value

    def _value_bits(self, length: str | None) -> int:
        if length == "hh":
            return 8
        if length == "h":
            return 16
        if length in ("ll", "q", "j"):
            return 64
        if length in ("l", "z", "t"):
            return self._emu.arch.pointer_size * 8
        return 32

    @staticmethod
    def _pad(text: str, flags: str, width: str | None, zero_prefix: int = 0) -> str:
        if width is None or len(text) >= int(width):
            return text
        padding = int(width) - len(text)
        if "-" in flags:
            return text + " " * padding
        if "0" in flags:
            return text[:zero_prefix] + "0" * padding + text[zero_prefix:]
        return " " * padding + text

    @classmethod
    def _hex_float(cls, value: float, flags: str, width: str | None, precision: str | None, uppercase: bool) -> str:
        negative = copysign(1.0, value) < 0
        body = abs(value).hex()
        if isfinite(value):
            mantissa, exponent = body.split("p")
            prefix, significand = mantissa[:2], mantissa[2:]
            whole, fraction = significand.split(".")
            if precision is None:
                fraction = fraction.rstrip("0")
                digits = len(fraction)
            else:
                digits = int(precision)
                if digits < len(fraction):
                    shift = 4 * (len(fraction) - digits)
                    retained, discarded = divmod(int(whole + fraction, 16), 1 << shift)
                    halfway = 1 << (shift - 1)
                    if discarded > halfway or discarded == halfway and retained & 1:
                        retained += 1
                    significand = f"{retained:0{digits + 1}x}"
                    whole, fraction = significand[:-digits] if digits else significand, significand[-digits:] if digits else ""
                else:
                    fraction += "0" * (digits - len(fraction))
            point = "." if digits or "#" in flags else ""
            body = f"{prefix}{whole}{point}{fraction}p{exponent}"
        sign = "-" if negative else "+" if "+" in flags else " " if " " in flags else ""
        text = sign + (body.upper() if uppercase else body)
        prefix_length = len(sign) + (2 if body.startswith("0x") else 0)
        return cls._pad(text, flags, width, prefix_length)

    def _write_count(self, address: int, length: str | None, count: int) -> None:
        bits = self._value_bits(length)
        writer = {8: self._emu.mem.write_u8, 16: self._emu.mem.write_u16, 32: self._emu.mem.write_u32, 64: self._emu.mem.write_u64}[bits]
        writer(address, count & ((1 << bits) - 1))

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
                dynamic_width = self._signed(self.integer(), 32)
                if dynamic_width < 0:
                    flags += "-"
                    dynamic_width = -dynamic_width
                width = str(dynamic_width)
            if precision == "*":
                dynamic_precision = self._signed(self.integer(), 32)
                precision = str(dynamic_precision) if dynamic_precision >= 0 else None
            spec = "%" + (flags or "") + (width or "") + ("." + precision if precision is not None else "")
            wide = length in self._WIDE_LENGTHS
            bits = self._value_bits(length)
            if conv in "di":
                out.append((spec + "d") % self._signed(self.integer(wide), bits))
            elif conv in "ouxX":
                out.append((spec + conv) % (self.integer(wide) & ((1 << bits) - 1)))
            elif conv in "eEfFgG":
                out.append((spec + conv) % self.real())
            elif conv in "aA":
                out.append(self._hex_float(self.real(), flags, width, precision, conv == "A"))
            elif conv == "c":
                out.append((spec + "c") % (self.integer() & 0xFF))
            elif conv == "s":
                ptr = self.integer()
                out.append((spec + "s") % (self._emu.mem.read_cstr(ptr) if ptr else "(null)"))
            elif conv == "p":
                pointer = self.integer()
                digits = f"{pointer:x}"
                if precision is not None:
                    digits = digits.rjust(int(precision), "0")
                out.append(self._pad("0x" + digits, flags, width, 2))
            elif conv == "n":
                pointer = self.integer()
                self._write_count(pointer, length, sum(len(part.encode("utf-8")) for part in out))
        out.append(fmt[last:])
        return "".join(out)
