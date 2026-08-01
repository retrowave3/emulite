from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import capstone

from emulite.common.errors import SymbolMissing
from emulite.loader.module.symbol import Symbol
from emulite.memory import MemoryManager

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


@dataclass
class NativeModule:
    _WILDCARD_TOKENS = {"??", "?", "*", "**", "..", ".", "xx", "x"}

    name: str
    path: str
    base: int
    size: int
    exports: dict[str, int] = field(default_factory=dict)
    symbols: list[Symbol] = field(default_factory=list, repr=False, compare=False)
    dependencies: list[str] = field(default_factory=list)
    segments: list[tuple[int, int, int]] = field(default_factory=list)
    import_relocations: list[tuple[int, str]] = field(
        default_factory=list, repr=False, compare=False
    )
    phdr_addr: int = 0
    phnum: int = 0
    dynamic_addr: int = 0
    entry_point: int = 0
    mem: "MemoryManager | None" = field(default=None, repr=False, compare=False)
    emu: "AndroidEmulatorBase | None" = field(default=None, repr=False, compare=False)
    _defined_index: "dict[str, Symbol] | None" = field(default=None, repr=False, compare=False)

    def __str__(self) -> str:
        return f"{self.name} @ {self.base:#x} (size {self.size:#x})"

    def init_functions(self) -> list[int]:
        return []

    def find_symbol(self, name: str) -> Symbol | None:
        if self._defined_index is None:
            self._defined_index = {s.name: s for s in self.symbols if not s.undefined and s.address}
        sym = self._defined_index.get(name)
        if sym is not None:
            return sym
        addr = self.exports.get(name)
        return Symbol(name, addr) if addr is not None else None

    def get_symbols(self) -> list[Symbol]:
        return (
            list(self.symbols)
            if self.symbols
            else [Symbol(name, addr) for name, addr in self.exports.items()]
        )

    def jni_methods(self) -> list[Symbol]:
        return [
            s
            for s in self.get_symbols()
            if s.name.startswith("Java_") and not s.undefined and s.address
        ]

    def get_import_relocations(self) -> list[tuple[int, str]]:
        return list(self.import_relocations)

    def symbol_at(self, addr: int) -> "tuple[Symbol, int] | None":
        if not self.contains(addr):
            return None
        best: Symbol | None = None
        best_val = -1
        for sym in self.get_symbols():
            # Thumb function symbols store the ISA bit in bit 0; runtime PCs do not.
            val = (sym.address & ~1) if sym.is_function else sym.address
            if sym.undefined or sym.address == 0 or val > addr:
                continue
            if best is None or val > best_val:
                best, best_val = sym, val
        return (best, addr - best_val) if best is not None else None

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.base + self.size

    def offset_of(self, addr: int) -> int:
        return addr - self.base

    def read(self, addr: int, size: int) -> bytes:
        return self._mem().read(addr, size)

    def scan_pattern(self, pattern: str) -> list[int]:
        matcher = self._compile_pattern(pattern)
        mem = self._mem()
        hits: list[int] = []
        for start, span, _perms in self.segments or [(self.base, self.size, 0)]:
            try:
                data = mem.read(start, span)
            except Exception:
                continue
            hits.extend(start + match.start() for match in matcher.finditer(data))
        return sorted(hits)

    def scan_pattern_first(self, pattern: str) -> int | None:
        hits = self.scan_pattern(pattern)
        return hits[0] if hits else None

    def call(self, offset: int, *args: int, **kwargs: object) -> object:
        if self.emu is None:
            raise RuntimeError(f"{self.name} is not attached to an emulator; cannot call")
        return self.emu.call(self.base + offset, *args, **kwargs)

    def call_symbol(self, name: str, *args: object, **kwargs: object) -> object:
        if self.emu is None:
            raise RuntimeError(f"{self.name} is not attached to an emulator; cannot call")
        symbol = self.find_symbol(name)
        if symbol is None:
            raise SymbolMissing(f"symbol {name!r} not found in {self.name}")
        return self.emu.call(symbol, *args, **kwargs)

    def disassemble(
        self, offset: int, count: int = 1, thumb: bool | None = None
    ) -> list[capstone.CsInsn]:
        if self.emu is None:
            raise RuntimeError(f"{self.name} is not attached to an emulator; cannot disassemble")
        return self.emu.disassemble(self.base + offset, count, thumb)

    def _mem(self) -> "MemoryManager":
        if self.mem is None:
            raise RuntimeError(
                f"{self.name} has no memory back-reference; load it through an emulator"
            )
        return self.mem

    @staticmethod
    def _compile_pattern(pattern: str) -> "re.Pattern[bytes]":
        text = pattern.strip()
        if " " in text:
            tokens = text.split()
        else:
            if len(text) % 2:
                raise ValueError(
                    f"odd-length byte pattern (continuous form needs whole bytes): {pattern!r}"
                )
            tokens = [text[i : i + 2] for i in range(0, len(text), 2)]
        parts = []
        for token in tokens:
            if token.lower() in NativeModule._WILDCARD_TOKENS:
                parts.append(b".")
                continue
            try:
                value = int(token, 16)
            except ValueError:
                raise ValueError(f"invalid byte-pattern token {token!r} in {pattern!r}") from None
            if not 0 <= value <= 0xFF:
                raise ValueError(f"byte-pattern token out of range: {token!r} in {pattern!r}")
            parts.append(re.escape(bytes([value])))
        if not parts:
            raise ValueError(f"empty byte pattern: {pattern!r}")
        return re.compile(b"".join(parts), re.DOTALL)
