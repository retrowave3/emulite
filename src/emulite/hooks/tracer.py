from __future__ import annotations

from typing import TYPE_CHECKING, Callable

import capstone

from emulite.hooks.disassembler import Disassembler
from emulite.hooks.trace_info import TraceInfo

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class Tracer:
    def __init__(
        self,
        emu: "AndroidEmulatorBase",
        callback: Callable[["AndroidEmulatorBase", TraceInfo], "bool | None"],
        disassembler: "Disassembler",
    ):
        self._emu = emu
        self._callback = callback
        self._disasm = disassembler
        self._pending: "TraceInfo | None" = None
        self._pending_written: list[str] = []
        self._stopped = False

    def step(self, emu: "AndroidEmulatorBase", address: int, size: int) -> None:
        if self._stopped:
            return
        self._finalize(emu)
        code = emu.mem.read(address, size)
        insn = self._disasm.one(code, address)
        if insn is None:
            self._pending = None
            return
        try:
            reads, writes = insn.regs_access()
        except capstone.CsError:
            reads, writes = (), ()
        module = emu.module_at(address)
        self._pending = TraceInfo(
            address=address,
            code=code,
            mnemonic=insn.mnemonic,
            operand=insn.op_str,
            instruction=insn,
            module_name=module.name if module else None,
            module_offset=(address - module.base) if module else 0,
            input_registers=self._values(emu, [insn.reg_name(r) for r in reads]),
        )
        self._pending_written = [insn.reg_name(w) for w in writes]

    def flush(self) -> None:
        self._finalize(self._emu)

    def _finalize(self, emu: "AndroidEmulatorBase") -> None:
        if self._pending is None or self._stopped:
            return
        self._pending.output_registers = self._values(emu, self._pending_written)
        info, self._pending = self._pending, None
        if self._callback(emu, info) is False:
            self._stopped = True

    def _values(self, emu: "AndroidEmulatorBase", names: list[str]) -> dict[str, int]:
        out: dict[str, int] = {}
        for name in names:
            spec = self._disasm.resolve(name)
            if spec is not None:
                reg_id, mask = spec
                out[name] = emu.reg(reg_id) & mask
        return out
