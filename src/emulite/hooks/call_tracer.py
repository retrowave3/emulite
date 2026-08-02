from __future__ import annotations

from typing import TYPE_CHECKING

import capstone

from emulite.cpu.backend import CpuArch
from emulite.hooks.call_event import CallEvent
from emulite.hooks.disassembler import Disassembler
from emulite.hooks.types import CallTraceHook, TraceAction

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class CallTracer:
    _MAX_OPEN = 4096

    def __init__(self, emu: AndroidEmulatorBase, callback: CallTraceHook, disassembler: Disassembler) -> None:
        self._emu = emu
        self._callback = callback
        self._disasm = disassembler
        self._arm64 = emu.arch.cpu_arch is CpuArch.ARM64
        self._mask = (1 << (emu.arch.pointer_size * 8)) - 1
        regs = emu.arch.registers
        self._arg_regs = regs.ARG_REGS
        self._ret_reg = regs.RET_REG
        self._sp_reg = regs.SP
        self._open: list[tuple[CallEvent, int]] = []
        self._stopped = False

    def step(self, emu: AndroidEmulatorBase, address: int, size: int) -> None:
        if self._stopped:
            return
        self._evict(emu.reg(self._sp_reg))
        insn = self._disasm.one(emu.mem.read(address, 4), address)
        if insn is None:
            return
        if self._is_return(insn):
            self._complete(emu)
            return
        if insn.group(capstone.CS_GRP_CALL):
            target = self._target(emu, insn)
            event = CallEvent(
                caller=address, callee=target, callee_name=emu.describe_address(target) if target is not None else "?", args=tuple(emu.reg(r) for r in self._arg_regs), depth=len(self._open)
            )
            self._open.append((event, emu.reg(self._sp_reg)))
            if len(self._open) > self._MAX_OPEN:
                self._open.pop(0)

    def flush(self) -> None:
        while self._open and not self._stopped:
            self._emit(self._open.pop()[0])

    def _complete(self, emu: AndroidEmulatorBase) -> None:
        if not self._open:
            return
        event, _ = self._open.pop()
        event.return_value = emu.reg(self._ret_reg) & self._mask
        self._emit(event)

    def _evict(self, sp: int) -> None:
        while self._open and sp > self._open[-1][1]:
            self._emit(self._open.pop()[0])

    def _emit(self, event: CallEvent) -> None:
        result = self._callback(self._emu, event)
        if result is False or result is TraceAction.STOP_TRACING:
            self._stopped = True

    def _is_return(self, insn: capstone.CsInsn) -> bool:
        if insn.group(capstone.CS_GRP_RET) or insn.mnemonic == "ret":
            return True
        if not self._arm64:
            return (insn.mnemonic == "bx" and insn.op_str.strip() == "lr") or (insn.mnemonic.startswith("pop") and "pc" in insn.op_str)
        return False

    def _target(self, emu: AndroidEmulatorBase, insn: capstone.CsInsn) -> int | None:
        for op in insn.operands:
            if op.type == capstone.CS_OP_IMM:
                return op.imm & self._mask
            if op.type == capstone.CS_OP_REG:
                spec = self._disasm.resolve(insn.reg_name(op.reg))
                if spec is not None:
                    return emu.reg(spec[0]) & spec[1]
        return None
