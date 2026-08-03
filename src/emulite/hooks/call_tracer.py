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
        prefix = "x" if self._arm64 else "r"
        self._argument_registers = tuple(f"{prefix}{index}" for index in range(len(self._arg_regs)))
        self._return_register = f"{prefix}0"
        self._open: list[tuple[CallEvent, int]] = []
        self._stopped = False

    def step(self, emu: AndroidEmulatorBase, address: int, size: int) -> None:
        if self._stopped:
            return
        self._evict(emu.read_register(self._sp_reg))
        insn = self._disasm.one(emu.mem.read(address, 4), address)
        if insn is None:
            return
        if self._is_return(insn):
            self._complete(emu)
            return
        if insn.group(capstone.CS_GRP_CALL):
            target = self._target(emu, insn)
            event = CallEvent(
                caller=address,
                callee=target,
                callee_name=emu.describe_address(target) if target is not None else "?",
                args=tuple(emu.read_register(register) for register in self._arg_regs),
                depth=len(self._open),
                caller_name=emu.describe_address(address),
                argument_registers=self._argument_registers,
                return_register=self._return_register,
            )
            self._open.append((event, emu.read_register(self._sp_reg)))
            if len(self._open) > self._MAX_OPEN:
                self._open.pop(0)

    def flush(self) -> None:
        while self._open and not self._stopped:
            self._emit(self._open.pop()[0])

    def _complete(self, emu: AndroidEmulatorBase) -> None:
        if not self._open:
            return
        event, _ = self._open.pop()
        event.return_value = emu.read_register(self._ret_reg) & self._mask
        self._emit(event)

    def _evict(self, sp: int) -> None:
        while self._open and sp > self._open[-1][1]:
            self._emit(self._open.pop()[0])

    def _emit(self, event: CallEvent) -> None:
        result = self._callback(self._emu, event)
        if result is TraceAction.STOP_TRACING:
            self._stopped = True
        elif result is not None and result is not TraceAction.CONTINUE:
            raise TypeError(f"call trace hook returned {result!r}; expected TraceAction or None")

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
                    return emu.read_register(spec[0]) & spec[1]
        return None
