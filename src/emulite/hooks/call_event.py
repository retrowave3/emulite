from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class CallEvent:
    """A completed or flushed guest call observed by :meth:`call_trace`.

    ``return_value`` is ``None`` when the matching return was outside the traced
    range or the trace was flushed before the call returned.
    """

    caller: int  # address of the bl/blr instruction
    callee: int | None  # branch target, or None when an indirect target is unresolved
    callee_name: str  # symbolized target address
    args: tuple[int, ...] = ()
    return_value: int | None = None  # x0/r0 at the matching ret, or None if unmatched
    depth: int = 0
    caller_name: str = ""  # symbolized call-site address
    argument_registers: tuple[str, ...] = ()
    return_register: str = "return"

    def format(self) -> str:
        indent = "  " * self.depth
        caller = self._format_caller(self.caller_name or f"{self.caller:#x}")
        callee = self._format_address(self.callee_name)
        registers = tuple(self.argument_registers[index] if index < len(self.argument_registers) else f"arg{index}" for index in range(len(self.args)))
        args = ", ".join(f"{register}={value:#x}" for register, value in zip(registers, self.args))
        result = "" if self.return_value is None else f" => {self.return_register}={self.return_value:#x}"
        return f"{indent}{caller} -> {callee} ({args}){result}"

    @staticmethod
    def _format_caller(description: str) -> str:
        return description.partition(" ")[0]

    @staticmethod
    def _format_address(description: str) -> str:
        location, separator, symbol = description.partition(" ")
        if not separator or symbol.startswith("["):
            return description
        return f"{location} [{symbol}]"
