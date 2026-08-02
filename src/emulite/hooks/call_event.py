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
    callee_name: str  # symbolized callee (module+off / symbol), for readability
    args: tuple[int, ...] = ()  # x0..x7 (arm64) / r0..r3 (arm32) at the call
    return_value: int | None = None  # x0/r0 at the matching ret, or None if unmatched
    depth: int = 0  # call-stack depth (indentation for a readable trace)

    def format(self) -> str:
        """Render a compact, indented call-trace line."""
        indent = "  " * self.depth
        args = ", ".join(f"{a:#x}" for a in self.args)
        result = "" if self.return_value is None else f" => {self.return_value:#x}"
        return f"{indent}-> {self.callee_name}({args}){result}"
