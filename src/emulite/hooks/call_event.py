from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CallEvent:
    caller: int  # address of the bl/blr instruction
    callee: int  # branch target (the function entered)
    callee_name: str  # symbolized callee (module+off / symbol), for readability
    args: list[int] = field(default_factory=list)  # x0..x7 (arm64) / r0..r3 (arm32) at the call
    return_value: "int | None" = None  # x0/r0 at the matching ret, or None if unmatched
    depth: int = 0  # call-stack depth (indentation for a readable trace)

    def format(self) -> str:
        indent = "  " * self.depth
        args = ", ".join(f"{a:#x}" for a in self.args)
        result = "" if self.return_value is None else f" => {self.return_value:#x}"
        return f"{indent}-> {self.callee_name}({args}){result}"
