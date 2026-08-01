from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import capstone


@dataclass
class TraceInfo:
    address: int
    code: bytes
    mnemonic: str
    operand: str
    instruction: capstone.CsInsn | None = None
    module_name: str | None = None
    module_offset: int = 0
    input_registers: dict[str, int] = field(default_factory=dict)
    output_registers: dict[str, int] = field(default_factory=dict)

    def format(self, timestamp: bool = True) -> str:
        parts = []
        if timestamp:
            now = datetime.now()
            parts.append(f"[{now:%H:%M:%S} {now.microsecond // 1000:03d}]")
        if self.module_name is not None:
            parts.append(f"[{self.module_name} 0x{self.module_offset:06x}]")
        else:
            parts.append(f"[missing 0x{self.address:x}]")
        parts.append(f"[{self.code.hex()}]")
        text = self.mnemonic + (f" {self.operand}" if self.operand else "")
        line = " ".join(parts) + f' 0x{self.address:x}: "{text}"'
        if self.input_registers:
            line += " " + " ".join(
                f"{name}=0x{value:x}" for name, value in self.input_registers.items()
            )
        if self.output_registers:
            line += " => " + " ".join(
                f"{name}=0x{value:x}" for name, value in self.output_registers.items()
            )
        return line

    def __str__(self) -> str:
        return self.format()
