from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Frame:
    index: int  # 0 = the innermost (current PC) frame
    address: int  # the PC / return address of this frame
    description: str  # symbolized location (module+off symbol+off)

    def format(self) -> str:
        return f"#{self.index} {self.address:#x} {self.description}"
