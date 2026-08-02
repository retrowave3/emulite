from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Frame:
    """A symbolized guest stack frame, ordered from innermost to outermost."""

    index: int  # 0 = the innermost (current PC) frame
    address: int  # the PC / return address of this frame
    description: str  # symbolized location (module+off symbol+off)

    def format(self) -> str:
        """Render a compact debugger-style frame line."""
        return f"#{self.index} {self.address:#x} {self.description}"
