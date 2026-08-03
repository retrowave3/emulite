from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PipeState:
    """Buffer and endpoint counts shared by both ends of a pipe."""

    buffer: bytearray = field(default_factory=bytearray)
    readers: int = 0
    writers: int = 0
