from typing import ClassVar

from emulite.memory.memory_layout import MemoryLayout


class MemoryLayout32(MemoryLayout):
    """Guest address-space constants that differ for a 32-bit process."""

    STACK_TOP: ClassVar[int] = 0xBF000000  # below the conventional 3G/1G split
