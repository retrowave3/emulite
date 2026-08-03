from typing import NamedTuple

from emulite.cpu import MemoryProtectionFlag


class ModuleSegment(NamedTuple):
    """A mapped memory range belonging to a native module."""

    start: int
    size: int
    permissions: MemoryProtectionFlag
