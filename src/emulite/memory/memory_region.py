from dataclasses import dataclass

from emulite.cpu.flags.memory_protection_flag import MemoryProtectionFlag


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    """An immutable description of one tracked guest-memory mapping."""

    base: int
    size: int
    perms: MemoryProtectionFlag
    label: str = ""

    def __post_init__(self) -> None:
        if self.base < 0:
            raise ValueError(f"memory region base cannot be negative: {self.base}")
        if self.size <= 0:
            raise ValueError(f"memory region size must be positive: {self.size}")

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, address: int) -> bool:
        return self.base <= address < self.end
