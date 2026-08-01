from dataclasses import dataclass

from emulite.cpu.flags.memory_protection_flag import MemoryProtectionFlag


@dataclass
class MemoryRegion:
    base: int
    size: int
    perms: MemoryProtectionFlag
    label: str = ""

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, address: int) -> bool:
        return self.base <= address < self.end
