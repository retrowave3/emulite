from enum import Enum, auto


class CpuArch(Enum):
    """Instruction-set architecture executed by a CPU backend."""

    ARM = auto()  # 32-bit ARM (AArch32)
    ARM64 = auto()  # 64-bit ARM (AArch64)
