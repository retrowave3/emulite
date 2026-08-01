from enum import IntFlag


class MemoryProtectionFlag(IntFlag):
    NONE = 0
    READ = 1
    WRITE = 2
    EXEC = 4
    ALL = 7


# Common combinations
RW = MemoryProtectionFlag.READ | MemoryProtectionFlag.WRITE
RX = MemoryProtectionFlag.READ | MemoryProtectionFlag.EXEC
RWX = MemoryProtectionFlag.ALL
