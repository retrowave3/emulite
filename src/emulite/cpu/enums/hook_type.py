from enum import IntEnum


class HookType(IntEnum):
    INTR = 1  # software interrupt (an ``svc`` trapped)
    CODE = 2  # per-instruction / ranged code hook
    MEM_READ = 3  # a guest load (address + size)
    MEM_WRITE = 4  # a guest store (address + size + value)
    MEM_FAULT = 5  # an access to unmapped memory (callback returns True to recover)
