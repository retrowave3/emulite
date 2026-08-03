from enum import Enum, auto


class HookType(Enum):
    """Backend event categories understood by the hook bridge."""

    INTR = auto()  # software interrupt (an ``svc`` trapped)
    CODE = auto()  # per-instruction / ranged code hook
    MEM_READ = auto()  # a guest load (address + size)
    MEM_WRITE = auto()  # a guest store (address + size + value)
    MEM_FAULT = auto()  # an access to unmapped memory
