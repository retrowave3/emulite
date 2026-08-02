from typing import Protocol


class RegisterNamespace(Protocol):
    """Architecture-independent register groups consumed by shared subsystems."""

    ARG_REGS: list[int]
    CPSR: int
    LR: int
    PC: int
    RET_REG: int
    SP: int
    SYSCALL_ARG_REGS: list[int]
    SYSCALL_NR: int
