from dataclasses import dataclass


@dataclass(slots=True)
class _GotHook:
    trampoline: int = 0
    after_trampoline: int = 0
