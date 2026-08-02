from enum import Enum


class HookStatus(Enum):
    """Choose whether a symbol or address replacement invokes its original body."""

    CALL_ORIGINAL = True
    SKIP_ORIGINAL = False

    @property
    def call_original(self) -> bool:
        return self.value
