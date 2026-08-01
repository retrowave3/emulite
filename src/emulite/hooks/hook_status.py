from enum import Enum


class HookStatus(Enum):
    CALL_ORIGINAL = True
    SKIP_ORIGINAL = False

    @property
    def call_original(self) -> bool:
        return self.value
