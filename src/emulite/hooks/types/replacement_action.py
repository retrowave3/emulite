from enum import Enum, auto


class ReplacementAction(Enum):
    """Choose whether a replacement hook invokes the original function."""

    CALL_ORIGINAL = auto()
    SKIP_ORIGINAL = auto()
