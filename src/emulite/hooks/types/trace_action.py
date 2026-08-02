from enum import Enum, auto


class TraceAction(Enum):
    """Control whether an instruction or call tracer should keep emitting events."""

    CONTINUE = auto()
    STOP_TRACING = auto()
