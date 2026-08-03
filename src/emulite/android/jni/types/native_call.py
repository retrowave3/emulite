from dataclasses import dataclass


@dataclass(slots=True)
class NativeCall:
    """State restored when a JNI-dispatched native method returns."""

    return_type: str
    return_address: int
    stack_pointer: int
    local_refs: set[int]
