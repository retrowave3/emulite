from __future__ import annotations

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_int


class JavaSupport:
    @staticmethod
    def java_equals(a: object, b: object) -> bool:
        return bool(a.equals(b)) if isinstance(a, JavaObject) else a == b

    @staticmethod
    def java_hash(obj: object) -> int:
        return (obj.hashCode() if isinstance(obj, JavaObject) else hash(obj)) & 0xFFFFFFFF

    @staticmethod
    def display(obj: object) -> str:
        return obj.toString() if isinstance(obj, JavaObject) else ("null" if obj is None else str(obj))

    @staticmethod
    def natural_compare(a: object, b: object) -> int:
        compare = getattr(a, "compareTo", None)
        if callable(compare):
            return as_int(compare(b))
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return (a > b) - (a < b)
        if isinstance(a, str) and isinstance(b, str):
            return (a > b) - (a < b)
        if isinstance(a, bytes) and isinstance(b, bytes):
            return (a > b) - (a < b)
        raise TypeError(f"values of type {type(a).__name__} and {type(b).__name__} are not naturally comparable")
