from __future__ import annotations

from emulite.android.java.lang.java_object import JavaObject


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
        if isinstance(a, JavaObject):
            return int(a.compareTo(b))
        return (a > b) - (a < b)


class HashKey:
    __slots__ = ("obj",)

    def __init__(self, obj: object):
        self.obj = obj

    def __hash__(self) -> int:
        return JavaSupport.java_hash(self.obj)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, HashKey) and JavaSupport.java_equals(self.obj, other.obj)
