from __future__ import annotations

from emulite.android.java.util._support import JavaSupport


class HashKey:
    __slots__ = ("obj",)

    def __init__(self, obj: object):
        self.obj = obj

    def __hash__(self) -> int:
        return JavaSupport.java_hash(self.obj)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, HashKey) and JavaSupport.java_equals(self.obj, other.obj)
