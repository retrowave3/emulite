"""
https://docs.oracle.com/javase/8/docs/api/java/util/Objects.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._support import JavaSupport


class JavaObjects(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Objects"

    @staticmethod
    def equals(a: object, b: object) -> bool:
        if a is None or b is None:
            return a is b
        return JavaSupport.java_equals(a, b)

    @staticmethod
    def hashCode(obj: object) -> int:
        return 0 if obj is None else JavaSupport.java_hash(obj)

    @staticmethod
    def toString(obj: object, *default: object) -> str:
        if obj is not None:
            return obj.toString() if isinstance(obj, JavaObject) else str(obj)
        return default[0].value if default and isinstance(default[0], JavaObject) else "null"

    @staticmethod
    def isNull(obj: object) -> bool:
        return obj is None

    @staticmethod
    def nonNull(obj: object) -> bool:
        return obj is not None

    @staticmethod
    def requireNonNull(obj: object, *message: object) -> object:
        if obj is None:
            raise ValueError("java.util.Objects.requireNonNull: null (NullPointerException)")
        return obj
