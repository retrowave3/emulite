"""
https://docs.oracle.com/javase/8/docs/api/java/util/Optional.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._support import JavaSupport


class JavaOptional(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Optional"

    def __init__(self, value: object = None, present: bool = False):
        super().__init__()
        self._value = value
        self._present = present

    @staticmethod
    def of(value: object) -> "JavaOptional":
        if value is None:
            raise ValueError("java.util.Optional.of: null (NullPointerException)")
        return JavaOptional(value, True)

    @staticmethod
    def ofNullable(value: object) -> "JavaOptional":
        return JavaOptional(value, value is not None)

    @staticmethod
    def empty() -> "JavaOptional":
        return JavaOptional(None, False)

    def isPresent(self) -> bool:
        return self._present

    def isEmpty(self) -> bool:
        return not self._present

    def get(self) -> object:
        if not self._present:
            raise ValueError("java.util.Optional.get: empty (NoSuchElementException)")
        return self._value

    def orElse(self, other: object) -> object:
        return self._value if self._present else other

    def equals(self, other: object) -> bool:
        # Java Optional.equals delegates to the contained values' equals(), not Python identity — two
        # Optionals wrapping equal-but-distinct values must compare equal.
        return isinstance(other, JavaOptional) and other._present == self._present and (not self._present or JavaSupport.java_equals(self._value, other._value))

    def toString(self) -> str:
        return f"Optional[{self._value}]" if self._present else "Optional.empty"
