"""
https://docs.oracle.com/javase/8/docs/api/java/lang/StringBuilder.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.jvalue import JChar
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.lang.java_string import JavaString
from emulite.android.java.value_conversion import as_int


class JavaStringBuilder(JavaObject[str]):
    JAVA_NAME: ClassVar[str] = "java/lang/StringBuilder"

    def __init__(self, initial: object = ""):
        text = initial.value if isinstance(initial, JavaObject) else (initial if isinstance(initial, str) else "")
        super().__init__(value=text)

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaStringBuilder:
        # new StringBuilder() / (int capacity) / (String) / (CharSequence). A capacity int -> empty.
        return cls(args[0]) if args and isinstance(args[0], JavaObject) else cls()

    def _s(self) -> str:
        return self.value or ""

    @staticmethod
    def _render(value: object) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, JChar):
            return chr(int(value))
        if isinstance(value, JavaObject):
            return value.toString()
        return str(value)

    def append(self, value: object) -> JavaStringBuilder:
        self.value = self._s() + self._render(value)
        return self

    def insert(self, offset: int, value: object) -> JavaStringBuilder:
        s = self._s()
        self.value = s[: int(offset)] + self._render(value) + s[int(offset) :]
        return self

    def replace(self, start: int, end: int, text: object) -> JavaStringBuilder:
        s = self._s()
        self.value = s[: int(start)] + self._render(text) + s[int(end) :]
        return self

    def delete(self, start: int, end: int) -> JavaStringBuilder:
        s = self._s()
        self.value = s[: int(start)] + s[int(end) :]
        return self

    def deleteCharAt(self, index: int) -> JavaStringBuilder:
        s = self._s()
        self.value = s[: int(index)] + s[int(index) + 1 :]
        return self

    def reverse(self) -> JavaStringBuilder:
        self.value = self._s()[::-1]
        return self

    def setCharAt(self, index: int, ch: object) -> None:
        s = self._s()
        self.value = s[: int(index)] + chr(as_int(ch)) + s[int(index) + 1 :]

    def setLength(self, length: int) -> None:
        s, n = self._s(), int(length)
        self.value = s[:n] if n <= len(s) else s + "\0" * (n - len(s))

    def charAt(self, index: int) -> int:
        return ord(self._s()[int(index)])

    def length(self) -> int:
        return len(self._s())

    def capacity(self) -> int:
        return max(len(self._s()), 16)  # our buffer has no fixed capacity; report a plausible one

    def indexOf(self, target: object, from_index: int = 0) -> int:
        return self._s().find(target.value if isinstance(target, JavaObject) else str(target), int(from_index))

    def substring(self, start: int, end: int | None = None) -> JavaString:
        s = self._s()
        return JavaString(s[int(start) :] if end is None else s[int(start) : int(end)])

    def toString(self) -> str:
        return self._s()
