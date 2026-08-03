"""
https://docs.oracle.com/javase/8/docs/api/java/io/ByteArrayInputStream.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_bytearray, as_bytes, as_int


class JavaByteArrayInputStream(JavaObject[bytes]):
    JAVA_NAME: ClassVar[str] = "java/io/ByteArrayInputStream"

    def __init__(self, buffer: object = b""):
        super().__init__(value=as_bytes(buffer))
        self._pos = 0

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaByteArrayInputStream:
        return cls(args[0]) if args else cls()  # new ByteArrayInputStream(byte[])

    def read(self, *args: object) -> int:
        if not args:  # read() -> next byte, or -1 at EOF
            if self._pos >= len(self.value):
                return -1
            byte = self.value[self._pos]
            self._pos += 1
            return byte
        target = as_bytearray(args[0])
        off = as_int(args[1]) if len(args) >= 3 else 0
        length = as_int(args[2]) if len(args) >= 3 else len(target)
        remaining = len(self.value) - self._pos
        if remaining <= 0:
            return -1
        count = min(length, remaining)
        target[off : off + count] = self.value[self._pos : self._pos + count]
        self._pos += count
        return count

    def available(self) -> int:
        return len(self.value) - self._pos

    def skip(self, n: int) -> int:
        step = max(0, min(int(n), len(self.value) - self._pos))
        self._pos += step
        return step

    def reset(self) -> None:
        self._pos = 0
