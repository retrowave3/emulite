"""
https://docs.oracle.com/javase/8/docs/api/java/io/ByteArrayOutputStream.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_bytes, as_int, as_text


class JavaByteArrayOutputStream(JavaObject[bytearray]):
    JAVA_NAME: ClassVar[str] = "java/io/ByteArrayOutputStream"

    def __init__(self, *_size: object):
        super().__init__(value=bytearray())

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaByteArrayOutputStream:
        return cls()  # (int size) is only a capacity hint here

    def write(self, *args: object) -> None:
        if args and isinstance(args[0], int):  # write(int b) -> low 8 bits
            self.value.append(int(args[0]) & 0xFF)
            return
        data = as_bytes(args[0]) if args else b""
        if len(args) == 3:
            off, length = as_int(args[1]), as_int(args[2])
            data = data[off : off + length]
        self.value.extend(data)

    def toByteArray(self) -> JavaObject:
        return JavaObject(JavaClass("[B"), bytearray(self.value))

    def size(self) -> int:
        return len(self.value)

    def reset(self) -> None:
        self.value = bytearray()

    def toString(self, *charset: object) -> str:
        name = as_text(charset[0]) if charset else "utf-8"
        return bytes(self.value).decode(name.lower().replace("utf8", "utf-8"), errors="replace")
