"""
https://docs.oracle.com/javase/8/docs/api/java/io/ByteArrayOutputStream.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaByteArrayOutputStream(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/io/ByteArrayOutputStream"

    def __init__(self, *_size: object):
        super().__init__(value=bytearray())

    @classmethod
    def jni_construct(cls, args: list) -> "JavaByteArrayOutputStream":
        return cls()  # (int size) is only a capacity hint here

    def write(self, *args: object) -> None:
        if args and isinstance(args[0], int):  # write(int b) -> low 8 bits
            self.value.append(int(args[0]) & 0xFF)
            return None
        data = (
            args[0].value if args and isinstance(args[0], JavaObject) else b""
        )  # write(byte[][, off, len])
        if len(args) == 3:
            off, length = int(args[1]), int(args[2])
            data = bytes(data)[off : off + length]
        self.value.extend(bytes(data))
        return None

    def toByteArray(self) -> "JavaObject":
        return JavaObject(JavaClass("[B"), bytearray(self.value))

    def size(self) -> int:
        return len(self.value)

    def reset(self) -> None:
        self.value = bytearray()
        return None

    def toString(self, *charset: object) -> str:
        name = charset[0].value if charset and isinstance(charset[0], JavaObject) else "utf-8"
        return bytes(self.value).decode(name.lower().replace("utf8", "utf-8"), errors="replace")
