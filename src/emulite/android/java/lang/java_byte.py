"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Byte.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang._java_boxed_integer import _JavaBoxedInteger


class JavaByte(_JavaBoxedInteger):
    JAVA_NAME: ClassVar[str] = "java/lang/Byte"
    MIN_VALUE: ClassVar[int] = -0x80
    MAX_VALUE: ClassVar[int] = 0x7F
    _BITS: ClassVar[int] = 8

    @staticmethod
    def parseByte(text: object, radix: int = 10) -> int:
        return JavaByte._parse(text, radix)

    def byteValue(self) -> int:
        return int(self.value)  # already narrowed to 8 bits in __init__
