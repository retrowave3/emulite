"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Short.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang._java_boxed_integer import _JavaBoxedInteger


class JavaShort(_JavaBoxedInteger):
    JAVA_NAME: ClassVar[str] = "java/lang/Short"
    MIN_VALUE: ClassVar[int] = -0x8000
    MAX_VALUE: ClassVar[int] = 0x7FFF
    _BITS: ClassVar[int] = 16

    @staticmethod
    def parseShort(text: object, radix: int = 10) -> int:
        return JavaShort._parse(text, radix)

    def shortValue(self) -> int:
        return int(self.value)  # already narrowed to 16 bits in __init__
