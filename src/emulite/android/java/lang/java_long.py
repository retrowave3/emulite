"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Long.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang._java_boxed_integer import _JavaBoxedInteger


class JavaLong(_JavaBoxedInteger):
    JAVA_NAME: ClassVar[str] = "java/lang/Long"
    MIN_VALUE: ClassVar[int] = -0x8000000000000000
    MAX_VALUE: ClassVar[int] = 0x7FFFFFFFFFFFFFFF
    _BITS: ClassVar[int] = 64

    @staticmethod
    def parseLong(text: object, radix: int = 10) -> int:
        return JavaLong._parse(text, radix)

    def intValue(self) -> int:
        return self._narrow(int(self.value), 32)  # (int) longValue()

    def hashCode(self) -> int:
        value = int(self.value) & 0xFFFFFFFFFFFFFFFF
        return self._narrow(value ^ (value >> 32), 32)  # Long.hashCode(): (int)(v ^ (v >>> 32))
