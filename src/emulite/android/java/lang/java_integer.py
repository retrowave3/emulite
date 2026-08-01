"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Integer.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang._java_boxed_integer import _JavaBoxedInteger


class JavaInteger(_JavaBoxedInteger):
    JAVA_NAME: ClassVar[str] = "java/lang/Integer"
    MIN_VALUE: ClassVar[int] = -0x80000000
    MAX_VALUE: ClassVar[int] = 0x7FFFFFFF
    _BITS: ClassVar[int] = 32

    @staticmethod
    def parseInt(text: object, radix: int = 10) -> int:
        return JavaInteger._parse(text, radix)
