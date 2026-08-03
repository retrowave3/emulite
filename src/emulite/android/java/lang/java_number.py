"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Number.html
"""

from __future__ import annotations

import math
from typing import ClassVar, Generic, TypeVar

from emulite.android.java.lang.java_object import JavaObject

NumberValue = TypeVar("NumberValue", int, float)


class JavaNumber(JavaObject[NumberValue], Generic[NumberValue]):
    JAVA_NAME: ClassVar[str] = "java/lang/Number"

    @classmethod
    def valueOf(cls, value: object) -> JavaNumber[NumberValue]:
        raise NotImplementedError

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaNumber[NumberValue]:
        # new Integer(int)/new Integer(String)/... — each subclass's valueOf accepts both forms.
        return cls.valueOf(args[0]) if args else cls()

    @staticmethod
    def _narrow(value: int, bits: int) -> int:
        value &= (1 << bits) - 1
        return value - (1 << bits) if value >> (bits - 1) else value

    @staticmethod
    def _d2i(value: float) -> int:
        if math.isnan(value):
            return 0
        if value >= 0x7FFFFFFF:
            return 0x7FFFFFFF
        if value <= -0x80000000:
            return -0x80000000
        return int(value)

    @staticmethod
    def _d2l(value: float) -> int:
        if math.isnan(value):
            return 0
        if value >= 0x7FFFFFFFFFFFFFFF:
            return 0x7FFFFFFFFFFFFFFF
        if value <= -0x8000000000000000:
            return -0x8000000000000000
        return int(value)

    def intValue(self) -> int:
        return int(self.value)

    def longValue(self) -> int:
        return int(self.value)

    def floatValue(self) -> float:
        return float(self.value)

    def doubleValue(self) -> float:
        return float(self.value)

    def byteValue(self) -> int:
        return self._narrow(self.intValue(), 8)  # (byte) intValue()

    def shortValue(self) -> int:
        return self._narrow(self.intValue(), 16)  # (short) intValue()
