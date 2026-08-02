"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Double.html
"""

from __future__ import annotations

import struct
from typing import ClassVar

from emulite.android.java.lang.java_number import JavaNumber
from emulite.android.java.lang.java_object import JavaObject


class JavaDouble(JavaNumber):
    JAVA_NAME: ClassVar[str] = "java/lang/Double"

    def __init__(self, value: float = 0.0):
        super().__init__(value=float(value))

    @staticmethod
    def valueOf(value: object) -> "JavaDouble":
        return JavaDouble(float(value.value) if isinstance(value, JavaObject) else float(value))

    @staticmethod
    def parseDouble(text: object) -> float:
        raw = text.value if isinstance(text, JavaObject) else text
        return float(str(raw))

    @staticmethod
    def _bits(value: float) -> int:
        # Double.doubleToLongBits: every NaN collapses to the canonical 0x7ff8000000000000.
        if value != value:
            return 0x7FF8000000000000
        return struct.unpack("<Q", struct.pack("<d", value))[0]

    def doubleValue(self) -> float:
        return float(self.value)

    def floatValue(self) -> float:
        return struct.unpack("<f", struct.pack("<f", self.value))[0]

    def intValue(self) -> int:
        return self._d2i(self.value)

    def longValue(self) -> int:
        return self._d2l(self.value)

    def isNaN(self) -> bool:
        return self.value != self.value

    def isInfinite(self) -> bool:
        return self.value in (float("inf"), float("-inf"))

    def toString(self) -> str:
        value = self.value
        if value != value:
            return "NaN"
        if value == float("inf"):
            return "Infinity"
        if value == float("-inf"):
            return "-Infinity"
        # Shortest round-trip like Java (via Python's repr); exponent-notation threshold can differ.
        text = repr(float(value))
        return text if ("." in text or "e" in text or "E" in text) else text + ".0"

    def equals(self, obj: "JavaObject | None") -> bool:
        return isinstance(obj, JavaDouble) and self._bits(self.value) == self._bits(obj.value)

    def hashCode(self) -> int:
        bits = self._bits(self.value)
        return self._narrow(bits ^ (bits >> 32), 32)  # Double.hashCode(): (int)(bits ^ (bits >>> 32))
