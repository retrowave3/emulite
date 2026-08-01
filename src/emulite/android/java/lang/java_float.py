"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Float.html
"""

from __future__ import annotations

import struct
from typing import ClassVar

from emulite.android.java.lang.java_number import JavaNumber
from emulite.android.java.lang.java_object import JavaObject


class JavaFloat(JavaNumber):
    JAVA_NAME: ClassVar[str] = "java/lang/Float"

    def __init__(self, value: float = 0.0):
        super().__init__(value=self._round(float(value)))

    @staticmethod
    def _round(value: float) -> float:
        return struct.unpack("<f", struct.pack("<f", value))[0]  # coerce to 32-bit float precision

    @staticmethod
    def valueOf(value: object) -> "JavaFloat":
        return JavaFloat(float(value.value) if isinstance(value, JavaObject) else float(value))

    @staticmethod
    def parseFloat(text: object) -> float:
        raw = text.value if isinstance(text, JavaObject) else text
        return JavaFloat._round(float(str(raw)))

    @staticmethod
    def _bits(value: float) -> int:
        # Float.floatToIntBits: every NaN collapses to the canonical 0x7fc00000.
        if value != value:
            return 0x7FC00000
        return struct.unpack("<I", struct.pack("<f", value))[0]

    def floatValue(self) -> float:
        return float(self.value)

    def doubleValue(self) -> float:
        return float(self.value)

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
        text = repr(float(value))
        return text if ("." in text or "e" in text or "E" in text) else text + ".0"

    def equals(self, obj: "JavaObject | None") -> bool:
        return isinstance(obj, JavaFloat) and self._bits(self.value) == self._bits(obj.value)

    def hashCode(self) -> int:
        return self._narrow(self._bits(self.value), 32)  # Float.hashCode() == floatToIntBits(value)
