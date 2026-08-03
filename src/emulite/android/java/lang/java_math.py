"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Math.html
"""

from __future__ import annotations

import math
from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject


class JavaMath(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/lang/Math"

    @staticmethod
    def abs(value: float) -> float:
        return abs(value)

    @staticmethod
    def min(a: float, b: float) -> float:
        return min(a, b)

    @staticmethod
    def max(a: float, b: float) -> float:
        return max(a, b)

    @staticmethod
    def floor(value: float) -> float:
        return float(math.floor(value))

    @staticmethod
    def ceil(value: float) -> float:
        return float(math.ceil(value))

    @staticmethod
    def round(value: float) -> int:
        # Java Math.round == round half toward +infinity. Computing floor(a + 0.5) is WRONG for
        # 0.49999999999999994 (a + 0.5 rounds up to 1.0), so decide on the fractional part instead:
        # round up only when it is truly >= 0.5. NaN -> 0.
        if math.isnan(value):
            return 0
        floor = math.floor(value)
        return int(floor + 1 if value - floor >= 0.5 else floor)

    @staticmethod
    def rint(value: float) -> float:
        return float(round(value))  # round-half-to-even, per Math.rint

    @staticmethod
    def sqrt(value: float) -> float:
        return math.sqrt(value)

    @staticmethod
    def cbrt(value: float) -> float:
        return math.copysign(abs(value) ** (1.0 / 3.0), value)

    @staticmethod
    def pow(base: float, exponent: float) -> float:
        return math.pow(base, exponent)

    @staticmethod
    def exp(value: float) -> float:
        return math.exp(value)

    @staticmethod
    def log(value: float) -> float:
        return math.log(value)

    @staticmethod
    def log10(value: float) -> float:
        return math.log10(value)

    @staticmethod
    def sin(value: float) -> float:
        return math.sin(value)

    @staticmethod
    def cos(value: float) -> float:
        return math.cos(value)

    @staticmethod
    def tan(value: float) -> float:
        return math.tan(value)

    @staticmethod
    def hypot(x: float, y: float) -> float:
        return math.hypot(x, y)

    @staticmethod
    def signum(value: float) -> float:
        return math.copysign(1.0, value) if value else 0.0

    @staticmethod
    def toRadians(degrees: float) -> float:
        return math.radians(degrees)

    @staticmethod
    def toDegrees(radians: float) -> float:
        return math.degrees(radians)

    @staticmethod
    def floorDiv(x: int, y: int) -> int:
        return int(x) // int(y)

    @staticmethod
    def floorMod(x: int, y: int) -> int:
        return int(x) % int(y)
