"""
https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html
"""

from __future__ import annotations

import math
from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaBigInteger(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/math/BigInteger"

    def __init__(self, value: object = 0, radix: int = 10):
        if isinstance(value, JavaObject):
            payload = value.value
            if isinstance(payload, (bytes, bytearray)):
                value = int.from_bytes(bytes(payload), "big", signed=True)
            else:
                value = int(str(payload), int(radix))
        elif isinstance(value, str):
            value = int(value, int(radix))
        super().__init__(value=int(value))

    @classmethod
    def jni_construct(cls, args: list) -> "JavaBigInteger":
        return cls(*args[:2]) if args else cls()

    @staticmethod
    def valueOf(value: object) -> "JavaBigInteger":
        return JavaBigInteger(int(value.value) if isinstance(value, JavaObject) else int(value))

    @staticmethod
    def _v(other: object) -> int:
        return int(other.value) if isinstance(other, JavaObject) else int(other)

    def add(self, other: object) -> "JavaBigInteger":
        return JavaBigInteger(int(self.value) + self._v(other))

    def subtract(self, other: object) -> "JavaBigInteger":
        return JavaBigInteger(int(self.value) - self._v(other))

    def multiply(self, other: object) -> "JavaBigInteger":
        return JavaBigInteger(int(self.value) * self._v(other))

    def divide(self, other: object) -> "JavaBigInteger":
        a, b = int(self.value), self._v(other)
        q = abs(a) // abs(b)  # Java integer division truncates toward zero
        return JavaBigInteger(q if (a < 0) == (b < 0) else -q)

    def mod(self, other: object) -> "JavaBigInteger":
        return JavaBigInteger(int(self.value) % self._v(other))  # BigInteger.mod result is non-negative

    def remainder(self, other: object) -> "JavaBigInteger":
        a, b = int(self.value), self._v(other)
        r = abs(a) % abs(b)  # remainder has the sign of the dividend
        return JavaBigInteger(r if a >= 0 else -r)

    def pow(self, exponent: int) -> "JavaBigInteger":
        return JavaBigInteger(int(self.value) ** int(exponent))

    def modPow(self, exponent: object, modulus: object) -> "JavaBigInteger":
        return JavaBigInteger(pow(int(self.value), self._v(exponent), self._v(modulus)))

    def modInverse(self, modulus: object) -> "JavaBigInteger":
        return JavaBigInteger(pow(int(self.value), -1, self._v(modulus)))

    def gcd(self, other: object) -> "JavaBigInteger":
        return JavaBigInteger(math.gcd(int(self.value), self._v(other)))

    def negate(self) -> "JavaBigInteger":
        return JavaBigInteger(-int(self.value))

    def abs(self) -> "JavaBigInteger":
        return JavaBigInteger(abs(int(self.value)))

    def shiftLeft(self, n: int) -> "JavaBigInteger":
        return JavaBigInteger(int(self.value) << int(n))

    def shiftRight(self, n: int) -> "JavaBigInteger":
        return JavaBigInteger(int(self.value) >> int(n))

    # (Bitwise and/or/not/xor are omitted: their Java names are Python keywords and so are unreachable
    #  by name-based dispatch; add via setattr if a target ever needs them.)

    def signum(self) -> int:
        return (int(self.value) > 0) - (int(self.value) < 0)

    def bitLength(self) -> int:
        v = int(self.value)
        return (v if v >= 0 else -v - 1).bit_length()  # Java: length of the minimal two's-complement

    def compareTo(self, other: object) -> int:
        a, b = int(self.value), self._v(other)
        return (a > b) - (a < b)

    def equals(self, other: object) -> bool:
        return isinstance(other, JavaBigInteger) and int(other.value) == int(self.value)

    def hashCode(self) -> int:
        h = int(self.value) & 0xFFFFFFFF
        return h - 0x100000000 if h >= 0x80000000 else h

    def intValue(self) -> int:
        v = int(self.value) & 0xFFFFFFFF
        return v - 0x100000000 if v >= 0x80000000 else v

    def longValue(self) -> int:
        v = int(self.value) & 0xFFFFFFFFFFFFFFFF
        return v - 0x10000000000000000 if v >= 0x8000000000000000 else v

    def toString(self, radix: int = 10) -> str:
        if int(radix) == 10:
            return str(int(self.value))
        value, digits = int(self.value), "0123456789abcdefghijklmnopqrstuvwxyz"
        if value == 0:
            return "0"
        sign, n, out = ("-" if value < 0 else ""), abs(value), ""
        while n:
            out = digits[n % int(radix)] + out
            n //= int(radix)
        return sign + out

    def toByteArray(self) -> "JavaObject":
        v = int(self.value)
        length = max(1, (v.bit_length() // 8) + 1)  # minimal signed big-endian length
        return JavaObject(JavaClass("[B"), bytearray(v.to_bytes(length, "big", signed=True)))
