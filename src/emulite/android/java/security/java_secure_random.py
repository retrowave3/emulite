"""
https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html
"""

from __future__ import annotations

import os
import secrets
from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_bytearray, as_int


class JavaSecureRandom(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/security/SecureRandom"

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaSecureRandom:
        return cls()  # new SecureRandom() / (byte[] seed) — seed ignored

    @staticmethod
    def getInstance(algorithm: object, *provider: object) -> JavaSecureRandom:
        return JavaSecureRandom()

    def nextBytes(self, array: object) -> None:
        buffer = as_bytearray(array)
        buffer[:] = os.urandom(len(buffer))

    def nextInt(self, *bound: object) -> int:
        if bound:
            return secrets.randbelow(as_int(bound[0]))
        value = int.from_bytes(os.urandom(4), "big")
        return value - 0x100000000 if value >= 0x80000000 else value

    def nextLong(self) -> int:
        value = int.from_bytes(os.urandom(8), "big")
        return value - 0x10000000000000000 if value >= 0x8000000000000000 else value

    def nextBoolean(self) -> bool:
        return bool(os.urandom(1)[0] & 1)

    def nextFloat(self) -> float:
        return int.from_bytes(os.urandom(3), "big") / float(1 << 24)  # 24 bits of mantissa, [0,1)

    def nextDouble(self) -> float:
        return int.from_bytes(os.urandom(7), "big") / float(1 << 53)  # 53 bits of mantissa, [0,1)

    def setSeed(self, seed: object) -> None:
        return None  # os.urandom needs no seeding

    @staticmethod
    def getSeed(count: int) -> JavaObject:
        return JavaObject(JavaClass("[B"), bytearray(os.urandom(int(count))))
