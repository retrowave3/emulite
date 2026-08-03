"""
https://docs.oracle.com/javase/8/docs/api/java/util/UUID.html
"""

from __future__ import annotations

import hashlib
import os
from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_bytes, as_int, as_text


class JavaUUID(JavaObject[int]):
    JAVA_NAME: ClassVar[str] = "java/util/UUID"

    def __init__(self, value: int = 0):
        super().__init__(value=int(value) & ((1 << 128) - 1))

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaUUID:
        if len(args) >= 2:  # new UUID(long mostSigBits, long leastSigBits)
            return cls((as_int(args[0]) << 64) | (as_int(args[1]) & 0xFFFFFFFFFFFFFFFF))
        return cls()

    @staticmethod
    def randomUUID() -> JavaUUID:
        raw = bytearray(os.urandom(16))
        raw[6] = (raw[6] & 0x0F) | 0x40  # version 4
        raw[8] = (raw[8] & 0x3F) | 0x80  # IETF variant
        return JavaUUID(int.from_bytes(raw, "big"))

    @staticmethod
    def nameUUIDFromBytes(data: object) -> JavaUUID:
        raw = bytearray(hashlib.md5(as_bytes(data)).digest())
        raw[6] = (raw[6] & 0x0F) | 0x30  # version 3 (name-based, MD5)
        raw[8] = (raw[8] & 0x3F) | 0x80
        return JavaUUID(int.from_bytes(raw, "big"))

    @staticmethod
    def fromString(text: object) -> JavaUUID:
        s = as_text(text)
        return JavaUUID(int(s.replace("-", ""), 16))

    def _signed64(self, value: int) -> int:
        value &= 0xFFFFFFFFFFFFFFFF
        return value - 0x10000000000000000 if value >= 0x8000000000000000 else value

    def getMostSignificantBits(self) -> int:
        return self._signed64(int(self.value) >> 64)

    def getLeastSignificantBits(self) -> int:
        return self._signed64(int(self.value))

    def toString(self) -> str:
        h = f"{int(self.value):032x}"
        return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    def equals(self, other: object) -> bool:
        return isinstance(other, JavaUUID) and int(other.value) == int(self.value)

    def hashCode(self) -> int:
        hilo = (int(self.value) >> 64) ^ (int(self.value) & 0xFFFFFFFFFFFFFFFF)
        h = ((hilo >> 32) ^ hilo) & 0xFFFFFFFF  # UUID.hashCode(): (int)(hilo ^ (hilo>>>32))
        return h - 0x100000000 if h >= 0x80000000 else h
