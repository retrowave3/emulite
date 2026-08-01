"""
https://docs.oracle.com/javase/8/docs/api/java/security/MessageDigest.html
"""

from __future__ import annotations

import hashlib
from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaMessageDigest(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/security/MessageDigest"

    def __init__(self, algorithm: str = "SHA-256"):
        super().__init__()
        self._algorithm = algorithm
        self._digest = hashlib.new(algorithm.lower().replace("-", ""))

    @staticmethod
    def getInstance(algorithm: object, *provider: object) -> "JavaMessageDigest":
        name = algorithm.value if isinstance(algorithm, JavaObject) else str(algorithm)
        return JavaMessageDigest(name)

    def update(self, *args: object) -> None:
        first = args[0] if args else None
        if isinstance(first, int):  # update(byte)
            self._digest.update(bytes([int(first) & 0xFF]))
        elif len(args) == 3:  # update(byte[], offset, len)
            self._digest.update(self._raw_bytes(first, int(args[1]), int(args[2])))
        else:  # update(byte[])
            self._digest.update(self._raw_bytes(first))
        return None

    def digest(self, *data: object) -> JavaObject:
        if data:  # digest(byte[]) == update then digest
            self._digest.update(self._raw_bytes(data[0]))
        out = self._digest.digest()
        self._digest = hashlib.new(
            self._algorithm.lower().replace("-", "")
        )  # digest() resets the engine
        return JavaObject(JavaClass("[B"), bytearray(out))

    def reset(self) -> None:
        self._digest = hashlib.new(self._algorithm.lower().replace("-", ""))
        return None

    def getAlgorithm(self) -> str:
        return self._algorithm

    def getDigestLength(self) -> int:
        return self._digest.digest_size

    @staticmethod
    def isEqual(a: object, b: object) -> bool:
        return JavaMessageDigest._raw_bytes(a) == JavaMessageDigest._raw_bytes(b)

    @staticmethod
    def _raw_bytes(data: object, off: int = 0, length: "int | None" = None) -> bytes:
        if isinstance(data, JavaObject):
            data = data.value
        raw = bytes(data or b"")
        return raw[off : off + length] if length is not None else raw
