"""
https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/SecretKeySpec.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_bytes, as_int, as_text


class JavaSecretKeySpec(JavaObject):
    JAVA_NAME: ClassVar[str] = "javax/crypto/spec/SecretKeySpec"

    def __init__(self, key: object = b"", algorithm: object = "AES"):
        super().__init__()
        self._key = as_bytes(key)
        self._algorithm = as_text(algorithm)

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaSecretKeySpec:
        # (byte[] key, String algo) or (byte[] key, int offset, int len, String algo)
        if len(args) == 4:
            raw = as_bytes(args[0])[as_int(args[1]) : as_int(args[1]) + as_int(args[2])]
            return cls(raw, args[3])
        return cls(args[0], args[1] if len(args) > 1 else "AES")

    def getEncoded(self) -> JavaObject:
        return JavaObject(JavaClass("[B"), bytearray(self._key))

    def getAlgorithm(self) -> str:
        return self._algorithm

    def getFormat(self) -> str:
        return "RAW"
