"""
https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/IvParameterSpec.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_bytes, as_int


class JavaIvParameterSpec(JavaObject):
    JAVA_NAME: ClassVar[str] = "javax/crypto/spec/IvParameterSpec"

    def __init__(self, iv: object = b""):
        super().__init__()
        self._iv = as_bytes(iv)

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaIvParameterSpec:
        if len(args) == 3:  # (byte[] iv, int offset, int len)
            return cls(as_bytes(args[0])[as_int(args[1]) : as_int(args[1]) + as_int(args[2])])
        return cls(args[0] if args else b"")

    def getIV(self) -> JavaObject:
        return JavaObject(JavaClass("[B"), bytearray(self._iv))  # a copy each call, per Java immutability
