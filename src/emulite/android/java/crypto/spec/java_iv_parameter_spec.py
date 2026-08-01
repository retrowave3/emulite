"""
https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/IvParameterSpec.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaIvParameterSpec(JavaObject):
    JAVA_NAME: ClassVar[str] = "javax/crypto/spec/IvParameterSpec"

    def __init__(self, iv: object = b""):
        super().__init__()
        self._iv = bytes(iv.value) if isinstance(iv, JavaObject) else bytes(iv or b"")

    @classmethod
    def jni_construct(cls, args: list) -> "JavaIvParameterSpec":
        if len(args) == 3:  # (byte[] iv, int offset, int len)
            return cls(bytes(args[0].value)[int(args[1]) : int(args[1]) + int(args[2])])
        return cls(args[0] if args else b"")

    def getIV(self) -> "JavaObject":
        return JavaObject(
            JavaClass("[B"), bytearray(self._iv)
        )  # a copy each call, per Java immutability
