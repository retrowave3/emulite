"""
https://docs.oracle.com/javase/8/docs/api/java/nio/ByteOrder.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject


class JavaByteOrder(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/nio/ByteOrder"

    # Set to singleton instances just below the class body (a class can't reference itself mid-body).
    BIG_ENDIAN: "ClassVar[JavaByteOrder]"
    LITTLE_ENDIAN: "ClassVar[JavaByteOrder]"

    def __init__(self, name: str = "BIG_ENDIAN"):
        super().__init__()
        self._name = name

    @staticmethod
    def nativeOrder() -> "JavaByteOrder":
        return JavaByteOrder.BIG_ENDIAN  # the JVM reports big-endian; matches our default

    def toString(self) -> str:
        return self._name

    def equals(self, other: object) -> bool:
        return isinstance(other, JavaByteOrder) and other._name == self._name


JavaByteOrder.BIG_ENDIAN = JavaByteOrder("BIG_ENDIAN")
JavaByteOrder.LITTLE_ENDIAN = JavaByteOrder("LITTLE_ENDIAN")
