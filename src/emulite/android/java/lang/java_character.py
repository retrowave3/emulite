"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Character.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_int


class JavaCharacter(JavaObject[int]):
    JAVA_NAME: ClassVar[str] = "java/lang/Character"

    def __init__(self, value: int = 0):
        super().__init__(value=int(value) & 0xFFFF)

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaCharacter:
        return cls(cls._code(args[0])) if args else cls()  # new Character(char)

    @staticmethod
    def _code(value: object) -> int:
        if isinstance(value, JavaObject):
            value = value.value
        if isinstance(value, str):
            return ord(value[:1] or "\0")
        return as_int(value) & 0xFFFF

    @staticmethod
    def valueOf(value: object) -> JavaCharacter:
        return JavaCharacter(JavaCharacter._code(value))

    def charValue(self) -> int:
        return int(self.value)

    def toString(self) -> str:
        return chr(int(self.value))

    def equals(self, obj: object) -> bool:
        return isinstance(obj, JavaCharacter) and int(obj.value) == int(self.value)

    def hashCode(self) -> int:
        return int(self.value)  # Character.hashCode() is the (int) value

    @staticmethod
    def isDigit(code: object) -> bool:
        return chr(JavaCharacter._code(code)).isdigit()

    @staticmethod
    def isLetter(code: object) -> bool:
        return chr(JavaCharacter._code(code)).isalpha()

    @staticmethod
    def isLetterOrDigit(code: object) -> bool:
        return chr(JavaCharacter._code(code)).isalnum()

    @staticmethod
    def isWhitespace(code: object) -> bool:
        return chr(JavaCharacter._code(code)).isspace()

    @staticmethod
    def toUpperCase(code: object) -> int:
        upper = chr(JavaCharacter._code(code)).upper()
        return ord(upper) if len(upper) == 1 else JavaCharacter._code(code)  # char->char, no expansion

    @staticmethod
    def toLowerCase(code: object) -> int:
        lower = chr(JavaCharacter._code(code)).lower()
        return ord(lower) if len(lower) == 1 else JavaCharacter._code(code)
