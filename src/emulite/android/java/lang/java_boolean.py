"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Boolean.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject


class JavaBoolean(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/lang/Boolean"

    def __init__(self, value: bool = False):
        super().__init__(value=bool(value))

    @classmethod
    def jni_construct(cls, args: list) -> "JavaBoolean":
        if not args:
            return cls(False)
        arg = args[0]
        if isinstance(arg, JavaObject):  # new Boolean(String) == parseBoolean: equalsIgnoreCase
            return cls(
                str(arg.value).lower() == "true"
            )  # ("true"), NO whitespace trim (" true " -> false)
        return cls(bool(arg))  # new Boolean(boolean)

    def booleanValue(self) -> bool:
        return bool(self.value)

    def toString(self) -> str:
        return "true" if self.value else "false"

    def equals(self, obj: "JavaObject | None") -> bool:
        return isinstance(obj, JavaBoolean) and bool(obj.value) == bool(self.value)

    def hashCode(self) -> int:
        return 1231 if self.value else 1237  # java.lang.Boolean.hashCode()
