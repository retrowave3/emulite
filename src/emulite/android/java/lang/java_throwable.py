"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Throwable.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_text


class JavaThrowable(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/lang/Throwable"

    def __init__(self, message: object = None, cause: JavaThrowable | None = None):
        super().__init__()
        self._message: str | None = as_text(message) if message is not None else None
        self._cause = cause

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaThrowable:
        # (), (String), (String, Throwable), (Throwable). A lone Throwable arg is the cause.
        first = args[0] if args else None
        second = args[1] if len(args) > 1 else None
        if isinstance(first, JavaThrowable) and second is None:
            return cls(None, first)
        return cls(first, second if isinstance(second, JavaThrowable) else None)

    def getMessage(self) -> str | None:
        return self._message

    def getLocalizedMessage(self) -> str | None:
        return self._message

    def getCause(self) -> JavaThrowable | None:
        return self._cause

    def initCause(self, cause: JavaThrowable | None) -> JavaThrowable:
        self._cause = cause
        return self

    def toString(self) -> str:
        # Throwable.toString(): "<class name>" or "<class name>: <message>".
        name = self.getClass().getName()
        return f"{name}: {self._message}" if self._message is not None else name

    def getStackTrace(self) -> list[object]:
        return []  # no frames modelled -> empty StackTraceElement[]

    def fillInStackTrace(self) -> JavaThrowable:
        return self

    def printStackTrace(self, *args: object) -> None:
        return None
