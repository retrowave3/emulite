"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Throwable.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject


class JavaThrowable(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/lang/Throwable"

    def __init__(self, message: object = None, cause: "JavaThrowable | None" = None):
        super().__init__()
        self._message = message.value if isinstance(message, JavaObject) else message  # unwrap a jstring
        self._cause = cause

    @classmethod
    def jni_construct(cls, args: list) -> "JavaThrowable":
        # (), (String), (String, Throwable), (Throwable). A lone Throwable arg is the cause.
        first = args[0] if args else None
        second = args[1] if len(args) > 1 else None
        if isinstance(first, JavaThrowable) and second is None:
            return cls(None, first)
        return cls(first, second)

    def getMessage(self) -> "str | None":
        return self._message

    def getLocalizedMessage(self) -> "str | None":
        return self._message

    def getCause(self) -> "JavaThrowable | None":
        return self._cause

    def initCause(self, cause: "JavaThrowable | None") -> "JavaThrowable":
        self._cause = cause
        return self

    def toString(self) -> str:
        # Throwable.toString(): "<class name>" or "<class name>: <message>".
        name = self.getClass().getName()
        return f"{name}: {self._message}" if self._message is not None else name

    def getStackTrace(self) -> list:
        return []  # no frames modelled -> empty StackTraceElement[]

    def fillInStackTrace(self) -> "JavaThrowable":
        return self

    def printStackTrace(self, *args: object) -> None:
        return None
