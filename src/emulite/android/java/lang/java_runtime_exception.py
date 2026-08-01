"""
https://docs.oracle.com/javase/8/docs/api/java/lang/RuntimeException.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_exception import JavaException


class JavaRuntimeException(JavaException):
    JAVA_NAME: ClassVar[str] = "java/lang/RuntimeException"
