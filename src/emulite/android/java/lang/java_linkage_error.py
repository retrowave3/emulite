"""
https://docs.oracle.com/javase/8/docs/api/java/lang/LinkageError.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_error import JavaError


class JavaLinkageError(JavaError):
    JAVA_NAME: ClassVar[str] = "java/lang/LinkageError"
