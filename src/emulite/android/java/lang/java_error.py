"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Error.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_throwable import JavaThrowable


class JavaError(JavaThrowable):
    JAVA_NAME: ClassVar[str] = "java/lang/Error"
