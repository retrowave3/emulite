"""
https://docs.oracle.com/javase/8/docs/api/java/lang/NoClassDefFoundError.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_linkage_error import JavaLinkageError


class JavaNoClassDefFoundError(JavaLinkageError):
    JAVA_NAME: ClassVar[str] = "java/lang/NoClassDefFoundError"
