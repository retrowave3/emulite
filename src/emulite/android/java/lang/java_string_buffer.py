"""
https://docs.oracle.com/javase/8/docs/api/java/lang/StringBuffer.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_string_builder import JavaStringBuilder


class JavaStringBuffer(JavaStringBuilder):
    JAVA_NAME: ClassVar[str] = "java/lang/StringBuffer"
