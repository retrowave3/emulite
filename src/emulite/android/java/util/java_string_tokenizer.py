"""
https://docs.oracle.com/javase/8/docs/api/java/util/StringTokenizer.html
"""

from __future__ import annotations

import re
from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject


class JavaStringTokenizer(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/StringTokenizer"

    def __init__(
        self, text: object = "", delimiters: object = " \t\n\r\f", _return_delims: object = False
    ):
        super().__init__()
        source = text.value if isinstance(text, JavaObject) else (text or "")
        delims = delimiters.value if isinstance(delimiters, JavaObject) else delimiters
        self._tokens = [t for t in re.split("[" + re.escape(delims) + "]", source) if t]
        self._index = 0

    @classmethod
    def jni_construct(cls, args: list) -> "JavaStringTokenizer":
        return cls(*args[:3])

    def hasMoreTokens(self) -> bool:
        return self._index < len(self._tokens)

    def nextToken(self, *_delims: object) -> str:
        if self._index >= len(self._tokens):
            raise IndexError(
                "java.util.StringTokenizer.nextToken: no more tokens (NoSuchElementException)"
            )
        token = self._tokens[self._index]
        self._index += 1
        return token

    def countTokens(self) -> int:
        return len(self._tokens) - self._index

    def hasMoreElements(self) -> bool:
        return self.hasMoreTokens()

    def nextElement(self) -> str:
        return self.nextToken()
