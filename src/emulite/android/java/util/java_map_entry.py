"""Model of ``java.util.Map.Entry``."""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._support import JavaSupport


class JavaMapEntry(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Map$Entry"

    def __init__(self, key: object = None, value: object = None):
        super().__init__()
        self._key = key
        self._value = value

    def getKey(self) -> object:
        return self._key

    def getValue(self) -> object:
        return self._value

    def setValue(self, value: object) -> object:
        old = self._value
        self._value = value
        return old

    def toString(self) -> str:
        return f"{JavaSupport.display(self._key)}={JavaSupport.display(self._value)}"
