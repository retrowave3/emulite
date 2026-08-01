"""
https://docs.oracle.com/javase/8/docs/api/java/util/Iterator.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject


class JavaIterator(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Iterator"

    def __init__(self, items: object = None):
        super().__init__()
        self._items = list(items) if items else []
        self._index = 0

    def hasNext(self) -> bool:
        return self._index < len(self._items)

    def next(self) -> object:
        if self._index >= len(self._items):
            raise IndexError("java.util.Iterator.next: no more elements (NoSuchElementException)")
        item = self._items[self._index]
        self._index += 1
        return item
