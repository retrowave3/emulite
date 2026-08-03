"""
https://docs.oracle.com/javase/8/docs/api/java/util/HashSet.html
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._support import JavaSupport
from emulite.android.java.util.hash_key import HashKey
from emulite.android.java.util.java_iterator import JavaIterator


class JavaHashSet(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/HashSet"

    def __init__(self, elements: Iterable[object] | None = None):
        super().__init__()
        self._data: dict[HashKey, object] = {}
        for element in elements or ():
            self._data[HashKey(element)] = element

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaHashSet:
        if args and hasattr(args[0], "_data"):  # new HashSet(Collection) -> copy
            return cls(list(args[0]._data.values()))
        if args and hasattr(args[0], "_items"):
            return cls(list(args[0]._items))
        return cls()

    def add(self, element: object) -> bool:
        key = HashKey(element)
        if key in self._data:
            return False
        self._data[key] = element
        return True

    def addAll(self, other: object) -> bool:
        # Sets/Maps store elements in _data; Lists (ArrayList/LinkedList) store them in _items — accept
        # both, mirroring jni_construct (a plain _data-only read silently no-ops on a List argument).
        source = other._items if hasattr(other, "_items") else getattr(other, "_data", {}).values()
        changed = False
        for element in source:
            changed = self.add(element) or changed
        return changed

    def contains(self, element: object) -> bool:
        return HashKey(element) in self._data

    def remove(self, element: object) -> bool:
        return self._data.pop(HashKey(element), None) is not None

    def size(self) -> int:
        return len(self._data)

    def isEmpty(self) -> bool:
        return not self._data

    def clear(self) -> None:
        self._data = {}

    def iterator(self) -> JavaIterator:
        return JavaIterator(list(self._data.values()))

    def toArray(self, *_ignore: object) -> JavaObject:
        return JavaObject(JavaClass("[Ljava/lang/Object;"), list(self._data.values()))

    def toString(self) -> str:
        return "[" + ", ".join(JavaSupport.display(x) for x in self._data.values()) + "]"
