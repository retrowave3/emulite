"""
https://docs.oracle.com/javase/8/docs/api/java/util/HashMap.html
https://docs.oracle.com/javase/8/docs/api/java/util/Map.Entry.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._support import JavaSupport
from emulite.android.java.util.hash_key import HashKey
from emulite.android.java.util.java_array_list import JavaArrayList
from emulite.android.java.util.java_hash_set import JavaHashSet
from emulite.android.java.util.java_map_entry import JavaMapEntry


class JavaHashMap(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/HashMap"

    def __init__(self) -> None:
        super().__init__()
        self._data: dict[HashKey, list[object]] = {}

    @classmethod
    def jni_construct(cls, args: list[object]) -> JavaHashMap:
        # new HashMap() / (int capacity[, float loadFactor]) / (Map). A capacity int -> empty; Map -> copy.
        instance = cls()
        if args and hasattr(args[0], "_data"):
            for entry in args[0]._data.values():
                if isinstance(entry, list):  # source is a Map: values are [key, value]
                    instance.put(entry[0], entry[1])
        return instance

    def put(self, key: object, value: object) -> object:
        previous = self._data.get(HashKey(key))
        self._data[HashKey(key)] = [key, value]
        return previous[1] if previous is not None else None

    def putIfAbsent(self, key: object, value: object) -> object:
        existing = self._data.get(HashKey(key))
        if existing is not None:
            return existing[1]
        self._data[HashKey(key)] = [key, value]
        return None

    def get(self, key: object) -> object:
        entry = self._data.get(HashKey(key))
        return entry[1] if entry is not None else None

    def getOrDefault(self, key: object, default: object) -> object:
        entry = self._data.get(HashKey(key))
        return entry[1] if entry is not None else default

    def containsKey(self, key: object) -> bool:
        return HashKey(key) in self._data

    def containsValue(self, value: object) -> bool:
        return any(JavaSupport.java_equals(v, value) for _, v in self._data.values())

    def remove(self, key: object) -> object:
        entry = self._data.pop(HashKey(key), None)
        return entry[1] if entry is not None else None

    def size(self) -> int:
        return len(self._data)

    def isEmpty(self) -> bool:
        return not self._data

    def clear(self) -> None:
        self._data = {}

    def keySet(self) -> object:
        return JavaHashSet(k for k, _ in self._data.values())

    def values(self) -> object:
        return JavaArrayList([v for _, v in self._data.values()])

    def entrySet(self) -> object:
        return JavaHashSet(JavaMapEntry(k, v) for k, v in self._data.values())

    def toString(self) -> str:
        return "{" + ", ".join(f"{JavaSupport.display(k)}={JavaSupport.display(v)}" for k, v in self._data.values()) + "}"
