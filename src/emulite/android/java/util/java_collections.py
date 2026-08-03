"""
https://docs.oracle.com/javase/8/docs/api/java/util/Collections.html
"""

from __future__ import annotations

import functools
from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._support import JavaSupport
from emulite.android.java.util.java_array_list import JavaArrayList
from emulite.android.java.util.java_hash_map import JavaHashMap
from emulite.android.java.util.java_hash_set import JavaHashSet
from emulite.android.java.util.java_iterator import JavaIterator


class JavaCollections(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Collections"

    @staticmethod
    def emptyList() -> object:
        return JavaArrayList()

    @staticmethod
    def emptySet() -> object:
        return JavaHashSet()

    @staticmethod
    def emptyMap() -> object:
        return JavaHashMap()

    @staticmethod
    def singletonList(element: object) -> object:
        return JavaArrayList([element])

    @staticmethod
    def singleton(element: object) -> object:
        return JavaHashSet([element])

    @staticmethod
    def singletonMap(key: object, value: object) -> object:
        m = JavaHashMap()
        m.put(key, value)
        return m

    @staticmethod
    def unmodifiableList(collection: object) -> object:
        return collection  # not enforced; returns the same list

    @staticmethod
    def unmodifiableSet(collection: object) -> object:
        return collection

    @staticmethod
    def unmodifiableMap(collection: object) -> object:
        return collection

    @staticmethod
    def unmodifiableCollection(collection: object) -> object:
        return collection

    @staticmethod
    def reverse(collection: object) -> None:
        if hasattr(collection, "_items"):
            collection._items.reverse()

    @staticmethod
    def sort(collection: object, *comparator: object) -> None:
        # A custom Comparator is guest code the pure model can't invoke — sorting by natural order instead
        # would silently return a wrong ordering, so fail loud (route such calls through the handler).
        if comparator and comparator[0] is not None:
            raise NotImplementedError("java.util.Collections.sort: a custom Comparator must be invoked via the JniHandler (the pure model cannot run a guest Comparator)")
        if hasattr(collection, "_items"):
            collection._items.sort(key=functools.cmp_to_key(JavaSupport.natural_compare))

    @staticmethod
    def emptyIterator() -> object:
        return JavaIterator()
