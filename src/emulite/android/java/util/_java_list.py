from __future__ import annotations

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._support import JavaSupport
from emulite.android.java.util.java_iterator import JavaIterator


class _JavaList(JavaObject):
    # Shared List surface of ArrayList/LinkedList (both are just a Python list in the pure model).

    def __init__(self, elements: object = None):
        super().__init__()
        self._items: list = list(elements) if elements else []

    @classmethod
    def jni_construct(cls, args: list) -> "_JavaList":
        # new List() / (int capacity) / (Collection). A capacity int -> empty; a collection -> copy.
        if args and hasattr(args[0], "_items"):
            return cls(list(args[0]._items))
        if args and hasattr(args[0], "_data"):
            return cls(list(args[0]._data.values()))
        return cls()

    def add(self, *args: object) -> object:
        if len(args) == 2 and isinstance(args[0], int):  # add(int index, E element) -> void
            self._items.insert(args[0], args[1])
            return None
        self._items.append(args[0] if args else None)  # add(E) -> boolean
        return True

    def get(self, index: int) -> object:
        return self._items[int(index)]

    def set(self, index: int, element: object) -> object:
        old = self._items[int(index)]
        self._items[int(index)] = element
        return old

    def remove(self, *args: object) -> object:
        if args and isinstance(args[0], int):  # remove(int index) -> E
            return self._items.pop(args[0])
        target = args[0] if args else None  # remove(Object) -> boolean
        for i, item in enumerate(self._items):
            if JavaSupport.java_equals(item, target):
                del self._items[i]
                return True
        return False

    def indexOf(self, obj: object) -> int:
        for i, item in enumerate(self._items):
            if JavaSupport.java_equals(item, obj):
                return i
        return -1

    def contains(self, obj: object) -> bool:
        return self.indexOf(obj) >= 0

    def size(self) -> int:
        return len(self._items)

    def isEmpty(self) -> bool:
        return not self._items

    def clear(self) -> None:
        self._items = []
        return None

    def iterator(self) -> object:
        return JavaIterator(self._items)

    def toArray(self, *_ignore: object) -> object:
        return JavaObject(JavaClass("[Ljava/lang/Object;"), list(self._items))

    def toString(self) -> str:
        return "[" + ", ".join(JavaSupport.display(x) for x in self._items) + "]"
