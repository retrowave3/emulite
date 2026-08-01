"""
https://docs.oracle.com/javase/8/docs/api/java/util/LinkedList.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.util._java_list import _JavaList


class JavaLinkedList(_JavaList):
    JAVA_NAME: ClassVar[str] = "java/util/LinkedList"

    def remove(self, *args: object) -> object:
        if not args:  # remove() == removeFirst()
            return self._items.pop(0)
        return super().remove(*args)

    def addFirst(self, element: object) -> None:
        self._items.insert(0, element)
        return None

    def addLast(self, element: object) -> None:
        self._items.append(element)
        return None

    def getFirst(self) -> object:
        return self._items[0]

    def getLast(self) -> object:
        return self._items[-1]

    def removeFirst(self) -> object:
        return self._items.pop(0)

    def removeLast(self) -> object:
        return self._items.pop()

    def peek(self) -> object:
        return self._items[0] if self._items else None

    def peekFirst(self) -> object:
        return self._items[0] if self._items else None

    def peekLast(self) -> object:
        return self._items[-1] if self._items else None

    def poll(self) -> object:
        return self._items.pop(0) if self._items else None

    def offer(self, element: object) -> bool:
        self._items.append(element)
        return True

    def push(self, element: object) -> None:
        self._items.insert(0, element)
        return None

    def pop(self) -> object:
        return self._items.pop(0)
