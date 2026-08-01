"""
https://docs.oracle.com/javase/8/docs/api/java/util/ArrayList.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.util._java_list import _JavaList


class JavaArrayList(_JavaList):
    JAVA_NAME: ClassVar[str] = "java/util/ArrayList"

    def addAll(self, other: object) -> bool:
        self._items.extend(getattr(other, "_items", []))
        return True
