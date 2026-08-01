"""
https://docs.oracle.com/javase/8/docs/api/java/lang/System.html
"""

from __future__ import annotations

import time
from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject


class JavaSystem(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/lang/System"

    _ELEM_BYTES: ClassVar[dict] = {"Z": 1, "B": 1, "C": 2, "S": 2, "I": 4, "J": 8, "F": 4, "D": 8}

    @staticmethod
    def _elem_size(array: object) -> int:
        name = array.java_class.name if isinstance(array, JavaObject) and array.java_class else "[B"
        return JavaSystem._ELEM_BYTES.get(name[1:2], 1)

    @staticmethod
    def arraycopy(src: object, src_pos: int, dest: object, dest_pos: int, length: int) -> None:
        sp, dp, n = int(src_pos), int(dest_pos), int(length)
        sv, dv = src.value, dest.value
        if isinstance(sv, list) and isinstance(dv, list):
            dv[dp : dp + n] = sv[sp : sp + n]
        else:  # primitive arrays: copy raw little-endian bytes
            es = JavaSystem._elem_size(dest)
            dv[dp * es : (dp + n) * es] = bytes(sv[sp * es : (sp + n) * es])
        return None

    @staticmethod
    def currentTimeMillis() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def nanoTime() -> int:
        return time.perf_counter_ns()

    @staticmethod
    def identityHashCode(obj: object) -> int:
        return (
            0 if obj is None else id(obj) & 0x7FFFFFFF
        )  # the identity hash, ignoring any override

    @staticmethod
    def lineSeparator() -> str:
        return "\n"

    @staticmethod
    def gc() -> None:
        return None  # no managed heap to collect
