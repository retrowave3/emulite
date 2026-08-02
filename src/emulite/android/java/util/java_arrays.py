"""
https://docs.oracle.com/javase/8/docs/api/java/util/Arrays.html
"""

from __future__ import annotations

import functools
import struct
from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_number import JavaNumber
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._support import JavaSupport
from emulite.android.java.util.java_array_list import JavaArrayList


class JavaArrays(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Arrays"

    _CODEC: ClassVar[dict] = {"Z": "<B", "B": "<b", "C": "<H", "S": "<h", "I": "<i", "J": "<q", "F": "<f", "D": "<d"}

    @staticmethod
    def _letter(array: object) -> str:
        name = array.java_class.name if isinstance(array, JavaObject) and array.java_class else "[B"
        return name[1:2]

    @staticmethod
    def _elements(array: object) -> list:
        if not isinstance(array, JavaObject):
            return []
        data = array.value
        if isinstance(data, list):
            return list(data)
        fmt = JavaArrays._CODEC.get(JavaArrays._letter(array))
        if fmt is None or not isinstance(data, (bytes, bytearray)):
            return list(data or [])
        size = struct.calcsize(fmt)
        return [struct.unpack(fmt, bytes(data[i : i + size]))[0] for i in range(0, len(data), size)]

    @staticmethod
    def toString(array: object) -> str:
        if array is None:
            return "null"
        elements = JavaArrays._elements(array)
        if JavaArrays._letter(array) == "Z":
            return "[" + ", ".join("true" if e else "false" for e in elements) + "]"
        return "[" + ", ".join(JavaSupport.display(e) for e in elements) + "]"

    @staticmethod
    def equals(a: object, b: object) -> bool:
        if a is None or b is None:
            return a is b
        va, vb = a.value, b.value
        if isinstance(va, (bytes, bytearray)) and isinstance(vb, (bytes, bytearray)):
            return bytes(va) == bytes(vb)
        ea, eb = JavaArrays._elements(a), JavaArrays._elements(b)
        return len(ea) == len(eb) and all(JavaSupport.java_equals(x, y) for x, y in zip(ea, eb))

    @staticmethod
    def hashCode(array: object) -> int:
        if array is None:
            return 0
        letter = JavaArrays._letter(array)
        result = 1
        for element in JavaArrays._elements(array):
            # java.util.Arrays.hashCode applies a PER-TYPE element hash before folding: long uses the
            # (int)(v^(v>>>32)) fold, double/float use their bit patterns, boolean uses 1231/1237.
            if element is None:
                h = 0
            elif isinstance(element, JavaObject):
                h = element.hashCode()
            elif letter == "Z":  # boolean
                h = 1231 if element else 1237
            elif letter == "J":  # long
                v = int(element) & 0xFFFFFFFFFFFFFFFF
                h = JavaNumber._narrow(v ^ (v >> 32), 32)
            elif letter == "D":  # double
                bits = struct.unpack("<q", struct.pack("<d", float(element)))[0] & 0xFFFFFFFFFFFFFFFF
                h = JavaNumber._narrow(bits ^ (bits >> 32), 32)
            elif letter == "F":  # float
                h = struct.unpack("<i", struct.pack("<f", float(element)))[0]
            else:  # byte/short/char/int
                h = int(element)
            result = JavaNumber._narrow(31 * result + h, 32)
        return result

    @staticmethod
    def asList(array: object) -> object:
        return JavaArrayList(JavaArrays._elements(array))

    @staticmethod
    def fill(array: object, value: object) -> None:
        if isinstance(array.value, list):
            array.value = [value] * len(array.value)
        return None

    @staticmethod
    def copyOf(array: object, new_length: int) -> object:
        n, data = int(new_length), array.value
        if isinstance(data, list):
            copied = (data + [None] * n)[:n]
        else:
            size = struct.calcsize(JavaArrays._CODEC.get(JavaArrays._letter(array), "<b"))
            copied = bytearray(bytes(data)[: n * size].ljust(n * size, b"\0"))
        return JavaObject(JavaClass(array.java_class.name if array.java_class else "[B"), copied)

    @staticmethod
    def copyOfRange(array: object, from_index: int, to_index: int) -> object:
        start, end = int(from_index), int(to_index)
        n, data = end - start, array.value
        if isinstance(data, list):
            copied = (data[start:end] + [None] * n)[:n]
        else:
            size = struct.calcsize(JavaArrays._CODEC.get(JavaArrays._letter(array), "<b"))
            copied = bytearray(bytes(data)[start * size : end * size].ljust(n * size, b"\0"))
        return JavaObject(JavaClass(array.java_class.name if array.java_class else "[B"), copied)

    @staticmethod
    def sort(array: object, *comparator: object) -> None:
        # A custom Comparator is guest code the pure model can't invoke — natural-order sorting would be
        # a silently-wrong result, so fail loud (route through the handler).
        if comparator and comparator[0] is not None:
            raise NotImplementedError("java.util.Arrays.sort: a custom Comparator must be invoked via the JniHandler")
        elements = sorted(JavaArrays._elements(array), key=functools.cmp_to_key(JavaSupport.natural_compare))
        if isinstance(array.value, list):
            array.value = elements
        else:  # primitive array: re-pack to little-endian bytes
            fmt = JavaArrays._CODEC.get(JavaArrays._letter(array), "<b")
            array.value = bytearray(b"".join(struct.pack(fmt, int(e)) for e in elements))
        return None

    @staticmethod
    def binarySearch(array: object, key: object) -> int:
        elements = JavaArrays._elements(array)
        low, high = 0, len(elements) - 1
        while low <= high:
            mid = (low + high) // 2
            order = JavaSupport.natural_compare(elements[mid], key)
            if order < 0:
                low = mid + 1
            elif order > 0:
                high = mid - 1
            else:
                return mid
        return -(low + 1)  # JDK: -(insertion point) - 1 when not found
