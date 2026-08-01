"""
https://docs.oracle.com/javase/8/docs/api/java/nio/ByteBuffer.html
"""

from __future__ import annotations

import struct
from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.nio.java_byte_order import JavaByteOrder


class JavaByteBuffer(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/nio/ByteBuffer"

    def __init__(self, backing: "bytearray | None" = None, capacity: int = 0):
        super().__init__()
        self._buf = backing if backing is not None else bytearray(int(capacity))
        self._pos = 0
        self._limit = len(self._buf)
        self._cap = len(self._buf)
        self._order = ">"

    @staticmethod
    def allocate(capacity: int) -> "JavaByteBuffer":
        return JavaByteBuffer(bytearray(int(capacity)))

    @staticmethod
    def allocateDirect(capacity: int) -> "JavaByteBuffer":
        return JavaByteBuffer(bytearray(int(capacity)))

    @staticmethod
    def wrap(array: object, *rest: object) -> "JavaByteBuffer":
        backing = array.value if isinstance(array, JavaObject) else array
        buffer = JavaByteBuffer(backing)
        if len(rest) == 2:
            buffer._pos, buffer._limit = int(rest[0]), int(rest[0]) + int(rest[1])
        return buffer

    def get(self, *args: object) -> object:
        if not args:
            value = self._buf[self._pos]
            self._pos += 1
            return value
        if isinstance(args[0], int):
            return self._buf[int(args[0])]
        dst = args[0].value
        off = int(args[1]) if len(args) >= 3 else 0
        length = int(args[2]) if len(args) >= 3 else len(dst)
        dst[off : off + length] = self._buf[self._pos : self._pos + length]
        self._pos += length
        return self

    def put(self, *args: object) -> "JavaByteBuffer":
        if len(args) == 1 and isinstance(args[0], int):
            self._buf[self._pos] = int(args[0]) & 0xFF
            self._pos += 1
            return self
        if len(args) == 2 and isinstance(args[0], int) and isinstance(args[1], int):
            self._buf[int(args[0])] = int(args[1]) & 0xFF
            return self
        source = args[0]
        if isinstance(source, JavaByteBuffer):
            data = bytes(source._buf[source._pos : source._limit])
            source._pos = source._limit
        else:
            data = bytes(source.value)
        if len(args) >= 3:
            data = data[int(args[1]) : int(args[1]) + int(args[2])]
        self._buf[self._pos : self._pos + len(data)] = data
        self._pos += len(data)
        return self

    def _get_num(self, fmt: str, size: int, args: tuple) -> object:
        if args:
            index = int(args[0])
        else:
            index, self._pos = self._pos, self._pos + size
        return struct.unpack(self._order + fmt, bytes(self._buf[index : index + size]))[0]

    def _put_num(self, fmt: str, size: int, args: tuple) -> "JavaByteBuffer":
        if len(args) == 2:
            index, value = int(args[0]), args[1]
        else:
            index, value = self._pos, args[0]
            self._pos += size
        if fmt in "fd":
            packed = struct.pack(self._order + fmt, value)
        else:
            packed = struct.pack(self._order + fmt.upper(), int(value) & ((1 << (size * 8)) - 1))
        self._buf[index : index + size] = packed
        return self

    def getShort(self, *a):
        return self._get_num("h", 2, a)

    def putShort(self, *a):
        return self._put_num("h", 2, a)

    def getChar(self, *a):
        return self._get_num("H", 2, a)

    def putChar(self, *a):
        return self._put_num("H", 2, a)

    def getInt(self, *a):
        return self._get_num("i", 4, a)

    def putInt(self, *a):
        return self._put_num("i", 4, a)

    def getLong(self, *a):
        return self._get_num("q", 8, a)

    def putLong(self, *a):
        return self._put_num("q", 8, a)

    def getFloat(self, *a):
        return self._get_num("f", 4, a)

    def putFloat(self, *a):
        return self._put_num("f", 4, a)

    def getDouble(self, *a):
        return self._get_num("d", 8, a)

    def putDouble(self, *a):
        return self._put_num("d", 8, a)

    def position(self, *args: object) -> object:
        if args:
            self._pos = int(args[0])
            return self
        return self._pos

    def limit(self, *args: object) -> object:
        if args:
            self._limit = int(args[0])
            return self
        return self._limit

    def capacity(self) -> int:
        return self._cap

    def remaining(self) -> int:
        return self._limit - self._pos

    def hasRemaining(self) -> bool:
        return self._pos < self._limit

    def flip(self) -> "JavaByteBuffer":
        self._limit, self._pos = self._pos, 0
        return self

    def clear(self) -> "JavaByteBuffer":
        self._pos, self._limit = 0, self._cap
        return self

    def rewind(self) -> "JavaByteBuffer":
        self._pos = 0
        return self

    def array(self) -> "JavaObject":
        return JavaObject(JavaClass("[B"), self._buf)

    def order(self, *args: object) -> object:
        if args:
            self._order = "<" if args[0] is JavaByteOrder.LITTLE_ENDIAN else ">"
            return self
        return JavaByteOrder.LITTLE_ENDIAN if self._order == "<" else JavaByteOrder.BIG_ENDIAN
