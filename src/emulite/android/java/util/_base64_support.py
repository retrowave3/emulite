from __future__ import annotations

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_bytes


def raw_bytes(data: object) -> bytes:
    return as_bytes(data)


def byte_array(data: bytes) -> JavaObject:
    return JavaObject(JavaClass("[B"), bytearray(data))
