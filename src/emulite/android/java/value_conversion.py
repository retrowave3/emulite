from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from emulite.android.java.lang.java_object import JavaObject


def unwrap(value: object) -> object:
    return value.value if isinstance(value, JavaObject) else value


def as_int(value: object) -> int:
    raw = unwrap(value)
    if isinstance(raw, (int, float, str, bytes, bytearray)):
        return int(raw)
    raise TypeError(f"expected an integer-compatible value, got {type(raw).__name__}")


def as_float(value: object) -> float:
    raw = unwrap(value)
    if isinstance(raw, (int, float, str, bytes, bytearray)):
        return float(raw)
    raise TypeError(f"expected a floating-point-compatible value, got {type(raw).__name__}")


def as_bytes(value: object) -> bytes:
    raw = unwrap(value)
    if raw is None:
        return b""
    if isinstance(raw, str):
        return raw.encode()
    if isinstance(raw, (bytes, bytearray, memoryview, int)):
        return bytes(raw)
    if isinstance(raw, Iterable):
        return bytes(cast(Iterable[int], raw))
    raise TypeError(f"expected a byte sequence, got {type(raw).__name__}")


def as_bytearray(value: object) -> bytearray:
    raw = unwrap(value)
    if isinstance(raw, bytearray):
        return raw
    raise TypeError(f"expected a mutable Java byte array, got {type(raw).__name__}")


def as_text(value: object) -> str:
    raw = unwrap(value)
    return raw if isinstance(raw, str) else str(raw)


def encoded_bytes(value: object) -> bytes:
    get_encoded = getattr(value, "getEncoded", None)
    return as_bytes(get_encoded()) if callable(get_encoded) else as_bytes(value)
