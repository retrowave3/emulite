from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_number import JavaNumber
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.value_conversion import as_int


class _JavaBoxedInteger(JavaNumber[int]):
    # Shared surface of the immutable integer box types (Integer/Long/Short/Byte). A subclass sets its
    # two's-complement width _BITS (and MIN_VALUE/MAX_VALUE); only genuinely type-specific overrides — Long's
    # narrowing intValue + xor-fold hashCode — stay on the subclass. Mirrors _JavaAtomicNumber's _BITS pattern.
    _BITS: ClassVar[int]

    def __init__(self, value: int = 0):
        super().__init__(value=self._narrow(int(value), self._BITS))

    @classmethod
    def valueOf(cls, value: object) -> _JavaBoxedInteger:
        # X.valueOf(int) and X.valueOf(String) — a jstring arg arrives as a JavaObject.
        return cls(as_int(value))

    @classmethod
    def _parse(cls, text: object, radix: int = 10) -> int:
        # The shared body of parseInt/parseLong/parseShort/parseByte (the distinct names stay per subclass,
        # since JNI resolves them by name).
        raw = text.value if isinstance(text, JavaObject) else text
        return cls._narrow(int(str(raw), radix), cls._BITS)

    def toString(self) -> str:
        return str(int(self.value))

    def equals(self, obj: object) -> bool:
        return isinstance(obj, type(self)) and int(obj.value) == int(self.value)

    def hashCode(self) -> int:
        return int(self.value)  # Integer/Short/Byte hashCode is the (int) value; Long overrides
