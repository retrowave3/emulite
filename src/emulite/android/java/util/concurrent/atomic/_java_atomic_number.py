from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_number import JavaNumber


class _JavaAtomicNumber(JavaNumber):
    # Shared surface of AtomicInteger/AtomicLong; the subclass sets _BITS (its two's-complement width).
    _BITS: ClassVar[int]

    @classmethod
    def _wrap(cls, value: int) -> int:
        return JavaNumber._narrow(int(value), cls._BITS)

    def __init__(self, initial: int = 0):
        super().__init__(value=self._wrap(initial))

    @classmethod
    def jni_construct(cls, args: list) -> "_JavaAtomicNumber":
        return cls(int(args[0]) if args else 0)

    def get(self) -> int:
        return int(self.value)

    def set(self, new_value: int) -> None:
        self.value = self._wrap(new_value)
        return None

    def getAndSet(self, new_value: int) -> int:
        old, self.value = int(self.value), self._wrap(new_value)
        return old

    def incrementAndGet(self) -> int:
        self.value = self._wrap(int(self.value) + 1)
        return int(self.value)

    def getAndIncrement(self) -> int:
        old, self.value = int(self.value), self._wrap(int(self.value) + 1)
        return old

    def decrementAndGet(self) -> int:
        self.value = self._wrap(int(self.value) - 1)
        return int(self.value)

    def getAndDecrement(self) -> int:
        old, self.value = int(self.value), self._wrap(int(self.value) - 1)
        return old

    def addAndGet(self, delta: int) -> int:
        self.value = self._wrap(int(self.value) + int(delta))
        return int(self.value)

    def getAndAdd(self, delta: int) -> int:
        old, self.value = int(self.value), self._wrap(int(self.value) + int(delta))
        return old

    def compareAndSet(self, expect: int, update: int) -> bool:
        if int(self.value) == int(expect):
            self.value = self._wrap(update)
            return True
        return False

    def toString(self) -> str:
        return str(int(self.value))
