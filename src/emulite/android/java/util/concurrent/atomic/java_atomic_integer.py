"""
https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/atomic/AtomicInteger.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.util.concurrent.atomic._java_atomic_number import _JavaAtomicNumber


class JavaAtomicInteger(_JavaAtomicNumber):
    JAVA_NAME: ClassVar[str] = "java/util/concurrent/atomic/AtomicInteger"
    _BITS: ClassVar[int] = 32  # AtomicInteger is a 32-bit int
