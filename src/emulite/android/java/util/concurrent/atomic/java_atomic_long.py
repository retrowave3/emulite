"""
https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/atomic/AtomicLong.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.util.concurrent.atomic._java_atomic_number import _JavaAtomicNumber


class JavaAtomicLong(_JavaAtomicNumber):
    JAVA_NAME: ClassVar[str] = "java/util/concurrent/atomic/AtomicLong"
    _BITS: ClassVar[int] = 64  # AtomicLong is a 64-bit int
