"""
https://docs.oracle.com/javase/8/docs/api/java/util/LinkedHashMap.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.util.java_hash_map import JavaHashMap


class JavaLinkedHashMap(JavaHashMap):
    JAVA_NAME: ClassVar[str] = "java/util/LinkedHashMap"
