"""
https://docs.oracle.com/javase/8/docs/api/java/lang/reflect/AccessibleObject.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaAccessibleObject(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/lang/reflect/AccessibleObject"

    def __init__(self):
        super().__init__()
        self._accessible = False  # the `accessible` flag toggled by setAccessible

    def setAccessible(self, flag: bool) -> None:
        self._accessible = flag

    def isAccessible(self) -> bool:
        return self._accessible

    def getAnnotation(self, annotationClass: "JavaClass") -> "JavaObject | None":
        return None

    def isAnnotationPresent(self, annotationClass: "JavaClass") -> bool:
        return False

    def getAnnotations(self) -> list["JavaObject"]:
        return []

    def getAnnotationsByType(self, annotationClass: "JavaClass") -> list["JavaObject"]:
        return []

    def getDeclaredAnnotation(self, annotationClass: "JavaClass") -> "JavaObject | None":
        return None

    def getDeclaredAnnotations(self) -> list["JavaObject"]:
        return []

    def getDeclaredAnnotationsByType(self, annotationClass: "JavaClass") -> list["JavaObject"]:
        return []
