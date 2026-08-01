"""
https://docs.oracle.com/javase/8/docs/api/java/lang/reflect/Field.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.lang.reflect.java_accessible_object import JavaAccessibleObject
from emulite.android.java.lang.reflect.modifier import Modifier


class JavaField(JavaAccessibleObject):
    JAVA_NAME: ClassVar[str] = "java/lang/reflect/Field"

    def __init__(self, java_class: "JavaClass", name: str, signature: str, is_static: bool):
        super().__init__()
        self.java_class = java_class  # the declaring class (jfieldID's class)
        self.name = name  # the field's own name
        self.signature = signature  # JNI type descriptor of the field
        self.is_static = is_static

    def getName(self) -> str:
        return self.name

    def getType(self) -> "JavaClass":
        return JavaClass.class_of_descriptor(self.signature)

    def getDeclaringClass(self) -> "JavaClass":
        return self.java_class

    def getModifiers(self) -> int:
        return Modifier.PUBLIC | (Modifier.STATIC if self.is_static else 0)

    def get(self, obj: "JavaObject | None") -> object:
        raise NotImplementedError("Field.get: reflective access — use JNI Get<T>Field")

    def set(self, obj: "JavaObject | None", value: object) -> None:
        raise NotImplementedError("Field.set: reflective access — use JNI Set<T>Field")
