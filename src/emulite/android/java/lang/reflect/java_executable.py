"""
https://docs.oracle.com/javase/8/docs/api/java/lang/reflect/Executable.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.reflect.java_accessible_object import JavaAccessibleObject
from emulite.android.java.lang.reflect.modifier import Modifier


class JavaExecutable(JavaAccessibleObject):
    JAVA_NAME: ClassVar[str] = "java/lang/reflect/Executable"

    def __init__(self, java_class: "JavaClass", name: str, signature: str, is_static: bool):
        super().__init__()
        self.java_class = java_class  # the declaring class
        self.name = name  # the method/constructor name
        self.signature = signature  # JNI signature "(args)ret"
        self.is_static = is_static

    def getName(self) -> str:
        return self.name

    def getDeclaringClass(self) -> "JavaClass":
        return self.java_class

    def getModifiers(self) -> int:
        return Modifier.PUBLIC | (Modifier.STATIC if self.is_static else 0)

    def getParameterTypes(self) -> list["JavaClass"]:
        return [JavaClass.class_of_descriptor(d) for d in JavaClass.split_arg_descriptors(self.signature)]

    def getParameterCount(self) -> int:
        return len(JavaClass.split_arg_descriptors(self.signature))
