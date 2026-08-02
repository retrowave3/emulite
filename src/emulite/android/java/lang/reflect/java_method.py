"""
https://docs.oracle.com/javase/8/docs/api/java/lang/reflect/Method.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.lang.reflect.java_executable import JavaExecutable


class JavaMethod(JavaExecutable):
    JAVA_NAME: ClassVar[str] = "java/lang/reflect/Method"

    def __init__(self, java_class: "JavaClass", name: str, signature: str, is_static: bool, native_addr: int = 0):
        super().__init__(java_class, name, signature, is_static)
        self.native_addr = native_addr

    def getReturnType(self) -> "JavaClass":
        return JavaClass.class_of_descriptor(self.signature[self.signature.index(")") + 1 :])

    def invoke(self, obj: "JavaObject | None", *args: object) -> object:
        raise NotImplementedError("Method.invoke: reflective call — drive it via emu.call_native")
