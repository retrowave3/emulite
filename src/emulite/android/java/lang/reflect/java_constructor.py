"""
https://docs.oracle.com/javase/8/docs/api/java/lang/reflect/Constructor.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.reflect.java_executable import JavaExecutable


class JavaConstructor(JavaExecutable):
    JAVA_NAME: ClassVar[str] = "java/lang/reflect/Constructor"

    def __init__(self, java_class: JavaClass, signature: str = "()V"):
        super().__init__(java_class, "<init>", signature, is_static=False)

    def getName(self) -> str:
        return self.java_class.getName()  # Constructor.getName() is the declaring class name

    def newInstance(self, *args: object) -> object:
        raise NotImplementedError(f"java.lang.reflect.Constructor.newInstance on {self.java_class.name} — reflective construction must go through the emulator/JniHandler, not the static model")
