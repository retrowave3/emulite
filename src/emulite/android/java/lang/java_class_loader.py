"""
https://docs.oracle.com/javase/8/docs/api/java/lang/ClassLoader.html
"""

from __future__ import annotations

from typing import Callable, ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaClassLoader(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/lang/ClassLoader"

    def __init__(
        self,
        resolver: "Callable[[str], JavaClass]",
        parent: "JavaClassLoader | None" = None,
        name: str = "dalvik.system.PathClassLoader",
    ):
        super().__init__()
        self._resolve = resolver  # bound DalvikVM.find_class: JNI name (slashes) -> JavaClass
        self._parent = parent  # delegation parent, for a faithful getParent()
        self._name = name

    def loadClass(self, name: object, resolve: bool = True) -> "JavaClass":
        return self._resolve(self._jni_name(name))

    def findClass(self, name: object) -> "JavaClass":
        return self._resolve(self._jni_name(name))

    @staticmethod
    def _jni_name(name: object) -> str:
        text = name.value if isinstance(name, JavaObject) else name  # unwrap a jstring arg
        return (text or "").replace(".", "/")

    def getParent(self) -> "JavaClassLoader | None":
        return self._parent

    def getName(self) -> str:
        return self._name

    def toString(self) -> str:
        return self._name

    def defineClass(self, *args: object, **kwargs: object) -> "JavaClass":
        raise NotImplementedError(
            "java.lang.ClassLoader.defineClass: emulite cannot load classes from bytecode"
        )

    def getResource(self, name: object) -> object:
        raise NotImplementedError(
            "java.lang.ClassLoader.getResource: emulite models no resource filesystem"
        )

    def getResourceAsStream(self, name: object) -> object:
        raise NotImplementedError(
            "java.lang.ClassLoader.getResourceAsStream: emulite models no resource filesystem"
        )
