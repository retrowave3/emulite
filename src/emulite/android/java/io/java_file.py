"""
https://docs.oracle.com/javase/8/docs/api/java/io/File.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject


class JavaFile(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/io/File"

    def __init__(self, path: object = "", child: object = None):
        base = path.value if isinstance(path, JavaObject) else (path or "")
        if child is not None:  # new File(parent, child)
            name = child.value if isinstance(child, JavaObject) else child
            base = base.rstrip("/") + "/" + str(name).lstrip("/")
        super().__init__(value=base)

    @classmethod
    def jni_construct(cls, args: list) -> "JavaFile":
        return cls(*args[:2]) if args else cls()  # (String) / (String, String) / (File, String)

    def getPath(self) -> str:
        return self.value or ""

    def getAbsolutePath(self) -> str:
        return self.value or ""

    def getCanonicalPath(self) -> str:
        return self.value or ""

    def getName(self) -> str:
        return (self.value or "").rstrip("/").rsplit("/", 1)[-1]

    def getParent(self) -> "str | None":
        trimmed = (self.value or "").rstrip("/")
        return trimmed.rsplit("/", 1)[0] if "/" in trimmed else None

    def getParentFile(self) -> "JavaFile | None":
        parent = self.getParent()
        return JavaFile(parent) if parent is not None else None

    def getAbsoluteFile(self) -> "JavaFile":
        return self

    def isAbsolute(self) -> bool:
        return (self.value or "").startswith("/")

    def toString(self) -> str:
        return self.value or ""
