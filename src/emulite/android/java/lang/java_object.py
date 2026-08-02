"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Object.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from emulite.android.java.lang.java_class import JavaClass


class JavaObject:
    JAVA_NAME: ClassVar[str] = "java/lang/Object"

    # JNI name -> modelled Python type, self-populated via __init_subclass__. Lets the base look up
    # JavaClass without importing java_class (which imports us) — breaking the base<->derived cycle.
    _REGISTRY: ClassVar[dict[str, type]] = {"java/lang/Object": None}

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        JavaObject._REGISTRY.setdefault(cls.JAVA_NAME, cls)

    def __init__(self, java_class: "JavaClass | None" = None, value: object = None):
        self.java_class = java_class
        self.value = value  # emulite payload: array bytes, boxed prim, native handle…

    def getClass(self) -> "JavaClass":
        java_class = JavaObject._REGISTRY["java/lang/Class"]
        if type(self) is JavaObject:  # a generic/proxied object reports its stored class
            return self.java_class if self.java_class is not None else java_class("java/lang/Object")
        return java_class(self.JAVA_NAME, backing=type(self))  # a modelled type reports its own class

    def hashCode(self) -> int:
        return id(self) & 0x7FFFFFFF  # identity hash masked to a positive jint

    def equals(self, obj: "JavaObject | None") -> bool:
        return self is obj

    def toString(self) -> str:
        return f"{self.getClass().getName()}@{self.hashCode():x}"

    def clone(self) -> "JavaObject":
        raise NotImplementedError("java.lang.Object.clone: not Cloneable")

    def finalize(self) -> None:
        return None  # no-op; the GC never runs here

    def notify(self) -> None:
        return None  # single-threaded: monitor ops are no-ops

    def notifyAll(self) -> None:
        return None

    def wait(self, timeout: int = 0, nanos: int = 0) -> None:
        return None  # single-threaded: nothing ever notifies us


JavaObject._REGISTRY["java/lang/Object"] = JavaObject  # the root isn't its own subclass, so register it here
