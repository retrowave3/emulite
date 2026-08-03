"""
https://docs.oracle.com/javase/8/docs/api/java/lang/Class.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from emulite.android.java.lang.java_object import JavaObject

if TYPE_CHECKING:
    from emulite.android.dalvik_vm import DalvikVM
    from emulite.android_emulator import AndroidEmulatorBase


class JavaClass(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/lang/Class"

    _PRIM_OF: ClassVar[dict[str, str]] = {"V": "void", "Z": "boolean", "B": "byte", "C": "char", "S": "short", "I": "int", "J": "long", "F": "float", "D": "double"}

    def __init__(self, name: str = "java/lang/Object", backing: type | None = None, dvm: DalvikVM | None = None):
        super().__init__()
        self.name = name
        self.backing = backing or JavaObject._REGISTRY.get(name)
        self._super_name: str | None = None
        self._dvm = dvm

    def _resolve(self, name: str, backing: type | None = None) -> JavaClass:
        return self._dvm.class_for(name, backing) if self._dvm is not None else JavaClass(name, backing)

    @staticmethod
    def forName(name: object, *rest: object) -> JavaClass:
        text = name.value if isinstance(name, JavaObject) else str(name)
        return JavaClass(text.replace(".", "/"))

    def getName(self) -> str:
        return self.name.replace("/", ".")

    def getSimpleName(self) -> str:
        if self.isArray():
            component = self.getComponentType()
            return component.getSimpleName() + "[]" if component is not None else self.name
        return self.name.rsplit("/", 1)[-1]

    def getCanonicalName(self) -> str:
        if self.isArray():
            component = self.getComponentType()
            return component.getCanonicalName() + "[]" if component is not None else self.name
        return self.getName()

    def getTypeName(self) -> str:
        return self.getName()

    def toString(self) -> str:
        kind = "interface" if self.isInterface() else "class"
        return f"{kind} {self.getName()}"

    def getSuperclass(self) -> JavaClass | None:
        if self._super_name is not None:
            return self._resolve(self._super_name) if self._super_name else None
        if self.name == "java/lang/Object" or self.isInterface() or self.isPrimitive():
            return None
        if self.backing is not None:
            for base in self.backing.__mro__[1:]:
                if issubclass(base, JavaObject) and "JAVA_NAME" in base.__dict__:
                    return self._resolve(base.JAVA_NAME, base)
        return self._resolve("java/lang/Object")

    def _is_subtype_of(self, ancestor_name: str) -> bool:
        cls: JavaClass | None = self
        for _ in range(64):
            if cls is None:
                return False
            if cls.name == ancestor_name:
                return True
            cls = cls.getSuperclass()
        return False

    def isInstance(self, obj: JavaObject | None) -> bool:
        if not isinstance(obj, JavaObject):
            return False
        if self.backing is not None:
            return isinstance(obj, self.backing)
        return obj.getClass()._is_subtype_of(self.name)

    def isAssignableFrom(self, cls: JavaClass) -> bool:
        if self.backing is not None and cls.backing is not None:
            return issubclass(cls.backing, self.backing)
        return cls._is_subtype_of(self.name) or self.name == "java/lang/Object"

    def isInterface(self) -> bool:
        return False

    def isArray(self) -> bool:
        return self.name.startswith("[")

    def isPrimitive(self) -> bool:
        return self.name in ("void", "boolean", "byte", "char", "short", "int", "long", "float", "double")

    def isEnum(self) -> bool:
        return False

    def getComponentType(self) -> JavaClass | None:
        return JavaClass.class_of_descriptor(self.name[1:]) if self.isArray() else None

    def getModifiers(self) -> int:
        return 0x0001

    def getInterfaces(self) -> list[JavaClass]:
        return []

    def call(self, method: str, signature: str, *args: object) -> object:
        return self._emu().call_static_native(self.name, method, signature, *args)

    def call_instance(self, instance: object, method: str, signature: str, *args: object) -> object:
        return self._emu().call_instance_native(instance, self.name, method, signature, *args)

    def _emu(self) -> AndroidEmulatorBase:
        if self._dvm is None or self._dvm.emu is None:
            raise RuntimeError(f"{self.name} is not bound to an emulator; obtain it via emu.java_class() / find_class()")
        return self._dvm.emu

    @staticmethod
    def split_arg_descriptors(signature: str) -> list[str]:
        inner = signature[signature.index("(") + 1 : signature.index(")")]
        out, i = [], 0
        while i < len(inner):
            start = i
            while inner[i] == "[":
                i += 1
            if inner[i] == "L":
                i = inner.index(";", i) + 1
            else:
                i += 1
            out.append(inner[start:i])
        return out

    @staticmethod
    def class_of_descriptor(descriptor: str) -> JavaClass:
        if descriptor.startswith("["):
            return JavaClass(descriptor)
        if descriptor.startswith("L") and descriptor.endswith(";"):
            return JavaClass(descriptor[1:-1])
        return JavaClass(JavaClass._PRIM_OF.get(descriptor, descriptor))
