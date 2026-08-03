from __future__ import annotations

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.lang.reflect.java_field import JavaField
from emulite.android.java.lang.reflect.java_method import JavaMethod
from emulite.android.jni.types.jni_value import JniValue


class JniHandler:
    """Application-defined behavior for Java methods and fields reached through JNI."""

    def accept_class(self, name: str) -> bool:
        return True

    def accept_method(self, dvm_class: JavaClass, name: str, signature: str, is_static: bool) -> bool:
        return True

    def accept_field(self, dvm_class: JavaClass, name: str, signature: str, is_static: bool) -> bool:
        return True

    def new_object(self, dvm_class: JavaClass, method: JavaMethod, args: list[object]) -> JniValue:
        return JavaObject(dvm_class)

    def call_method(self, obj: object, method: JavaMethod, args: list[object]) -> JniValue:
        raise NotImplementedError(f"call {method.getDeclaringClass().name}.{method.name}{method.signature} — override JniHandler")

    def call_static_method(self, method: JavaMethod, args: list[object]) -> JniValue:
        raise NotImplementedError(f"call static {method.getDeclaringClass().name}.{method.name}{method.signature} — override JniHandler")

    def get_field(self, obj: object, field: JavaField) -> JniValue:
        raise NotImplementedError(f"get field {field.getDeclaringClass().name}.{field.name} — override JniHandler")

    def get_static_field(self, field: JavaField) -> JniValue:
        raise NotImplementedError(f"get static field {field.getDeclaringClass().name}.{field.name} — override JniHandler")

    def set_field(self, obj: object, field: JavaField, value: object) -> None:
        raise NotImplementedError(f"set field {field.getDeclaringClass().name}.{field.name} — override JniHandler")

    def set_static_field(self, field: JavaField, value: object) -> None:
        raise NotImplementedError(f"set static field {field.getDeclaringClass().name}.{field.name} — override JniHandler")
