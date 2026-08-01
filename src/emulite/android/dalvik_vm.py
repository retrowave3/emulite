from __future__ import annotations

import zlib

from emulite.android.art_method_area import ArtMethodArea
from emulite.android.java import models  # noqa: F401 — importing populates JavaObject._REGISTRY
from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_class_loader import JavaClassLoader
from emulite.android.java.lang.reflect.java_field import JavaField
from emulite.android.java.lang.reflect.java_method import JavaMethod
from emulite.common.errors import EmulatorCrashed
from emulite.cpu.flags.memory_protection_flag import MemoryProtectionFlag


class DalvikVM:
    _ACC_PUBLIC, _ACC_STATIC, _ACC_NATIVE = 0x0001, 0x0008, 0x0100

    def __init__(self, emu: object | None = None) -> None:
        self._emu = emu
        self._classes: dict[str, JavaClass] = {}
        self._objects: dict[int, object] = {}
        self._handles: dict[int, int] = {}
        self._local: dict[int, object] = {}
        self._global: dict[int, object] = {}
        self._global_refs: dict[int, int] = {}
        self._weak_global: set[int] = set()
        self._next_ref = 0x100
        self._members: dict[int, JavaMethod | JavaField] = {}
        self._method_index: dict[tuple[str, str, str], int] = {}
        self._field_index: dict[tuple[str, str, str], int] = {}
        self._member_ids: dict[int, int] = {}
        self._next_id = 0x9000_0000
        self._class_loader: JavaClassLoader | None = None
        self._art_area: ArtMethodArea | None = None
        self._art_methods: dict[int, int] = {}

    @property
    def emu(self) -> object:
        return self._emu

    def class_for(self, name: str, backing: type | None = None) -> JavaClass:
        klass = self._classes.get(name)
        if klass is None:
            klass = JavaClass(name, backing, dvm=self)
            self._classes[name] = klass
        return klass

    def find_class(self, name: str) -> JavaClass:
        return self.class_for(name)

    def define_class(self, name: str, superclass: str | None = None) -> JavaClass:
        klass = self.class_for(name)
        if superclass is not None:
            klass._super_name = superclass
        return klass

    def get_all_classes(self) -> list[JavaClass]:
        return list(self._classes.values())

    def is_in_hierarchy(self, base_name: str, derived: JavaClass) -> bool:
        node: JavaClass | None = derived
        while node is not None:
            if node.name == base_name:
                return True
            node = node.getSuperclass()
        return False

    def class_loader(self) -> JavaClassLoader:
        if self._class_loader is None:
            boot = JavaClassLoader(self.find_class, parent=None, name="bootstrap")
            self._class_loader = JavaClassLoader(self.find_class, parent=boot)
        return self._class_loader

    def _handle_for(self, obj: object) -> int:
        if isinstance(obj, JavaClass) and obj._dvm is not self:
            obj = self.class_for(obj.name, obj.backing)
        handle = self._handles.get(id(obj))
        if handle is None:
            handle = self._next_ref
            self._next_ref += 1
            self._handles[id(obj)] = handle
            self._objects[handle] = obj
        return handle

    def add_local(self, obj: object) -> int:
        handle = self._handle_for(obj)
        self._local[handle] = obj
        return handle

    def add_global(self, obj: object) -> int:
        handle = self._handle_for(obj)
        self._global[handle] = obj
        self._global_refs[handle] = self._global_refs.get(handle, 0) + 1
        return handle

    def get(self, ref: int) -> object | None:
        return self._objects.get(ref)

    def _forget(self, ref: int) -> None:
        if ref not in self._local and ref not in self._global and ref not in self._weak_global:
            obj = self._objects.pop(ref, None)
            if obj is not None:
                self._handles.pop(id(obj), None)

    def add_weak_global(self, obj: object) -> int:
        handle = self._handle_for(obj)
        self._weak_global.add(handle)
        return handle

    def delete_weak_global(self, ref: int) -> None:
        self._weak_global.discard(ref)
        self._forget(ref)

    def delete_local(self, ref: int) -> None:
        self._local.pop(ref, None)
        self._forget(ref)

    def local_mark(self) -> set:
        return set(self._local)

    def local_release(self, mark: set) -> None:
        for ref in [r for r in self._local if r not in mark]:
            self.delete_local(ref)

    def delete_global(self, ref: int) -> None:
        count = self._global_refs.get(ref, 0)
        if count > 1:
            self._global_refs[ref] = count - 1
            return
        self._global_refs.pop(ref, None)
        self._global.pop(ref, None)
        self._forget(ref)

    def ref_type(self, ref: int) -> int:
        if ref in self._weak_global:
            return 3
        if ref in self._global:
            return 2
        return 1 if ref in self._local else 0

    def method_id(self, java_class: JavaClass, name: str, signature: str, is_static: bool) -> int:
        key = (java_class.name, name, signature)
        mid = self._method_index.get(key)
        if mid is not None:
            return mid
        mid = self._next_id
        self._next_id += 1
        member = JavaMethod(java_class, name, signature, is_static)
        self._members[mid] = member
        self._method_index[key] = mid
        self._member_ids[id(member)] = mid
        return mid

    def field_id(self, java_class: JavaClass, name: str, signature: str, is_static: bool) -> int:
        key = (java_class.name, name, signature)
        fid = self._field_index.get(key)
        if fid is not None:
            return fid
        fid = self._next_id
        self._next_id += 1
        member = JavaField(java_class, name, signature, is_static)
        self._members[fid] = member
        self._field_index[key] = fid
        self._member_ids[id(member)] = fid
        return fid

    def member(self, member_id: int) -> "JavaMethod | JavaField | None":
        return self._members.get(member_id)

    def id_of(self, member: object) -> int:
        return self._member_ids.get(id(member), 0)

    def set_native(self, java_class: JavaClass, name: str, signature: str, addr: int) -> None:
        method = self._members[self.method_id(java_class, name, signature, False)]
        assert isinstance(method, JavaMethod)
        method.native_addr = addr

    def registered_natives(self) -> list[JavaMethod]:
        return [m for m in self._members.values() if isinstance(m, JavaMethod) and m.native_addr]

    def art_method_ptr(self, method: JavaMethod) -> int:
        cached = self._art_methods.get(id(method))
        if cached is not None:
            return cached
        if self._emu is None:
            raise RuntimeError("art_method_ptr needs an emulator-backed DVM")
        if self._art_area is None:
            self._art_area = ArtMethodArea(self._emu.mem)
        libart = self._executable_addr("libart.so")
        if method.native_addr:
            data = method.native_addr
        elif libart is not None:
            data = libart
        else:
            raise EmulatorCrashed(
                f"ArtMethod.data_ for framework method {method.java_class.name}.{method.name} "
                f"needs libart.so loaded (ART anti-hook introspection)"
            )
        flags = self._ACC_PUBLIC | (self._ACC_STATIC if method.is_static else 0) | self._ACC_NATIVE
        index = len(self._art_methods)
        ptr = self._art_area.create(
            declaring_class=zlib.crc32(method.java_class.name.encode()) | 1,
            access_flags=flags,
            dex_index=index,
            method_index=index,
            data=data,
            entry=libart if libart is not None else data,
        )
        self._art_methods[id(method)] = ptr
        return ptr

    def _executable_addr(self, module_name: str) -> "int | None":
        module = self._emu.get_module(module_name)
        if module is None:
            return None
        for start, _size, perms in module.segments:
            if perms & MemoryProtectionFlag.EXEC:
                return start
        return module.base
