from __future__ import annotations

import inspect
import struct
from collections.abc import Callable
from typing import TYPE_CHECKING, ClassVar, cast

from emulite.android.cformat import RegisterArgs32, VaListArgs, VaListArgs32, VarArgs
from emulite.android.dalvik_vm import DalvikVM
from emulite.android.java.jvalue import JChar
from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_no_class_def_found_error import JavaNoClassDefFoundError
from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.lang.java_string import JavaString
from emulite.android.java.lang.java_throwable import JavaThrowable
from emulite.android.java.lang.reflect.java_field import JavaField
from emulite.android.java.lang.reflect.java_method import JavaMethod
from emulite.android.jni.enums.jni_function import JNIFunction
from emulite.android.jni.enums.jni_return_code import JNIReturnCode
from emulite.android.jni.enums.jni_version import JNIVersion
from emulite.android.jni.mutf8 import Mutf8
from emulite.android.jni.types.native_call import NativeCall
from emulite.common.errors import EmulatorCrashed, JavaException
from emulite.cpu.backend import CpuArch
from emulite.cpu.registers.arm32_reg import Arm32Reg
from emulite.cpu.registers.arm64_reg import Arm64Reg
from emulite.memory import RW, MemoryLayout

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase
    from emulite.android_emulator32 import AndroidEmulator32


class JNIEnv:
    """Guest JNI function table and Java/native value bridge."""

    _ELEM_SIZE: ClassVar[dict[str, int]] = {"Z": 1, "B": 1, "C": 2, "S": 2, "I": 4, "J": 8, "F": 4, "D": 8}
    _PRIM_ARRAY_NAME: ClassVar[dict[str, str]] = {"Z": "Boolean", "B": "Byte", "C": "Char", "S": "Short", "I": "Int", "J": "Long", "F": "Float", "D": "Double"}
    _MISS = object()

    @staticmethod
    def parse_arg_types(signature: str) -> list[str]:
        return ["L" if d[0] in "[L" else d for d in JavaClass.split_arg_descriptors(signature)]

    @staticmethod
    def _build_table(emu: AndroidEmulatorBase, base: int, handlers: dict[int, Callable[[], int | None]], label: str) -> None:
        mem = emu.mem
        pointer_size = emu.arch.pointer_size
        write_ptr = mem.write_u64 if pointer_size == 8 else mem.write_u32
        mem.map(base, MemoryLayout.PAGE_SIZE, RW, label)
        functions = base + 0x10
        write_ptr(base, functions)
        for index in range(max(handlers) + 1):
            handler = handlers.get(index)
            if handler is None:
                write_ptr(functions + index * pointer_size, 0)
                continue
            slot = emu.trap.alloc_slot(handler, f"{label}:{handler.__name__}")
            write_ptr(functions + index * pointer_size, slot)

    def __init__(self, emu: AndroidEmulatorBase, version: JNIVersion = JNIVersion.JNI_VERSION_1_6):
        self.emu = emu
        self.handler = emu.jni_handler
        self.log = emu.log
        self.version = version
        self.dvm = DalvikVM(emu)
        self._array_ptrs: dict[int, int] = {}
        self._string_ptrs: set[int] = set()
        self._local_frames: list[set[int]] = []
        self._pending_exception: object | None = None
        self._native_return_slot = 0  # one-shot trampoline a redirected native returns through
        self._native_calls: list[NativeCall] = []
        self.pointer = MemoryLayout.JNIENV_BASE
        self._build_table(emu, self.pointer, self._handlers(), "JNIEnv")

    def _arg(self, index: int) -> int:
        return self.emu.arg(index)

    def _cstr(self, ptr: int) -> str:
        return self.emu.mem.read_cstr(ptr) if ptr else ""

    def _str(self, ref: int) -> str:
        obj = self.dvm.get(ref)
        return obj.value if isinstance(obj, JavaObject) and isinstance(obj.value, str) else ""

    def _array(self, ref: int) -> JavaObject | None:
        obj = self.dvm.get(ref)
        return obj if isinstance(obj, JavaObject) and obj.value is not None else None

    def _method_id(self, static: bool) -> int:
        cls, name, sig = (self.dvm.get(self._arg(1)), self._cstr(self._arg(2)), self._cstr(self._arg(3)))
        if not isinstance(cls, JavaClass) or not self.handler.accept_method(cls, name, sig, static):
            return 0
        mid = self.dvm.method_id(cls, name, sig, static)
        self.log.jni_call(f"Get{'Static' if static else ''}MethodID", f"{cls.name}.{name}{sig}", mid)
        return mid

    def _field_id(self, static: bool) -> int:
        cls, name, sig = (self.dvm.get(self._arg(1)), self._cstr(self._arg(2)), self._cstr(self._arg(3)))
        if not isinstance(cls, JavaClass) or not self.handler.accept_field(cls, name, sig, static):
            return 0
        fid = self.dvm.field_id(cls, name, sig, static)
        self.log.jni_call(f"Get{'Static' if static else ''}FieldID", f"{cls.name}.{name}:{sig}", fid)
        return fid

    def _as_double(self, bits: int) -> float:
        return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]

    def _as_real(self, letter: str, bits: int) -> float:
        if letter == "F":
            return struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]
        return self._as_double(bits)

    def _convert(self, letter: str, raw: int) -> object:
        if letter == "L":
            return self.dvm.get(raw)
        if letter == "Z":
            return bool(raw & 1)
        if letter == "C":
            return JChar(raw & 0xFFFF)
        return raw & 0xFFFFFFFFFFFFFFFF

    def _box(self, letter: str, result: object) -> int | None:
        if letter == "V":
            return None
        if letter == "Z":
            return 1 if result else 0
        if letter in "BCSIJ":
            if result is None:
                return 0
            if not isinstance(result, (bool, int, float)):
                raise TypeError(f"JNI {letter} return requires a number, got {type(result).__name__}")
            return int(result) & 0xFFFFFFFFFFFFFFFF
        if letter in "FD":
            if result is not None and not isinstance(result, (bool, int, float)):
                raise TypeError(f"JNI {letter} return requires a number, got {type(result).__name__}")
            value = float(result or 0.0)
            if self.emu.arch.cpu_arch is CpuArch.ARM:
                if letter == "D":
                    bits = struct.unpack("<Q", struct.pack("<d", value))[0]
                    self.emu.backend.reg_write(Arm32Reg.R[0], bits & 0xFFFFFFFF)
                    self.emu.backend.reg_write(Arm32Reg.R[1], bits >> 32)
                else:
                    self.emu.backend.reg_write(Arm32Reg.R[0], struct.unpack("<I", struct.pack("<f", value))[0])
                return None
            packed = struct.pack("<d", value) if letter == "D" else struct.pack("<f", value)
            self.emu.backend.reg_write(Arm64Reg.Q[0], int.from_bytes(packed, "little"))
            return None
        if isinstance(result, str):
            return self.dvm.add_local(JavaString(result))
        if isinstance(result, (JavaObject, JavaClass)):
            return self.dvm.add_local(result)
        if isinstance(result, list):  # model returned a Java array (e.g. getStackTrace())
            return self.dvm.add_local(JavaObject(JavaClass("[Ljava/lang/Object;"), result))
        if result is None:
            return 0
        if isinstance(result, (bool, int, float)):
            return int(result) & 0xFFFFFFFFFFFFFFFF
        raise TypeError(f"unsupported JNI return value: {type(result).__name__}")

    def _read_call_args(self, arg_types: list[str], mode: str, first_arg: int) -> list[object]:
        if mode == "A":
            return self._read_jvalues(arg_types, self._arg(first_arg))
        if mode == "V":
            return self._read_valist(arg_types, self._arg(first_arg))
        return self._read_registers(arg_types, first_arg)

    def _read_registers(self, arg_types: list[str], gp_start: int) -> list[object]:
        if self.emu.arch.cpu_arch is CpuArch.ARM:
            return self._read_from_varargs(RegisterArgs32(cast("AndroidEmulator32", self.emu), gp_start), arg_types)
        gp, fp = gp_start, 0
        out: list[object] = []
        for letter in arg_types:
            if letter in "FD":
                out.append(self._as_double(self.emu.backend.reg_read(Arm64Reg.Q[fp])))
                fp += 1
            else:
                out.append(self._convert(letter, self._arg(gp)))
                gp += 1
        return out

    def _read_from_varargs(self, source: VarArgs, arg_types: list[str]) -> list[object]:
        out: list[object] = []
        for letter in arg_types:
            if letter in "FD":
                out.append(source.real())
            else:
                out.append(self._convert(letter, source.integer(letter == "J")))
        return out

    def _read_valist(self, arg_types: list[str], valist_ptr: int) -> list[object]:
        if self.emu.arch.cpu_arch is CpuArch.ARM:
            return self._read_from_varargs(VaListArgs32(cast("AndroidEmulator32", self.emu), valist_ptr), arg_types)
        return self._read_from_varargs(VaListArgs(self.emu, valist_ptr), arg_types)

    def _read_jvalues(self, arg_types: list[str], array_ptr: int) -> list[object]:
        out: list[object] = []
        for index, letter in enumerate(arg_types):
            raw = self.emu.mem.read_u64(array_ptr + index * 8)
            out.append(self._as_real(letter, raw) if letter in "FD" else self._convert(letter, raw))
        return out

    def _real_method(self, obj: object, name: str) -> Callable[..., object] | None:
        if not isinstance(obj, JavaObject) or type(obj) is JavaObject:
            return None
        fn = getattr(type(obj), name, None)
        return fn.__get__(obj) if callable(fn) else None

    def _real_static_method(self, java_class: object, name: str) -> Callable[..., object] | None:
        backing = getattr(java_class, "backing", None)
        if backing is None:
            return None
        raw = inspect.getattr_static(backing, name, None)
        return getattr(backing, name) if isinstance(raw, (staticmethod, classmethod)) else None

    def _call(self, ret: str, kind: str, mode: str) -> int | None:
        method_arg = 3 if kind == "nonvirtual" else 2  # nonvirtual has an extra jclass before the id
        method = self.dvm.member(self._arg(method_arg))
        if not isinstance(method, JavaMethod):
            return self._box(ret, None)
        arg_types = self.parse_arg_types(method.signature)
        args = self._read_call_args(arg_types, mode, method_arg + 1)
        recv = None if kind == "static" else self.dvm.get(self._arg(1))
        declaring_class = method.getDeclaringClass()
        real = self._real_static_method(declaring_class, method.name) if kind == "static" else self._real_method(recv, method.name)
        if real is None and method.native_addr:
            # A registered native (its body is in a loaded .so) — run it on the current guest stack and let it
            # return for us, exactly like the JVM. Redirects PC; the native returns through _native_return.
            self._dispatch_native(method, arg_types, args, ret, kind)
            return None
        try:
            if real is not None:
                result = real(*args)
            elif kind == "static":
                result = self.handler.call_static_method(method, args)
            else:
                result = self.handler.call_method(recv, method, args)
        except JavaException as exc:  # a modelled Java method threw -> set the pending JNI exception
            self._pending_exception = self._make_exception(JavaClass(exc.class_name), exc.message)
            result = None
        self.log.jni_call("Call", f"{declaring_class.name}.{method.name}", 0)
        return self._box(ret, result)

    def _dispatch_native(self, method: JavaMethod, arg_types: list[str], args: list[object], ret: str, kind: str) -> None:
        # Design (B): no nested emu_start (unicorn forbids it from inside a hook). Set up the native's AAPCS
        # frame on the CURRENT stack (x0=JNIEnv, x1=this/jclass, args…), make LR a one-shot return trampoline,
        # and jump to native_addr; the same emu_start runs the native, whose own JNI calls are just more traps.
        if not self._native_return_slot:
            self._native_return_slot = self.emu.trap.alloc_slot(self._native_return, "JNIEnv:native-return")
        saved_lr, saved_sp = (self.emu.lr, self.emu.sp)  # where Call*Method returns; SP to restore after the native
        ref_mark = self.dvm.local_mark()  # the native's local-ref frame (jclass + object args live here)
        this_ref = self.dvm.add_local(method.getDeclaringClass()) if kind == "static" else self._arg(1)
        self.emu._marshal_native(int(this_ref), arg_types, args)  # x0=env, x1=this, ints in x2.., fp in v0.., spill
        self.emu.lr = self._native_return_slot
        self._native_calls.append(NativeCall(ret, saved_lr, saved_sp, ref_mark))
        self.emu.pc = method.native_addr

    def _native_return(self) -> None:
        call = self._native_calls.pop()
        if call.return_type in ("L", "["):  # promote the returned local ref out of the native's frame
            obj = self.dvm.get(self.emu.ret)  # resolve BEFORE releasing (release invalidates the handle)
            self.dvm.local_release(call.local_refs)
            self.emu.ret = self.dvm.add_local(obj) if obj is not None else 0
        else:
            self.dvm.local_release(call.local_refs)  # int/long/bool/float/double/void: value already in x0 / v0
        self.emu.sp = call.stack_pointer  # undo the arg spill; resume the Call*Method caller
        self.emu.pc = call.return_address

    def _real_static_field(self, java_class: object, name: str) -> object:
        backing = getattr(java_class, "backing", None)
        if backing is None:
            return JNIEnv._MISS
        raw = inspect.getattr_static(backing, name, JNIEnv._MISS)
        if raw is JNIEnv._MISS or callable(raw) or isinstance(raw, (staticmethod, classmethod, property)):
            return JNIEnv._MISS
        return getattr(backing, name)

    def _get_field(self, letter: str, static: bool) -> int | None:
        field = self.dvm.member(self._arg(2))
        if not isinstance(field, JavaField):
            return self._box(letter, None)
        if not static and field.name == "artMethod":  # ART introspection: Executable.artMethod : J (core-owned)
            method = self.dvm.get(self._arg(1))
            if isinstance(method, JavaMethod):
                return self._box("J", self.dvm.art_method_ptr(method))
        if static:
            real = self._real_static_field(field.getDeclaringClass(), field.name)
            result = real if real is not JNIEnv._MISS else self.handler.get_static_field(field)
        else:
            result = self.handler.get_field(self.dvm.get(self._arg(1)), field)
        return self._box(letter, result)

    def _set_field(self, letter: str, static: bool) -> None:
        field = self.dvm.member(self._arg(2))
        if not isinstance(field, JavaField):
            return
        if letter in "FD":
            if self.emu.arch.cpu_arch is CpuArch.ARM:
                source = RegisterArgs32(cast("AndroidEmulator32", self.emu), 3)
                value = source.real() if letter == "D" else struct.unpack("<f", struct.pack("<I", source.integer(False)))[0]
            else:
                value = self._as_real(letter, self.emu.backend.reg_read(Arm64Reg.Q[0]))
        else:
            value = self._convert(letter, self._arg(3))
        if static:
            self.handler.set_static_field(field, value)
        else:
            self.handler.set_field(self.dvm.get(self._arg(1)), field, value)

    def _new_instance(self, mode: str) -> int:
        dvm_class, method = self.dvm.get(self._arg(1)), self.dvm.member(self._arg(2))
        if not isinstance(dvm_class, JavaClass):
            self._set_pending_exception("java/lang/NullPointerException", "NewObject called with an invalid class")
            return 0
        if not isinstance(method, JavaMethod):
            self._set_pending_exception("java/lang/NoSuchMethodError", "NewObject called with an invalid constructor")
            return 0
        args = self._read_call_args(self.parse_arg_types(method.signature), mode, 3)
        backing = dvm_class.backing
        if backing is not None and hasattr(backing, "jni_construct"):
            obj = backing.jni_construct(args)
        else:
            obj = self.handler.new_object(dvm_class, method, args)

        return self.dvm.add_local(obj) if obj is not None else 0

    @staticmethod
    def _jsize(raw: int) -> int:
        value = raw & 0xFFFFFFFF
        return value - 0x1_0000_0000 if value & 0x8000_0000 else value

    def _set_pending_exception(self, class_name: str, message: str) -> None:
        self._pending_exception = self._make_exception(self.dvm.find_class(class_name), message)

    def _new_primitive_array(self, letter: str) -> int:
        length = self._jsize(self._arg(1))
        if length < 0:
            self._set_pending_exception("java/lang/NegativeArraySizeException", str(length))
            return 0
        obj = JavaObject(JavaClass("[" + letter), bytearray(length * self._ELEM_SIZE[letter]))
        ref = self.dvm.add_local(obj)
        self.log.jni_call(f"New{self._PRIM_ARRAY_NAME[letter]}Array", str(length), ref)
        return ref

    def _get_array_elements(self, _letter: str) -> int:
        obj = self._array(self._arg(1))
        if obj is None or not isinstance(obj.value, (bytes, bytearray)):
            self._set_pending_exception("java/lang/NullPointerException", "primitive array is null or invalid")
            return 0
        data = bytes(obj.value)
        ptr = self.emu.libc.heap.malloc(max(len(data), 1))
        if not ptr:
            self._set_pending_exception("java/lang/OutOfMemoryError", "unable to copy primitive array")
            return 0
        self.emu.mem.write(ptr, data)
        self._array_ptrs[ptr] = self._arg(1)
        if self._arg(2):
            self.emu.mem.write_u8(self._arg(2), 1)
        return ptr

    def _release_array_elements(self, _letter: str) -> None:
        array_ref, ptr, mode = self._arg(1), self._arg(2), self._arg(3)
        obj = self._array(array_ref)
        tracked_ref = self._array_ptrs.get(ptr)
        if tracked_ref != array_ref or obj is None or not isinstance(obj.value, (bytes, bytearray)):
            return
        if mode != 2:
            data = self.emu.mem.read(ptr, len(obj.value))
            if isinstance(obj.value, bytearray):
                obj.value[:] = data  # in-place, so a caller-shared bytearray sees the mutation
            else:
                obj.value = bytearray(data)
        if mode != 1:
            self._array_ptrs.pop(ptr, None)
            self.emu.libc.heap.free(ptr)

    def _get_array_region(self, letter: str) -> None:
        obj = self._array(self._arg(1))
        start, count, buf = self._jsize(self._arg(2)), self._jsize(self._arg(3)), self._arg(4)
        if obj is None or not isinstance(obj.value, (bytes, bytearray)):
            self._set_pending_exception("java/lang/NullPointerException", "primitive array is null or invalid")
            return
        elem = self._ELEM_SIZE[letter]
        if start < 0 or count < 0 or start + count > len(obj.value) // elem:
            self._set_pending_exception("java/lang/ArrayIndexOutOfBoundsException", f"start={start}, count={count}")
            return
        self.emu.mem.write(buf, bytes(obj.value[start * elem : (start + count) * elem]))

    def _set_array_region(self, letter: str) -> None:
        obj = self._array(self._arg(1))
        start, count, buf = self._jsize(self._arg(2)), self._jsize(self._arg(3)), self._arg(4)
        if obj is None or not isinstance(obj.value, (bytes, bytearray)):
            self._set_pending_exception("java/lang/NullPointerException", "primitive array is null or invalid")
            return
        elem = self._ELEM_SIZE[letter]
        if start < 0 or count < 0 or start + count > len(obj.value) // elem:
            self._set_pending_exception("java/lang/ArrayIndexOutOfBoundsException", f"start={start}, count={count}")
            return
        data = self.emu.mem.read(buf, count * elem)
        begin = start * elem
        if isinstance(obj.value, bytearray):
            obj.value[begin : begin + len(data)] = data
        else:
            arr = bytearray(obj.value)
            arr[begin : begin + len(data)] = data
            obj.value = arr

    def _handlers(self) -> dict[int, Callable[[], int | None]]:
        handlers: dict[int, Callable[[], int | None]] = {
            JNIFunction.GET_VERSION: self._get_version,
            JNIFunction.DEFINE_CLASS: self._define_class,
            JNIFunction.FIND_CLASS: self._find_class,
            JNIFunction.FROM_REFLECTED_METHOD: self._from_reflected_method,
            JNIFunction.FROM_REFLECTED_FIELD: self._from_reflected_field,
            JNIFunction.TO_REFLECTED_METHOD: self._to_reflected_method,
            JNIFunction.GET_SUPERCLASS: self._get_superclass,
            JNIFunction.IS_ASSIGNABLE_FROM: self._is_assignable_from,
            JNIFunction.TO_REFLECTED_FIELD: self._to_reflected_field,
            JNIFunction.THROW: self._throw,
            JNIFunction.THROW_NEW: self._throw_new,
            JNIFunction.EXCEPTION_OCCURRED: self._exception_occurred,
            JNIFunction.EXCEPTION_DESCRIBE: self._exception_describe,
            JNIFunction.EXCEPTION_CLEAR: self._exception_clear,
            JNIFunction.FATAL_ERROR: self._fatal_error,
            JNIFunction.PUSH_LOCAL_FRAME: self._push_local_frame,
            JNIFunction.POP_LOCAL_FRAME: self._pop_local_frame,
            JNIFunction.NEW_GLOBAL_REF: self._new_global_ref,
            JNIFunction.DELETE_GLOBAL_REF: self._delete_global_ref,
            JNIFunction.DELETE_LOCAL_REF: self._delete_local_ref,
            JNIFunction.IS_SAME_OBJECT: self._is_same_object,
            JNIFunction.NEW_LOCAL_REF: self._new_local_ref,
            JNIFunction.ENSURE_LOCAL_CAPACITY: self._ensure_local_capacity,
            JNIFunction.ALLOC_OBJECT: self._alloc_object,
            JNIFunction.NEW_OBJECT: self._new_object,
            JNIFunction.NEW_OBJECT_V: self._new_object_v,
            JNIFunction.NEW_OBJECT_A: self._new_object_a,
            JNIFunction.GET_OBJECT_CLASS: self._get_object_class,
            JNIFunction.IS_INSTANCE_OF: self._is_instance_of,
            JNIFunction.GET_METHOD_ID: self._get_method_id,
            JNIFunction.CALL_OBJECT_METHOD: self._call_object_method,
            JNIFunction.CALL_OBJECT_METHOD_V: self._call_object_method_v,
            JNIFunction.CALL_OBJECT_METHOD_A: self._call_object_method_a,
            JNIFunction.CALL_BOOLEAN_METHOD: self._call_boolean_method,
            JNIFunction.CALL_BOOLEAN_METHOD_V: self._call_boolean_method_v,
            JNIFunction.CALL_BOOLEAN_METHOD_A: self._call_boolean_method_a,
            JNIFunction.CALL_BYTE_METHOD: self._call_byte_method,
            JNIFunction.CALL_BYTE_METHOD_V: self._call_byte_method_v,
            JNIFunction.CALL_BYTE_METHOD_A: self._call_byte_method_a,
            JNIFunction.CALL_CHAR_METHOD: self._call_char_method,
            JNIFunction.CALL_CHAR_METHOD_V: self._call_char_method_v,
            JNIFunction.CALL_CHAR_METHOD_A: self._call_char_method_a,
            JNIFunction.CALL_SHORT_METHOD: self._call_short_method,
            JNIFunction.CALL_SHORT_METHOD_V: self._call_short_method_v,
            JNIFunction.CALL_SHORT_METHOD_A: self._call_short_method_a,
            JNIFunction.CALL_INT_METHOD: self._call_int_method,
            JNIFunction.CALL_INT_METHOD_V: self._call_int_method_v,
            JNIFunction.CALL_INT_METHOD_A: self._call_int_method_a,
            JNIFunction.CALL_LONG_METHOD: self._call_long_method,
            JNIFunction.CALL_LONG_METHOD_V: self._call_long_method_v,
            JNIFunction.CALL_LONG_METHOD_A: self._call_long_method_a,
            JNIFunction.CALL_FLOAT_METHOD: self._call_float_method,
            JNIFunction.CALL_FLOAT_METHOD_V: self._call_float_method_v,
            JNIFunction.CALL_FLOAT_METHOD_A: self._call_float_method_a,
            JNIFunction.CALL_DOUBLE_METHOD: self._call_double_method,
            JNIFunction.CALL_DOUBLE_METHOD_V: self._call_double_method_v,
            JNIFunction.CALL_DOUBLE_METHOD_A: self._call_double_method_a,
            JNIFunction.CALL_VOID_METHOD: self._call_void_method,
            JNIFunction.CALL_VOID_METHOD_V: self._call_void_method_v,
            JNIFunction.CALL_VOID_METHOD_A: self._call_void_method_a,
            JNIFunction.CALL_NONVIRTUAL_OBJECT_METHOD: self._call_nonvirtual_object_method,
            JNIFunction.CALL_NONVIRTUAL_OBJECT_METHOD_V: self._call_nonvirtual_object_method_v,
            JNIFunction.CALL_NONVIRTUAL_OBJECT_METHOD_A: self._call_nonvirtual_object_method_a,
            JNIFunction.CALL_NONVIRTUAL_BOOLEAN_METHOD: self._call_nonvirtual_boolean_method,
            JNIFunction.CALL_NONVIRTUAL_BOOLEAN_METHOD_V: self._call_nonvirtual_boolean_method_v,
            JNIFunction.CALL_NONVIRTUAL_BOOLEAN_METHOD_A: self._call_nonvirtual_boolean_method_a,
            JNIFunction.CALL_NONVIRTUAL_BYTE_METHOD: self._call_nonvirtual_byte_method,
            JNIFunction.CALL_NONVIRTUAL_BYTE_METHOD_V: self._call_nonvirtual_byte_method_v,
            JNIFunction.CALL_NONVIRTUAL_BYTE_METHOD_A: self._call_nonvirtual_byte_method_a,
            JNIFunction.CALL_NONVIRTUAL_CHAR_METHOD: self._call_nonvirtual_char_method,
            JNIFunction.CALL_NONVIRTUAL_CHAR_METHOD_V: self._call_nonvirtual_char_method_v,
            JNIFunction.CALL_NONVIRTUAL_CHAR_METHOD_A: self._call_nonvirtual_char_method_a,
            JNIFunction.CALL_NONVIRTUAL_SHORT_METHOD: self._call_nonvirtual_short_method,
            JNIFunction.CALL_NONVIRTUAL_SHORT_METHOD_V: self._call_nonvirtual_short_method_v,
            JNIFunction.CALL_NONVIRTUAL_SHORT_METHOD_A: self._call_nonvirtual_short_method_a,
            JNIFunction.CALL_NONVIRTUAL_INT_METHOD: self._call_nonvirtual_int_method,
            JNIFunction.CALL_NONVIRTUAL_INT_METHOD_V: self._call_nonvirtual_int_method_v,
            JNIFunction.CALL_NONVIRTUAL_INT_METHOD_A: self._call_nonvirtual_int_method_a,
            JNIFunction.CALL_NONVIRTUAL_LONG_METHOD: self._call_nonvirtual_long_method,
            JNIFunction.CALL_NONVIRTUAL_LONG_METHOD_V: self._call_nonvirtual_long_method_v,
            JNIFunction.CALL_NONVIRTUAL_LONG_METHOD_A: self._call_nonvirtual_long_method_a,
            JNIFunction.CALL_NONVIRTUAL_FLOAT_METHOD: self._call_nonvirtual_float_method,
            JNIFunction.CALL_NONVIRTUAL_FLOAT_METHOD_V: self._call_nonvirtual_float_method_v,
            JNIFunction.CALL_NONVIRTUAL_FLOAT_METHOD_A: self._call_nonvirtual_float_method_a,
            JNIFunction.CALL_NONVIRTUAL_DOUBLE_METHOD: self._call_nonvirtual_double_method,
            JNIFunction.CALL_NONVIRTUAL_DOUBLE_METHOD_V: self._call_nonvirtual_double_method_v,
            JNIFunction.CALL_NONVIRTUAL_DOUBLE_METHOD_A: self._call_nonvirtual_double_method_a,
            JNIFunction.CALL_NONVIRTUAL_VOID_METHOD: self._call_nonvirtual_void_method,
            JNIFunction.CALL_NONVIRTUAL_VOID_METHOD_V: self._call_nonvirtual_void_method_v,
            JNIFunction.CALL_NONVIRTUAL_VOID_METHOD_A: self._call_nonvirtual_void_method_a,
            JNIFunction.GET_FIELD_ID: self._get_field_id,
            JNIFunction.GET_OBJECT_FIELD: self._get_object_field,
            JNIFunction.GET_BOOLEAN_FIELD: self._get_boolean_field,
            JNIFunction.GET_BYTE_FIELD: self._get_byte_field,
            JNIFunction.GET_CHAR_FIELD: self._get_char_field,
            JNIFunction.GET_SHORT_FIELD: self._get_short_field,
            JNIFunction.GET_INT_FIELD: self._get_int_field,
            JNIFunction.GET_LONG_FIELD: self._get_long_field,
            JNIFunction.GET_FLOAT_FIELD: self._get_float_field,
            JNIFunction.GET_DOUBLE_FIELD: self._get_double_field,
            JNIFunction.SET_OBJECT_FIELD: self._set_object_field,
            JNIFunction.SET_BOOLEAN_FIELD: self._set_boolean_field,
            JNIFunction.SET_BYTE_FIELD: self._set_byte_field,
            JNIFunction.SET_CHAR_FIELD: self._set_char_field,
            JNIFunction.SET_SHORT_FIELD: self._set_short_field,
            JNIFunction.SET_INT_FIELD: self._set_int_field,
            JNIFunction.SET_LONG_FIELD: self._set_long_field,
            JNIFunction.SET_FLOAT_FIELD: self._set_float_field,
            JNIFunction.SET_DOUBLE_FIELD: self._set_double_field,
            JNIFunction.GET_STATIC_METHOD_ID: self._get_static_method_id,
            JNIFunction.CALL_STATIC_OBJECT_METHOD: self._call_static_object_method,
            JNIFunction.CALL_STATIC_OBJECT_METHOD_V: self._call_static_object_method_v,
            JNIFunction.CALL_STATIC_OBJECT_METHOD_A: self._call_static_object_method_a,
            JNIFunction.CALL_STATIC_BOOLEAN_METHOD: self._call_static_boolean_method,
            JNIFunction.CALL_STATIC_BOOLEAN_METHOD_V: self._call_static_boolean_method_v,
            JNIFunction.CALL_STATIC_BOOLEAN_METHOD_A: self._call_static_boolean_method_a,
            JNIFunction.CALL_STATIC_BYTE_METHOD: self._call_static_byte_method,
            JNIFunction.CALL_STATIC_BYTE_METHOD_V: self._call_static_byte_method_v,
            JNIFunction.CALL_STATIC_BYTE_METHOD_A: self._call_static_byte_method_a,
            JNIFunction.CALL_STATIC_CHAR_METHOD: self._call_static_char_method,
            JNIFunction.CALL_STATIC_CHAR_METHOD_V: self._call_static_char_method_v,
            JNIFunction.CALL_STATIC_CHAR_METHOD_A: self._call_static_char_method_a,
            JNIFunction.CALL_STATIC_SHORT_METHOD: self._call_static_short_method,
            JNIFunction.CALL_STATIC_SHORT_METHOD_V: self._call_static_short_method_v,
            JNIFunction.CALL_STATIC_SHORT_METHOD_A: self._call_static_short_method_a,
            JNIFunction.CALL_STATIC_INT_METHOD: self._call_static_int_method,
            JNIFunction.CALL_STATIC_INT_METHOD_V: self._call_static_int_method_v,
            JNIFunction.CALL_STATIC_INT_METHOD_A: self._call_static_int_method_a,
            JNIFunction.CALL_STATIC_LONG_METHOD: self._call_static_long_method,
            JNIFunction.CALL_STATIC_LONG_METHOD_V: self._call_static_long_method_v,
            JNIFunction.CALL_STATIC_LONG_METHOD_A: self._call_static_long_method_a,
            JNIFunction.CALL_STATIC_FLOAT_METHOD: self._call_static_float_method,
            JNIFunction.CALL_STATIC_FLOAT_METHOD_V: self._call_static_float_method_v,
            JNIFunction.CALL_STATIC_FLOAT_METHOD_A: self._call_static_float_method_a,
            JNIFunction.CALL_STATIC_DOUBLE_METHOD: self._call_static_double_method,
            JNIFunction.CALL_STATIC_DOUBLE_METHOD_V: self._call_static_double_method_v,
            JNIFunction.CALL_STATIC_DOUBLE_METHOD_A: self._call_static_double_method_a,
            JNIFunction.CALL_STATIC_VOID_METHOD: self._call_static_void_method,
            JNIFunction.CALL_STATIC_VOID_METHOD_V: self._call_static_void_method_v,
            JNIFunction.CALL_STATIC_VOID_METHOD_A: self._call_static_void_method_a,
            JNIFunction.GET_STATIC_FIELD_ID: self._get_static_field_id,
            JNIFunction.GET_STATIC_OBJECT_FIELD: self._get_static_object_field,
            JNIFunction.GET_STATIC_BOOLEAN_FIELD: self._get_static_boolean_field,
            JNIFunction.GET_STATIC_BYTE_FIELD: self._get_static_byte_field,
            JNIFunction.GET_STATIC_CHAR_FIELD: self._get_static_char_field,
            JNIFunction.GET_STATIC_SHORT_FIELD: self._get_static_short_field,
            JNIFunction.GET_STATIC_INT_FIELD: self._get_static_int_field,
            JNIFunction.GET_STATIC_LONG_FIELD: self._get_static_long_field,
            JNIFunction.GET_STATIC_FLOAT_FIELD: self._get_static_float_field,
            JNIFunction.GET_STATIC_DOUBLE_FIELD: self._get_static_double_field,
            JNIFunction.SET_STATIC_OBJECT_FIELD: self._set_static_object_field,
            JNIFunction.SET_STATIC_BOOLEAN_FIELD: self._set_static_boolean_field,
            JNIFunction.SET_STATIC_BYTE_FIELD: self._set_static_byte_field,
            JNIFunction.SET_STATIC_CHAR_FIELD: self._set_static_char_field,
            JNIFunction.SET_STATIC_SHORT_FIELD: self._set_static_short_field,
            JNIFunction.SET_STATIC_INT_FIELD: self._set_static_int_field,
            JNIFunction.SET_STATIC_LONG_FIELD: self._set_static_long_field,
            JNIFunction.SET_STATIC_FLOAT_FIELD: self._set_static_float_field,
            JNIFunction.SET_STATIC_DOUBLE_FIELD: self._set_static_double_field,
            JNIFunction.NEW_STRING: self._new_string,
            JNIFunction.GET_STRING_LENGTH: self._get_string_length,
            JNIFunction.GET_STRING_CHARS: self._get_string_chars,
            JNIFunction.RELEASE_STRING_CHARS: self._release_string_chars,
            JNIFunction.NEW_STRING_UTF: self._new_string_utf,
            JNIFunction.GET_STRING_UTF_LENGTH: self._get_string_utf_length,
            JNIFunction.GET_STRING_UTF_CHARS: self._get_string_utf_chars,
            JNIFunction.RELEASE_STRING_UTF_CHARS: self._release_string_utf_chars,
            JNIFunction.GET_ARRAY_LENGTH: self._get_array_length,
            JNIFunction.NEW_OBJECT_ARRAY: self._new_object_array,
            JNIFunction.GET_OBJECT_ARRAY_ELEMENT: self._get_object_array_element,
            JNIFunction.SET_OBJECT_ARRAY_ELEMENT: self._set_object_array_element,
            JNIFunction.NEW_BOOLEAN_ARRAY: self._new_boolean_array,
            JNIFunction.NEW_BYTE_ARRAY: self._new_byte_array,
            JNIFunction.NEW_CHAR_ARRAY: self._new_char_array,
            JNIFunction.NEW_SHORT_ARRAY: self._new_short_array,
            JNIFunction.NEW_INT_ARRAY: self._new_int_array,
            JNIFunction.NEW_LONG_ARRAY: self._new_long_array,
            JNIFunction.NEW_FLOAT_ARRAY: self._new_float_array,
            JNIFunction.NEW_DOUBLE_ARRAY: self._new_double_array,
            JNIFunction.GET_BOOLEAN_ARRAY_ELEMENTS: self._get_boolean_array_elements,
            JNIFunction.GET_BYTE_ARRAY_ELEMENTS: self._get_byte_array_elements,
            JNIFunction.GET_CHAR_ARRAY_ELEMENTS: self._get_char_array_elements,
            JNIFunction.GET_SHORT_ARRAY_ELEMENTS: self._get_short_array_elements,
            JNIFunction.GET_INT_ARRAY_ELEMENTS: self._get_int_array_elements,
            JNIFunction.GET_LONG_ARRAY_ELEMENTS: self._get_long_array_elements,
            JNIFunction.GET_FLOAT_ARRAY_ELEMENTS: self._get_float_array_elements,
            JNIFunction.GET_DOUBLE_ARRAY_ELEMENTS: self._get_double_array_elements,
            JNIFunction.RELEASE_BOOLEAN_ARRAY_ELEMENTS: self._release_boolean_array_elements,
            JNIFunction.RELEASE_BYTE_ARRAY_ELEMENTS: self._release_byte_array_elements,
            JNIFunction.RELEASE_CHAR_ARRAY_ELEMENTS: self._release_char_array_elements,
            JNIFunction.RELEASE_SHORT_ARRAY_ELEMENTS: self._release_short_array_elements,
            JNIFunction.RELEASE_INT_ARRAY_ELEMENTS: self._release_int_array_elements,
            JNIFunction.RELEASE_LONG_ARRAY_ELEMENTS: self._release_long_array_elements,
            JNIFunction.RELEASE_FLOAT_ARRAY_ELEMENTS: self._release_float_array_elements,
            JNIFunction.RELEASE_DOUBLE_ARRAY_ELEMENTS: self._release_double_array_elements,
            JNIFunction.GET_BOOLEAN_ARRAY_REGION: self._get_boolean_array_region,
            JNIFunction.GET_BYTE_ARRAY_REGION: self._get_byte_array_region,
            JNIFunction.GET_CHAR_ARRAY_REGION: self._get_char_array_region,
            JNIFunction.GET_SHORT_ARRAY_REGION: self._get_short_array_region,
            JNIFunction.GET_INT_ARRAY_REGION: self._get_int_array_region,
            JNIFunction.GET_LONG_ARRAY_REGION: self._get_long_array_region,
            JNIFunction.GET_FLOAT_ARRAY_REGION: self._get_float_array_region,
            JNIFunction.GET_DOUBLE_ARRAY_REGION: self._get_double_array_region,
            JNIFunction.SET_BOOLEAN_ARRAY_REGION: self._set_boolean_array_region,
            JNIFunction.SET_BYTE_ARRAY_REGION: self._set_byte_array_region,
            JNIFunction.SET_CHAR_ARRAY_REGION: self._set_char_array_region,
            JNIFunction.SET_SHORT_ARRAY_REGION: self._set_short_array_region,
            JNIFunction.SET_INT_ARRAY_REGION: self._set_int_array_region,
            JNIFunction.SET_LONG_ARRAY_REGION: self._set_long_array_region,
            JNIFunction.SET_FLOAT_ARRAY_REGION: self._set_float_array_region,
            JNIFunction.SET_DOUBLE_ARRAY_REGION: self._set_double_array_region,
            JNIFunction.REGISTER_NATIVES: self._register_natives,
            JNIFunction.UNREGISTER_NATIVES: self._unregister_natives,
            JNIFunction.MONITOR_ENTER: self._monitor_enter,
            JNIFunction.MONITOR_EXIT: self._monitor_exit,
            JNIFunction.GET_JAVA_VM: self._get_java_vm,
            JNIFunction.GET_STRING_REGION: self._get_string_region,
            JNIFunction.GET_STRING_UTF_REGION: self._get_string_utf_region,
            JNIFunction.GET_PRIMITIVE_ARRAY_CRITICAL: self._get_primitive_array_critical,
            JNIFunction.RELEASE_PRIMITIVE_ARRAY_CRITICAL: self._release_primitive_array_critical,
            JNIFunction.GET_STRING_CRITICAL: self._get_string_critical,
            JNIFunction.RELEASE_STRING_CRITICAL: self._release_string_critical,
            JNIFunction.NEW_WEAK_GLOBAL_REF: self._new_weak_global_ref,
            JNIFunction.DELETE_WEAK_GLOBAL_REF: self._delete_weak_global_ref,
            JNIFunction.EXCEPTION_CHECK: self._exception_check,
            JNIFunction.NEW_DIRECT_BYTE_BUFFER: self._new_direct_byte_buffer,
            JNIFunction.GET_DIRECT_BUFFER_ADDRESS: self._get_direct_buffer_address,
            JNIFunction.GET_DIRECT_BUFFER_CAPACITY: self._get_direct_buffer_capacity,
            JNIFunction.GET_OBJECT_REF_TYPE: self._get_object_ref_type,
            JNIFunction.GET_MODULE: self._get_module,
            JNIFunction.IS_VIRTUAL_THREAD: self._is_virtual_thread,
            JNIFunction.GET_STRING_UTF_LENGTH_AS_LONG: self._get_string_utf_length_as_long,
        }
        return handlers

    def _get_version(self) -> int | None:
        return self.version

    def _define_class(self) -> int | None:
        raise NotImplementedError("JNIEnv.DefineClass: emulite cannot load classes from bytecode")

    def _find_class(self) -> int | None:
        name = self._cstr(self._arg(1))
        if not self.handler.accept_class(name):
            self._pending_exception = JavaNoClassDefFoundError(name)
            self.log.jni("FindClass(%r) not found => NULL + NoClassDefFoundError", name)
            return 0
        ref = self.dvm.add_local(self.dvm.find_class(name))
        self.log.jni_call("FindClass", repr(name), ref)
        return ref

    def _from_reflected_method(self) -> int | None:
        member = self.dvm.get(self._arg(1))
        return self.dvm.id_of(member) if isinstance(member, JavaMethod) else 0

    def _from_reflected_field(self) -> int | None:
        member = self.dvm.get(self._arg(1))
        return self.dvm.id_of(member) if isinstance(member, JavaField) else 0

    def _to_reflected_method(self) -> int | None:
        member = self.dvm.member(self._arg(2))
        return self.dvm.add_local(member) if isinstance(member, JavaMethod) else 0

    def _get_superclass(self) -> int | None:
        clazz = self.dvm.get(self._arg(1))
        if not isinstance(clazz, JavaClass):
            return 0
        superclass = clazz.getSuperclass()
        return self.dvm.add_local(superclass) if superclass is not None else 0

    def _is_assignable_from(self) -> int | None:
        source, target = self.dvm.get(self._arg(1)), self.dvm.get(self._arg(2))
        return 1 if isinstance(source, JavaClass) and isinstance(target, JavaClass) and target.isAssignableFrom(source) else 0

    def _to_reflected_field(self) -> int | None:
        member = self.dvm.member(self._arg(2))
        return self.dvm.add_local(member) if isinstance(member, JavaField) else 0

    def _throw(self) -> int | None:
        self._pending_exception = self.dvm.get(self._arg(1))
        return 0

    def _throw_new(self) -> int | None:
        clazz = self.dvm.get(self._arg(1))
        klass = clazz if isinstance(clazz, JavaClass) else JavaClass("java/lang/Throwable")
        self._pending_exception = self._make_exception(klass, self._cstr(self._arg(2)))
        return 0

    def _make_exception(self, klass: JavaClass, message: str) -> object:
        backing = klass.backing
        if backing is not None and issubclass(backing, JavaThrowable):
            exception = backing(message)
            if isinstance(exception, JavaObject):
                return exception
        return JavaObject(klass, message)

    def take_pending_exception(self) -> object | None:
        exception, self._pending_exception = self._pending_exception, None
        return exception

    def _exception_occurred(self) -> int | None:
        if self._pending_exception is None:
            return 0
        return self.dvm.add_local(self._pending_exception)

    def _exception_describe(self) -> None:
        if self._pending_exception is not None:
            self.log.jni("ExceptionDescribe: %r", self._pending_exception)
            self._pending_exception = None

    def _exception_clear(self) -> None:
        self._pending_exception = None

    def _fatal_error(self) -> int | None:
        raise EmulatorCrashed(f"JNI FatalError: {self._cstr(self._arg(1))}")

    def _push_local_frame(self) -> int | None:
        self._local_frames.append(self.dvm.local_mark())
        return 0

    def _pop_local_frame(self) -> int | None:
        if not self._local_frames:
            return self._arg(1)
        result = self.dvm.get(self._arg(1))
        self.dvm.local_release(self._local_frames.pop())
        return self.dvm.add_local(result) if result is not None else 0

    def _new_global_ref(self) -> int | None:
        obj = self.dvm.get(self._arg(1))
        return self.dvm.add_global(obj) if obj is not None else 0

    def _delete_global_ref(self) -> int | None:
        self.dvm.delete_global(self._arg(1))
        return None

    def _delete_local_ref(self) -> int | None:
        self.dvm.delete_local(self._arg(1))
        return None

    def _is_same_object(self) -> int | None:
        return 1 if self.dvm.get(self._arg(1)) is self.dvm.get(self._arg(2)) else 0

    def _new_local_ref(self) -> int | None:
        obj = self.dvm.get(self._arg(1))
        return self.dvm.add_local(obj) if obj is not None else 0

    def _ensure_local_capacity(self) -> int | None:
        return 0

    def _alloc_object(self) -> int | None:
        clazz = self.dvm.get(self._arg(1))
        return self.dvm.add_local(JavaObject(clazz)) if isinstance(clazz, JavaClass) else 0

    def _new_object(self) -> int | None:
        return self._new_instance("")

    def _new_object_v(self) -> int | None:
        return self._new_instance("V")

    def _new_object_a(self) -> int | None:
        return self._new_instance("A")

    def _get_object_class(self) -> int | None:
        obj = self.dvm.get(self._arg(1))
        if isinstance(obj, JavaObject):
            return self.dvm.add_local(obj.getClass())
        self._set_pending_exception("java/lang/NullPointerException", "GetObjectClass called with null")
        return 0

    def _is_instance_of(self) -> int | None:
        obj, clazz = self.dvm.get(self._arg(1)), self.dvm.get(self._arg(2))
        if obj is None:
            return 1
        return 1 if isinstance(clazz, JavaClass) and isinstance(obj, JavaObject) and clazz.isInstance(obj) else 0

    def _get_method_id(self) -> int | None:
        return self._method_id(static=False)

    def _call_object_method(self) -> int | None:
        return self._call("L", "virtual", "")

    def _call_object_method_v(self) -> int | None:
        return self._call("L", "virtual", "V")

    def _call_object_method_a(self) -> int | None:
        return self._call("L", "virtual", "A")

    def _call_boolean_method(self) -> int | None:
        return self._call("Z", "virtual", "")

    def _call_boolean_method_v(self) -> int | None:
        return self._call("Z", "virtual", "V")

    def _call_boolean_method_a(self) -> int | None:
        return self._call("Z", "virtual", "A")

    def _call_byte_method(self) -> int | None:
        return self._call("B", "virtual", "")

    def _call_byte_method_v(self) -> int | None:
        return self._call("B", "virtual", "V")

    def _call_byte_method_a(self) -> int | None:
        return self._call("B", "virtual", "A")

    def _call_char_method(self) -> int | None:
        return self._call("C", "virtual", "")

    def _call_char_method_v(self) -> int | None:
        return self._call("C", "virtual", "V")

    def _call_char_method_a(self) -> int | None:
        return self._call("C", "virtual", "A")

    def _call_short_method(self) -> int | None:
        return self._call("S", "virtual", "")

    def _call_short_method_v(self) -> int | None:
        return self._call("S", "virtual", "V")

    def _call_short_method_a(self) -> int | None:
        return self._call("S", "virtual", "A")

    def _call_int_method(self) -> int | None:
        return self._call("I", "virtual", "")

    def _call_int_method_v(self) -> int | None:
        return self._call("I", "virtual", "V")

    def _call_int_method_a(self) -> int | None:
        return self._call("I", "virtual", "A")

    def _call_long_method(self) -> int | None:
        return self._call("J", "virtual", "")

    def _call_long_method_v(self) -> int | None:
        return self._call("J", "virtual", "V")

    def _call_long_method_a(self) -> int | None:
        return self._call("J", "virtual", "A")

    def _call_float_method(self) -> int | None:
        return self._call("F", "virtual", "")

    def _call_float_method_v(self) -> int | None:
        return self._call("F", "virtual", "V")

    def _call_float_method_a(self) -> int | None:
        return self._call("F", "virtual", "A")

    def _call_double_method(self) -> int | None:
        return self._call("D", "virtual", "")

    def _call_double_method_v(self) -> int | None:
        return self._call("D", "virtual", "V")

    def _call_double_method_a(self) -> int | None:
        return self._call("D", "virtual", "A")

    def _call_void_method(self) -> int | None:
        return self._call("V", "virtual", "")

    def _call_void_method_v(self) -> int | None:
        return self._call("V", "virtual", "V")

    def _call_void_method_a(self) -> int | None:
        return self._call("V", "virtual", "A")

    def _call_nonvirtual_object_method(self) -> int | None:
        return self._call("L", "nonvirtual", "")

    def _call_nonvirtual_object_method_v(self) -> int | None:
        return self._call("L", "nonvirtual", "V")

    def _call_nonvirtual_object_method_a(self) -> int | None:
        return self._call("L", "nonvirtual", "A")

    def _call_nonvirtual_boolean_method(self) -> int | None:
        return self._call("Z", "nonvirtual", "")

    def _call_nonvirtual_boolean_method_v(self) -> int | None:
        return self._call("Z", "nonvirtual", "V")

    def _call_nonvirtual_boolean_method_a(self) -> int | None:
        return self._call("Z", "nonvirtual", "A")

    def _call_nonvirtual_byte_method(self) -> int | None:
        return self._call("B", "nonvirtual", "")

    def _call_nonvirtual_byte_method_v(self) -> int | None:
        return self._call("B", "nonvirtual", "V")

    def _call_nonvirtual_byte_method_a(self) -> int | None:
        return self._call("B", "nonvirtual", "A")

    def _call_nonvirtual_char_method(self) -> int | None:
        return self._call("C", "nonvirtual", "")

    def _call_nonvirtual_char_method_v(self) -> int | None:
        return self._call("C", "nonvirtual", "V")

    def _call_nonvirtual_char_method_a(self) -> int | None:
        return self._call("C", "nonvirtual", "A")

    def _call_nonvirtual_short_method(self) -> int | None:
        return self._call("S", "nonvirtual", "")

    def _call_nonvirtual_short_method_v(self) -> int | None:
        return self._call("S", "nonvirtual", "V")

    def _call_nonvirtual_short_method_a(self) -> int | None:
        return self._call("S", "nonvirtual", "A")

    def _call_nonvirtual_int_method(self) -> int | None:
        return self._call("I", "nonvirtual", "")

    def _call_nonvirtual_int_method_v(self) -> int | None:
        return self._call("I", "nonvirtual", "V")

    def _call_nonvirtual_int_method_a(self) -> int | None:
        return self._call("I", "nonvirtual", "A")

    def _call_nonvirtual_long_method(self) -> int | None:
        return self._call("J", "nonvirtual", "")

    def _call_nonvirtual_long_method_v(self) -> int | None:
        return self._call("J", "nonvirtual", "V")

    def _call_nonvirtual_long_method_a(self) -> int | None:
        return self._call("J", "nonvirtual", "A")

    def _call_nonvirtual_float_method(self) -> int | None:
        return self._call("F", "nonvirtual", "")

    def _call_nonvirtual_float_method_v(self) -> int | None:
        return self._call("F", "nonvirtual", "V")

    def _call_nonvirtual_float_method_a(self) -> int | None:
        return self._call("F", "nonvirtual", "A")

    def _call_nonvirtual_double_method(self) -> int | None:
        return self._call("D", "nonvirtual", "")

    def _call_nonvirtual_double_method_v(self) -> int | None:
        return self._call("D", "nonvirtual", "V")

    def _call_nonvirtual_double_method_a(self) -> int | None:
        return self._call("D", "nonvirtual", "A")

    def _call_nonvirtual_void_method(self) -> int | None:
        return self._call("V", "nonvirtual", "")

    def _call_nonvirtual_void_method_v(self) -> int | None:
        return self._call("V", "nonvirtual", "V")

    def _call_nonvirtual_void_method_a(self) -> int | None:
        return self._call("V", "nonvirtual", "A")

    def _get_field_id(self) -> int | None:
        return self._field_id(static=False)

    def _get_object_field(self) -> int | None:
        return self._get_field("L", static=False)

    def _get_boolean_field(self) -> int | None:
        return self._get_field("Z", static=False)

    def _get_byte_field(self) -> int | None:
        return self._get_field("B", static=False)

    def _get_char_field(self) -> int | None:
        return self._get_field("C", static=False)

    def _get_short_field(self) -> int | None:
        return self._get_field("S", static=False)

    def _get_int_field(self) -> int | None:
        return self._get_field("I", static=False)

    def _get_long_field(self) -> int | None:
        return self._get_field("J", static=False)

    def _get_float_field(self) -> int | None:
        return self._get_field("F", static=False)

    def _get_double_field(self) -> int | None:
        return self._get_field("D", static=False)

    def _set_object_field(self) -> None:
        self._set_field("L", static=False)

    def _set_boolean_field(self) -> None:
        self._set_field("Z", static=False)

    def _set_byte_field(self) -> None:
        self._set_field("B", static=False)

    def _set_char_field(self) -> None:
        self._set_field("C", static=False)

    def _set_short_field(self) -> None:
        self._set_field("S", static=False)

    def _set_int_field(self) -> None:
        self._set_field("I", static=False)

    def _set_long_field(self) -> None:
        self._set_field("J", static=False)

    def _set_float_field(self) -> None:
        self._set_field("F", static=False)

    def _set_double_field(self) -> None:
        self._set_field("D", static=False)

    def _get_static_method_id(self) -> int | None:
        return self._method_id(static=True)

    def _call_static_object_method(self) -> int | None:
        return self._call("L", "static", "")

    def _call_static_object_method_v(self) -> int | None:
        return self._call("L", "static", "V")

    def _call_static_object_method_a(self) -> int | None:
        return self._call("L", "static", "A")

    def _call_static_boolean_method(self) -> int | None:
        return self._call("Z", "static", "")

    def _call_static_boolean_method_v(self) -> int | None:
        return self._call("Z", "static", "V")

    def _call_static_boolean_method_a(self) -> int | None:
        return self._call("Z", "static", "A")

    def _call_static_byte_method(self) -> int | None:
        return self._call("B", "static", "")

    def _call_static_byte_method_v(self) -> int | None:
        return self._call("B", "static", "V")

    def _call_static_byte_method_a(self) -> int | None:
        return self._call("B", "static", "A")

    def _call_static_char_method(self) -> int | None:
        return self._call("C", "static", "")

    def _call_static_char_method_v(self) -> int | None:
        return self._call("C", "static", "V")

    def _call_static_char_method_a(self) -> int | None:
        return self._call("C", "static", "A")

    def _call_static_short_method(self) -> int | None:
        return self._call("S", "static", "")

    def _call_static_short_method_v(self) -> int | None:
        return self._call("S", "static", "V")

    def _call_static_short_method_a(self) -> int | None:
        return self._call("S", "static", "A")

    def _call_static_int_method(self) -> int | None:
        return self._call("I", "static", "")

    def _call_static_int_method_v(self) -> int | None:
        return self._call("I", "static", "V")

    def _call_static_int_method_a(self) -> int | None:
        return self._call("I", "static", "A")

    def _call_static_long_method(self) -> int | None:
        return self._call("J", "static", "")

    def _call_static_long_method_v(self) -> int | None:
        return self._call("J", "static", "V")

    def _call_static_long_method_a(self) -> int | None:
        return self._call("J", "static", "A")

    def _call_static_float_method(self) -> int | None:
        return self._call("F", "static", "")

    def _call_static_float_method_v(self) -> int | None:
        return self._call("F", "static", "V")

    def _call_static_float_method_a(self) -> int | None:
        return self._call("F", "static", "A")

    def _call_static_double_method(self) -> int | None:
        return self._call("D", "static", "")

    def _call_static_double_method_v(self) -> int | None:
        return self._call("D", "static", "V")

    def _call_static_double_method_a(self) -> int | None:
        return self._call("D", "static", "A")

    def _call_static_void_method(self) -> int | None:
        return self._call("V", "static", "")

    def _call_static_void_method_v(self) -> int | None:
        return self._call("V", "static", "V")

    def _call_static_void_method_a(self) -> int | None:
        return self._call("V", "static", "A")

    def _get_static_field_id(self) -> int | None:
        return self._field_id(static=True)

    def _get_static_object_field(self) -> int | None:
        return self._get_field("L", static=True)

    def _get_static_boolean_field(self) -> int | None:
        return self._get_field("Z", static=True)

    def _get_static_byte_field(self) -> int | None:
        return self._get_field("B", static=True)

    def _get_static_char_field(self) -> int | None:
        return self._get_field("C", static=True)

    def _get_static_short_field(self) -> int | None:
        return self._get_field("S", static=True)

    def _get_static_int_field(self) -> int | None:
        return self._get_field("I", static=True)

    def _get_static_long_field(self) -> int | None:
        return self._get_field("J", static=True)

    def _get_static_float_field(self) -> int | None:
        return self._get_field("F", static=True)

    def _get_static_double_field(self) -> int | None:
        return self._get_field("D", static=True)

    def _set_static_object_field(self) -> None:
        self._set_field("L", static=True)

    def _set_static_boolean_field(self) -> None:
        self._set_field("Z", static=True)

    def _set_static_byte_field(self) -> None:
        self._set_field("B", static=True)

    def _set_static_char_field(self) -> None:
        self._set_field("C", static=True)

    def _set_static_short_field(self) -> None:
        self._set_field("S", static=True)

    def _set_static_int_field(self) -> None:
        self._set_field("I", static=True)

    def _set_static_long_field(self) -> None:
        self._set_field("J", static=True)

    def _set_static_float_field(self) -> None:
        self._set_field("F", static=True)

    def _set_static_double_field(self) -> None:
        self._set_field("D", static=True)

    def _new_string(self) -> int | None:
        ptr, length = self._arg(1), self._jsize(self._arg(2))
        if length < 0:
            self._set_pending_exception("java/lang/IllegalArgumentException", f"negative string length: {length}")
            return 0
        text = self.emu.mem.read(ptr, length * 2).decode("utf-16-le", "surrogatepass") if ptr else ""
        return self.dvm.add_local(JavaString(text))

    def _get_string_length(self) -> int | None:
        return len(self._str(self._arg(1)).encode("utf-16-le", "surrogatepass")) // 2

    def _get_string_chars(self) -> int | None:
        data = self._str(self._arg(1)).encode("utf-16-le", "surrogatepass")
        ptr = self.emu.libc.heap.malloc(max(len(data), 2))
        if not ptr:
            self._set_pending_exception("java/lang/OutOfMemoryError", "unable to copy string")
            return 0
        self.emu.mem.write(ptr, data)
        self._string_ptrs.add(ptr)
        if self._arg(2):
            self.emu.mem.write_u8(self._arg(2), 1)
        return ptr

    def _release_string_chars(self) -> int | None:
        ptr = self._arg(2)
        if ptr in self._string_ptrs:
            self._string_ptrs.remove(ptr)
            self.emu.libc.heap.free(ptr)
        return None

    def _new_string_utf(self) -> int | None:
        ptr = self._arg(1)
        try:
            text = Mutf8.decode(self.emu.mem.read_cstr_bytes(ptr)) if ptr else ""
        except UnicodeDecodeError as error:
            self._set_pending_exception("java/lang/IllegalArgumentException", str(error))
            return 0
        ref = self.dvm.add_local(JavaString(text))
        self.log.jni_call("NewStringUTF", repr(text), ref)
        return ref

    def _get_string_utf_length(self) -> int | None:
        return len(Mutf8.encode(self._str(self._arg(1))))

    def _get_string_utf_chars(self) -> int | None:
        data = Mutf8.encode(self._str(self._arg(1))) + b"\x00"
        ptr = self.emu.libc.heap.malloc(len(data))
        if not ptr:
            self._set_pending_exception("java/lang/OutOfMemoryError", "unable to copy modified UTF-8 string")
            return 0
        self.emu.mem.write(ptr, data)
        self._string_ptrs.add(ptr)
        if self._arg(2):
            self.emu.mem.write_u8(self._arg(2), 1)
        return ptr

    def _release_string_utf_chars(self) -> int | None:
        ptr = self._arg(2)
        if ptr in self._string_ptrs:
            self._string_ptrs.remove(ptr)
            self.emu.libc.heap.free(ptr)
        return None

    def _get_array_length(self) -> int | None:
        obj = self._array(self._arg(1))
        if obj is None:
            self._set_pending_exception("java/lang/NullPointerException", "GetArrayLength called with null")
            return 0
        elif isinstance(obj.value, list):
            length = len(obj.value)
        elif isinstance(obj.value, (bytes, bytearray)):
            name = obj.getClass().name
            elem = self._ELEM_SIZE.get(name[1:2], 1) if name.startswith("[") else 1
            length = len(obj.value) // elem
        else:
            self._set_pending_exception("java/lang/IllegalArgumentException", "object is not an array")
            return 0
        self.log.jni_call("GetArrayLength", "", length)
        return length

    def _new_object_array(self) -> int | None:
        length, initial = self._jsize(self._arg(1)), self.dvm.get(self._arg(3))
        if length < 0:
            self._set_pending_exception("java/lang/NegativeArraySizeException", str(length))
            return 0
        element = self.dvm.get(self._arg(2))
        name = element.name if isinstance(element, JavaClass) else "java/lang/Object"
        descriptor = ("[" + name) if name.startswith("[") else ("[L" + name + ";")
        ref = self.dvm.add_local(JavaObject(JavaClass(descriptor), [initial] * length))
        self.log.jni_call("NewObjectArray", f"{length} {descriptor}", ref)
        return ref

    def _get_object_array_element(self) -> int | None:
        obj, index = self.dvm.get(self._arg(1)), self._jsize(self._arg(2))
        if isinstance(obj, JavaObject) and isinstance(obj.value, list) and 0 <= index < len(obj.value):
            element = obj.value[index]
            return self.dvm.add_local(element) if element is not None else 0
        self._set_pending_exception("java/lang/ArrayIndexOutOfBoundsException", str(index))
        return 0

    def _set_object_array_element(self) -> int | None:
        obj, index, value = self.dvm.get(self._arg(1)), self._jsize(self._arg(2)), self.dvm.get(self._arg(3))
        if isinstance(obj, JavaObject) and isinstance(obj.value, list) and 0 <= index < len(obj.value):
            obj.value[index] = value
        else:
            self._set_pending_exception("java/lang/ArrayIndexOutOfBoundsException", str(index))
        return None

    def _new_boolean_array(self) -> int | None:
        return self._new_primitive_array("Z")

    def _new_byte_array(self) -> int | None:
        return self._new_primitive_array("B")

    def _new_char_array(self) -> int | None:
        return self._new_primitive_array("C")

    def _new_short_array(self) -> int | None:
        return self._new_primitive_array("S")

    def _new_int_array(self) -> int | None:
        return self._new_primitive_array("I")

    def _new_long_array(self) -> int | None:
        return self._new_primitive_array("J")

    def _new_float_array(self) -> int | None:
        return self._new_primitive_array("F")

    def _new_double_array(self) -> int | None:
        return self._new_primitive_array("D")

    def _get_boolean_array_elements(self) -> int | None:
        return self._get_array_elements("Z")

    def _get_byte_array_elements(self) -> int | None:
        return self._get_array_elements("B")

    def _get_char_array_elements(self) -> int | None:
        return self._get_array_elements("C")

    def _get_short_array_elements(self) -> int | None:
        return self._get_array_elements("S")

    def _get_int_array_elements(self) -> int | None:
        return self._get_array_elements("I")

    def _get_long_array_elements(self) -> int | None:
        return self._get_array_elements("J")

    def _get_float_array_elements(self) -> int | None:
        return self._get_array_elements("F")

    def _get_double_array_elements(self) -> int | None:
        return self._get_array_elements("D")

    def _release_boolean_array_elements(self) -> None:
        self._release_array_elements("Z")

    def _release_byte_array_elements(self) -> None:
        self._release_array_elements("B")

    def _release_char_array_elements(self) -> None:
        self._release_array_elements("C")

    def _release_short_array_elements(self) -> None:
        self._release_array_elements("S")

    def _release_int_array_elements(self) -> None:
        self._release_array_elements("I")

    def _release_long_array_elements(self) -> None:
        self._release_array_elements("J")

    def _release_float_array_elements(self) -> None:
        self._release_array_elements("F")

    def _release_double_array_elements(self) -> None:
        self._release_array_elements("D")

    def _get_boolean_array_region(self) -> None:
        self._get_array_region("Z")

    def _get_byte_array_region(self) -> None:
        self._get_array_region("B")

    def _get_char_array_region(self) -> None:
        self._get_array_region("C")

    def _get_short_array_region(self) -> None:
        self._get_array_region("S")

    def _get_int_array_region(self) -> None:
        self._get_array_region("I")

    def _get_long_array_region(self) -> None:
        self._get_array_region("J")

    def _get_float_array_region(self) -> None:
        self._get_array_region("F")

    def _get_double_array_region(self) -> None:
        self._get_array_region("D")

    def _set_boolean_array_region(self) -> None:
        self._set_array_region("Z")

    def _set_byte_array_region(self) -> None:
        self._set_array_region("B")

    def _set_char_array_region(self) -> None:
        self._set_array_region("C")

    def _set_short_array_region(self) -> None:
        self._set_array_region("S")

    def _set_int_array_region(self) -> None:
        self._set_array_region("I")

    def _set_long_array_region(self) -> None:
        self._set_array_region("J")

    def _set_float_array_region(self) -> None:
        self._set_array_region("F")

    def _set_double_array_region(self) -> None:
        self._set_array_region("D")

    def _register_natives(self) -> int | None:
        cls, methods_ptr, count = self.dvm.get(self._arg(1)), self._arg(2), self._arg(3)
        if not isinstance(cls, JavaClass):
            return JNIReturnCode.JNI_ERR
        mem = self.emu.mem
        pointer_size = self.emu.arch.pointer_size
        read_ptr = mem.read_u64 if pointer_size == 8 else mem.read_u32
        for i in range(count):
            entry = methods_ptr + i * (pointer_size * 3)
            name = self._cstr(read_ptr(entry))
            sig = self._cstr(read_ptr(entry + pointer_size))
            fn = read_ptr(entry + pointer_size * 2)
            self.dvm.set_native(cls, name, sig, fn)
            self.log.jni("RegisterNatives %s.%s%s => %#x", cls.name, name, sig, fn)
        return JNIReturnCode.JNI_OK

    def _unregister_natives(self) -> int | None:
        java_class = self.dvm.get(self._arg(1))
        if not isinstance(java_class, JavaClass):
            return JNIReturnCode.JNI_ERR
        self.dvm.unregister_natives(java_class)
        return JNIReturnCode.JNI_OK

    def _monitor_enter(self) -> int | None:
        return JNIReturnCode.JNI_OK

    def _monitor_exit(self) -> int | None:
        return JNIReturnCode.JNI_OK

    def _get_java_vm(self) -> int | None:
        self.emu.mem.write_ptr(self._arg(1), self.emu.javavm.pointer)
        return JNIReturnCode.JNI_OK

    def _get_string_region(self) -> int | None:
        text, start, length, buf = self._str(self._arg(1)), self._jsize(self._arg(2)), self._jsize(self._arg(3)), self._arg(4)
        units = text.encode("utf-16-le", "surrogatepass")
        if start < 0 or length < 0 or start + length > len(units) // 2:
            self._set_pending_exception("java/lang/StringIndexOutOfBoundsException", f"start={start}, length={length}")
            return None
        self.emu.mem.write(buf, units[start * 2 : (start + length) * 2])
        return None

    def _get_string_utf_region(self) -> int | None:
        text, start, length, buf = self._str(self._arg(1)), self._jsize(self._arg(2)), self._jsize(self._arg(3)), self._arg(4)
        units = text.encode("utf-16-le", "surrogatepass")
        if start < 0 or length < 0 or start + length > len(units) // 2:
            self._set_pending_exception("java/lang/StringIndexOutOfBoundsException", f"start={start}, length={length}")
            return None
        region = units[start * 2 : (start + length) * 2].decode("utf-16-le", "surrogatepass")
        self.emu.mem.write(buf, Mutf8.encode(region))
        return None

    def _get_primitive_array_critical(self) -> int | None:
        return self._get_array_elements("B")

    def _release_primitive_array_critical(self) -> None:
        self._release_array_elements("B")

    def _get_string_critical(self) -> int | None:
        return self._get_string_chars()

    def _release_string_critical(self) -> None:
        self._release_string_chars()

    def _new_weak_global_ref(self) -> int | None:
        obj = self.dvm.get(self._arg(1))
        return self.dvm.add_weak_global(obj) if obj is not None else 0

    def _delete_weak_global_ref(self) -> int | None:
        self.dvm.delete_weak_global(self._arg(1))
        return None

    def _exception_check(self) -> int | None:
        return 1 if self._pending_exception is not None else 0

    def _new_direct_byte_buffer(self) -> int | None:
        address, capacity = self._arg(1), self._arg(2)
        ref = self.dvm.add_local(JavaObject(JavaClass("java/nio/DirectByteBuffer"), (address, capacity)))
        self.log.jni_call("NewDirectByteBuffer", f"{address:#x}+{capacity:#x}", ref)  # a common in-memory-DEX carrier
        return ref

    def _get_direct_buffer_address(self) -> int | None:
        obj = self.dvm.get(self._arg(1))
        address = obj.value[0] if isinstance(obj, JavaObject) and isinstance(obj.value, tuple) else 0
        self.log.jni_call("GetDirectBufferAddress", hex(self._arg(1)), address)
        return address

    def _get_direct_buffer_capacity(self) -> int | None:
        obj = self.dvm.get(self._arg(1))
        capacity = obj.value[1] if isinstance(obj, JavaObject) and isinstance(obj.value, tuple) else -1
        self.log.jni_call("GetDirectBufferCapacity", hex(self._arg(1)), capacity)
        return capacity

    def _get_object_ref_type(self) -> int | None:
        return self.dvm.ref_type(self._arg(1))

    def _get_module(self) -> int | None:
        raise NotImplementedError("JNIEnv.GetModule: no module model")

    def _is_virtual_thread(self) -> int | None:
        return 0

    def _get_string_utf_length_as_long(self) -> int | None:
        return len(Mutf8.encode(self._str(self._arg(1))))
