from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from emulite.android.jni.enums.java_vm_function import JavaVMFunction
from emulite.android.jni.enums.jni_return_code import JNIReturnCode
from emulite.android.jni.jni_env import JNIEnv
from emulite.memory import MemoryLayout

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class JavaVM:
    """Guest JavaVM invocation table backed by the emulator's current JNI environment."""

    def __init__(self, emu: AndroidEmulatorBase):
        self.emu = emu
        self.log = emu.log
        self.pointer = MemoryLayout.JAVAVM_BASE
        JNIEnv._build_table(emu, self.pointer, self._handlers(), "JavaVM")

    def _handlers(self) -> dict[int, Callable[[], int | None]]:
        return {
            JavaVMFunction.DESTROY_JAVA_VM: self._destroy_java_vm,
            JavaVMFunction.ATTACH_CURRENT_THREAD: self._attach_current_thread,
            JavaVMFunction.DETACH_CURRENT_THREAD: self._detach_current_thread,
            JavaVMFunction.GET_ENV: self._get_env,
            JavaVMFunction.ATTACH_CURRENT_THREAD_AS_DAEMON: self._attach_current_thread_as_daemon,
        }

    def _destroy_java_vm(self) -> int:
        return JNIReturnCode.JNI_OK

    def _attach_current_thread(self) -> int:
        self.emu.mem.write_ptr(self.emu.arg(1), self.emu.jni.pointer)  # *env = JNIEnv*
        return JNIReturnCode.JNI_OK

    def _detach_current_thread(self) -> int:
        return JNIReturnCode.JNI_OK

    def _get_env(self) -> int:
        self.emu.mem.write_ptr(self.emu.arg(1), self.emu.jni.pointer)  # *env = JNIEnv*
        self.log.jni("GetEnv => %#x (JNI_OK)", self.emu.jni.pointer)
        return JNIReturnCode.JNI_OK

    def _attach_current_thread_as_daemon(self) -> int:
        self.emu.mem.write_ptr(self.emu.arg(1), self.emu.jni.pointer)
        return JNIReturnCode.JNI_OK
