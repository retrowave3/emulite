from __future__ import annotations

import enum
import sys
from typing import Callable, Optional


class LogLevel(enum.IntEnum):
    TRACE = 0
    DEBUG = 1
    INFO = 2
    WARN = 3
    ERROR = 4
    CRITICAL = 5


class LogCategory(enum.IntFlag):
    NONE = 0
    Libc = 1 << 0
    JNI = 1 << 1
    Syscall = 1 << 2
    Memory = 1 << 3
    Hooks = 1 << 4
    VFS = 1 << 5
    TLS = 1 << 6
    Loader = 1 << 7
    DVM = 1 << 8
    Trap = 1 << 9
    Crash = 1 << 10

    # Handy presets.
    All = Libc | JNI | Syscall | Memory | Hooks | VFS | TLS | Loader | DVM | Trap | Crash
    Verbose = All
    Default = Loader | JNI | Libc | VFS | Crash
    Minimal = Crash


class Logger:
    def __init__(self, categories: LogCategory = LogCategory.Default, level: LogLevel = LogLevel.DEBUG, sink: Optional[Callable[[LogLevel, LogCategory, str], None]] = None):
        self.categories = categories
        self.min_level = level
        self.sink = sink if sink is not None else self._default_sink

    def is_enabled(self, category: LogCategory, level: LogLevel) -> bool:
        return self.sink is not None and level >= self.min_level and bool(self.categories & category)

    def enable(self, category: LogCategory) -> None:
        self.categories |= category

    def disable(self, category: LogCategory) -> None:
        self.categories &= ~category

    def _emit(self, category: LogCategory, level: LogLevel, msg: str, args: tuple) -> None:
        if not self.is_enabled(category, level):
            return
        self.sink(level, category, msg % args if args else msg)  # type: ignore[misc]

    def libc(self, msg: str, *args: object, level: LogLevel = LogLevel.DEBUG) -> None:
        self._emit(LogCategory.Libc, level, msg, args)

    def jni(self, msg: str, *args: object, level: LogLevel = LogLevel.DEBUG) -> None:
        self._emit(LogCategory.JNI, level, msg, args)

    def syscall(self, msg: str, *args: object, level: LogLevel = LogLevel.DEBUG) -> None:
        self._emit(LogCategory.Syscall, level, msg, args)

    def memory(self, msg: str, *args: object, level: LogLevel = LogLevel.DEBUG) -> None:
        self._emit(LogCategory.Memory, level, msg, args)

    def hooks(self, msg: str, *args: object, level: LogLevel = LogLevel.DEBUG) -> None:
        self._emit(LogCategory.Hooks, level, msg, args)

    def vfs(self, msg: str, *args: object, level: LogLevel = LogLevel.DEBUG) -> None:
        self._emit(LogCategory.VFS, level, msg, args)

    def tls(self, msg: str, *args: object, level: LogLevel = LogLevel.DEBUG) -> None:
        self._emit(LogCategory.TLS, level, msg, args)

    def loader(self, msg: str, *args: object, level: LogLevel = LogLevel.INFO) -> None:
        self._emit(LogCategory.Loader, level, msg, args)

    def dvm(self, msg: str, *args: object, level: LogLevel = LogLevel.DEBUG) -> None:
        self._emit(LogCategory.DVM, level, msg, args)

    def trap(self, msg: str, *args: object, level: LogLevel = LogLevel.DEBUG) -> None:
        self._emit(LogCategory.Trap, level, msg, args)

    def crash(self, msg: str, *args: object, level: LogLevel = LogLevel.ERROR) -> None:
        self._emit(LogCategory.Crash, level, msg, args)

    def jni_call(self, func: str, args: str, result: int) -> None:
        self._emit(LogCategory.JNI, LogLevel.DEBUG, "%s(%s) => %#x", (func, args, result))

    def syscall_call(self, name: str, nr: int, args: str, result: int) -> None:
        self._emit(LogCategory.Syscall, LogLevel.DEBUG, "%s(%d)(%s) => %d", (name, nr, args, result))

    def libc_call(self, func: str, args: str, result: int) -> None:
        self._emit(LogCategory.Libc, LogLevel.DEBUG, "%s(%s) => %#x", (func, args, result))

    def library_load(self, name: str, base: int, size: int) -> None:
        self._emit(LogCategory.Loader, LogLevel.INFO, "loaded %s @ %#x (size=%#x)", (name, base, size))

    def crash_event(self, reason: str, pc: int, details: str) -> None:
        self._emit(LogCategory.Crash, LogLevel.ERROR, "CRASH: %s at %#x - %s", (reason, pc, details))

    @staticmethod
    def _default_sink(level: LogLevel, category: LogCategory, text: str) -> None:
        print(f"{level.name:<5} [{category.name}] {text}", file=sys.stderr)
