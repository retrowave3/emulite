from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Callable

from emulite.android import cformat
from emulite.android.enums.errno import Errno
from emulite.android.structs.dl_info64 import DlInfo64
from emulite.android.structs.dl_phdr_info64 import DlPhdrInfo64
from emulite.common.errors import ElfFormatError, EmulatorCrashed
from emulite.common.log import LogLevel
from emulite.cpu.registers.arm64_reg import Arm64Reg
from emulite.loader import NativeModule
from emulite.memory.heap_allocator import HeapAllocator

if TYPE_CHECKING:
    from emulite.android_emulator64 import AndroidEmulator64


class AndroidLibcHooks64:
    _MAIN_HANDLE = 0x1
    _RTLD_DEFAULT = 0
    _RTLD_NEXT = 0xFFFFFFFFFFFFFFFF
    _PROP_VALUE_MAX = 92
    _LOG_LEVELS = {2: "V", 3: "D", 4: "I", 5: "W", 6: "E", 7: "F"}

    def __init__(self, emu: "AndroidEmulator64"):
        self._emu = emu
        self.heap = HeapAllocator(emu.mem)
        self._override: dict[str, int] = {}
        self._fallback: dict[str, int] = {}
        self._dl_error: str | None = None
        self._cstr_cache: dict[str, int] = {}
        self._phdr_iterations: list[dict] = []
        self._phdr_next_slot = 0
        self._phdr_info_pool: list[int] = []
        self._prop_foreach_iterations: list[dict] = []
        self._prop_foreach_slot = 0
        self._register_builtins()

    def _intern_cstr(self, text: str) -> int:
        addr = self._cstr_cache.get(text)
        if addr is None:
            addr = self.heap.malloc(len(text.encode("utf-8")) + 1)
            self._emu.mem.write_cstr(addr, text)
            self._cstr_cache[text] = addr
        return addr

    def register(self, name: str, fn: Callable, override: bool = True) -> int:
        slot = self._emu.trap.alloc_slot(lambda: fn(self._emu), f"libc:{name}")
        (self._override if override else self._fallback)[name] = slot
        return slot

    def resolve_override(self, name: str) -> int | None:
        return self._override.get(name)

    def resolve_fallback(self, name: str) -> int | None:
        return self._fallback.get(name)

    def hook_addr(self, name: str) -> int | None:
        return self._override.get(name) or self._fallback.get(name)

    def _register_builtins(self) -> None:
        for name, fn in {
            "malloc": self._malloc,
            "calloc": self._calloc,
            "realloc": self._realloc,
            "free": self._free,
            "memalign": self._memalign,
            "posix_memalign": self._posix_memalign,
            "aligned_alloc": self._aligned_alloc,
            "malloc_usable_size": self._malloc_usable_size,
            "dlopen": self._dlopen,
            "android_dlopen_ext": self._dlopen,
            "dlsym": self._dlsym,
            "dladdr": self._dladdr,
            "dlclose": self._dlclose,
            "dlerror": self._dlerror_get,
            "dl_iterate_phdr": self._dl_iterate_phdr,
            "__android_log_print": self._android_log_print,
            "__android_log_write": self._android_log_write,
            "__android_log_vprint": self._android_log_vprint,
            "__android_log_buf_write": self._android_log_buf_write,
            "__android_log_buf_print": self._android_log_buf_print,
            "__android_log_is_loggable": self._android_log_is_loggable,
            "__android_log_assert": self._android_log_assert,
            "getauxval": self._getauxval,
            "getenv": self._getenv,
            "__system_property_get": self._system_property_get,
            "__system_property_find": self._system_property_find,
            "__system_property_read": self._system_property_read,
            "__system_property_read_callback": self._system_property_read_callback,
            "__system_property_foreach": self._system_property_foreach,
            "__cxa_atexit": self._cxa_atexit,
            "__cxa_finalize": self._cxa_finalize,
            "__register_atfork": self._register_atfork,
            "__stack_chk_fail": self._stack_chk_fail,
            "__errno": self._errno,
            "abort": self._abort,
        }.items():
            self.register(name, fn)
        for name, fn in {
            "snprintf": self._snprintf,
            "sprintf": self._sprintf,
            "vsnprintf": self._vsnprintf,
            "vsprintf": self._vsprintf,
            "printf": self._printf,
            "fprintf": self._fprintf,
            "puts": self._puts,
        }.items():
            self.register(name, fn, override=False)

    def _malloc(self, emu: "AndroidEmulator64") -> int:
        size = emu.arg(0)
        addr = self.heap.malloc(size)
        return addr

    def _calloc(self, emu: "AndroidEmulator64") -> int:
        count, size = emu.arg(0), emu.arg(1)
        addr = self.heap.calloc(count, size)
        return addr

    def _realloc(self, emu: "AndroidEmulator64") -> int:
        ptr, size = emu.arg(0), emu.arg(1)
        addr = self.heap.realloc(ptr, size)
        return addr

    def _free(self, emu: "AndroidEmulator64") -> None:
        ptr = emu.arg(0)
        self.heap.free(ptr)
        return None

    def _memalign(self, emu: "AndroidEmulator64") -> int:
        alignment, size = emu.arg(0), emu.arg(1)
        addr = self.heap.memalign(alignment, size)
        emu.log.libc_call("memalign", f"{alignment}, {size}", addr)
        return addr

    def _posix_memalign(self, emu: "AndroidEmulator64") -> int:
        memptr, alignment, size = emu.arg(0), emu.arg(1), emu.arg(2)
        if alignment < 8 or (alignment & (alignment - 1)):
            emu.log.libc("posix_memalign(align=%d) => EINVAL", alignment, level=LogLevel.WARN)
            return Errno.EINVAL
        addr = self.heap.memalign(alignment, size)
        emu.mem.write_u64(memptr, addr)
        emu.log.libc_call("posix_memalign", f"align={alignment}, size={size}", addr)
        return 0

    def _aligned_alloc(self, emu: "AndroidEmulator64") -> int:
        alignment, size = emu.arg(0), emu.arg(1)
        if alignment == 0 or (alignment & (alignment - 1)) or size % alignment != 0:
            emu.log.libc("aligned_alloc(align=%d, size=%d) => NULL (invalid)", alignment, size, level=LogLevel.WARN)
            return 0
        addr = self.heap.memalign(alignment, size)
        emu.log.libc_call("aligned_alloc", f"{alignment}, {size}", addr)
        return addr

    def _malloc_usable_size(self, emu: "AndroidEmulator64") -> int:
        ptr = emu.arg(0)
        size = self.heap.usable_size(ptr)
        emu.log.libc_call("malloc_usable_size", f"{ptr:#x}", size)
        return size

    def _dlopen(self, emu: "AndroidEmulator64") -> int:
        name_ptr = emu.arg(0)
        if name_ptr == 0:
            emu.log.libc("dlopen(NULL) => %#x (main)", self._MAIN_HANDLE)
            return self._MAIN_HANDLE
        name = emu.mem.read_cstr(name_ptr)
        try:
            module = emu.loader.load(name)
        except (FileNotFoundError, OSError, ElfFormatError) as error:
            self._dl_error = f'dlopen failed: library "{name}" not found'
            emu.log.libc("dlopen(%r) => NULL (%s)", name, error, level=LogLevel.WARN)
            return 0
        emu.log.libc("dlopen(%r) => %#x", name, module.base)
        return module.base

    def _dlsym(self, emu: "AndroidEmulator64") -> int:
        handle, name_ptr = emu.arg(0), emu.arg(1)
        name = emu.mem.read_cstr(name_ptr)
        if handle == self._RTLD_NEXT:
            raise NotImplementedError(f"dlsym(RTLD_NEXT, {name!r}) is not supported yet")
        if handle in (self._RTLD_DEFAULT, self._MAIN_HANDLE):
            addr = emu.loader.resolve(name) or 0
        else:
            module = emu.loader.module_by_base(handle)
            addr = self._lookup_scoped(emu, module, name, set()) if module else 0
        if addr == 0:
            self._dl_error = f'dlsym failed: undefined symbol "{name}"'
        emu.log.libc_call("dlsym", f"{handle:#x}, {name!r}", addr)
        return addr

    def _lookup_scoped(self, emu: "AndroidEmulator64", module: NativeModule, name: str, seen: set[str]) -> int:
        if module.name in seen:
            return 0
        seen.add(module.name)
        if name in module.exports:
            return module.exports[name]
        for dep_name in module.dependencies:
            dep = emu.loader.modules.get(dep_name)
            if dep is not None:
                found = self._lookup_scoped(emu, dep, name, seen)
                if found:
                    return found
        return 0

    def _dladdr(self, emu: "AndroidEmulator64") -> int:
        addr, info_ptr = emu.arg(0), emu.arg(1)
        module = emu.loader.module_at(addr)
        if module is None:
            emu.log.libc("dladdr(%#x) => 0 (no module)", addr)
            return 0
        nearest = max((s for s in module.exports.items() if s[1] <= addr), key=lambda s: s[1], default=None)
        DlInfo64(fname=self._intern_cstr(emu.vfs.device_path(module)), fbase=module.base, sname=self._intern_cstr(nearest[0]) if nearest else 0, saddr=nearest[1] if nearest else 0).write_to(
            emu.mem, info_ptr
        )
        emu.log.libc("dladdr(%#x) => 1 (%s in %s)", addr, nearest[0] if nearest else "?", module.name)
        return 1

    def _dl_iterate_phdr(self, emu: "AndroidEmulator64") -> "int | None":
        callback, data = emu.arg(0), emu.arg(1)
        ld = emu.linker_debug
        modules = [ld.main_image, *(m for m in emu.modules if m.phdr_addr), *ld.dep_images, ld.linker_image]
        if callback == 0:
            emu.log.libc("dl_iterate_phdr => 0 (no callback)")
            return 0
        emu.log.libc("dl_iterate_phdr(cb=%#x) over %d images", callback, len(modules))
        if not self._phdr_next_slot:
            self._phdr_next_slot = emu.trap.alloc_slot(lambda: self._dl_iterate_step(emu), "dl_iterate_phdr:next")
        depth = len(self._phdr_iterations)
        while len(self._phdr_info_pool) <= depth:
            self._phdr_info_pool.append(emu.mem.mmap(DlPhdrInfo64.SIZE, label="dl_phdr_info"))
        state = {"modules": modules, "index": 0, "callback": callback, "data": data, "saved_lr": emu.lr, "info": self._phdr_info_pool[depth]}
        self._phdr_iterations.append(state)
        self._dl_iterate_invoke(emu, state)
        return None

    def _dl_iterate_invoke(self, emu: "AndroidEmulator64", state: dict) -> None:
        module = state["modules"][state["index"]]
        info = state["info"]
        path = getattr(module, "device_path", None) or emu.vfs.device_path(module)
        DlPhdrInfo64(addr=module.base, name=self._intern_cstr(path), phdr=module.phdr_addr, phnum=module.phnum).write_to(emu.mem, info)
        emu.set_arg(0, info)
        emu.set_arg(1, DlPhdrInfo64.SIZE)
        emu.set_arg(2, state["data"])
        emu.lr = self._phdr_next_slot
        emu.pc = state["callback"]

    def _dl_iterate_step(self, emu: "AndroidEmulator64") -> None:
        state = self._phdr_iterations[-1]
        result = emu.ret
        if result != 0 or state["index"] + 1 >= len(state["modules"]):
            self._phdr_iterations.pop()
            emu.ret = result
            emu.pc = state["saved_lr"]
            return
        state["index"] += 1
        self._dl_iterate_invoke(emu, state)

    def _system_property_foreach(self, emu: "AndroidEmulator64") -> "int | None":
        callback, cookie = emu.arg(0), emu.arg(1)
        if callback == 0:
            emu.log.libc("__system_property_foreach => 0 (no callback)")
            return 0
        infos = [info for info in (emu.device.find(name) for name in sorted(emu.device.properties)) if info]
        emu.log.libc("__system_property_foreach(cb=%#x) over %d properties", callback, len(infos))
        if not infos:
            return 0
        if not self._prop_foreach_slot:
            self._prop_foreach_slot = emu.trap.alloc_slot(lambda: self._prop_foreach_step(emu), "__system_property_foreach:next")
        state = {"infos": infos, "index": 0, "callback": callback, "cookie": cookie, "saved_lr": emu.lr}
        self._prop_foreach_iterations.append(state)
        self._prop_foreach_invoke(emu, state)
        return None

    def _prop_foreach_invoke(self, emu: "AndroidEmulator64", state: dict) -> None:
        emu.set_arg(0, state["infos"][state["index"]])  # const prop_info*
        emu.set_arg(1, state["cookie"])
        emu.lr = self._prop_foreach_slot
        emu.pc = state["callback"]

    def _prop_foreach_step(self, emu: "AndroidEmulator64") -> None:
        state = self._prop_foreach_iterations[-1]
        if state["index"] + 1 >= len(state["infos"]):
            self._prop_foreach_iterations.pop()
            emu.ret = 0
            emu.pc = state["saved_lr"]
            return
        state["index"] += 1
        self._prop_foreach_invoke(emu, state)

    def _dlclose(self, emu: "AndroidEmulator64") -> int:
        emu.log.libc("dlclose(%#x) => 0 (kept loaded)", emu.arg(0))
        return 0

    def _dlerror_get(self, emu: "AndroidEmulator64") -> int:
        if not self._dl_error:
            emu.log.libc("dlerror() => NULL (no error)")
            return 0
        addr = self._intern_cstr(self._dl_error)
        emu.log.libc("dlerror() => %r", self._dl_error)
        self._dl_error = None
        return addr

    def _getauxval(self, emu: "AndroidEmulator64") -> int:
        at_type = emu.arg(0)
        value = emu.auxv.get(at_type, 0)
        emu.log.libc_call("getauxval", str(at_type), value)
        return value

    def _getenv(self, emu: "AndroidEmulator64") -> int:
        name = emu.mem.read_cstr(emu.arg(0))
        value = emu.profile.environment_variables.get(name)
        if value is None:
            emu.log.libc("getenv(%r) => NULL", name)
            return 0
        addr = self._intern_cstr(value)
        emu.log.libc("getenv(%r) => %r", name, value)
        return addr

    @staticmethod
    def _prop_value_bytes(value: str) -> bytes:
        raw = value.encode("utf-8")[: AndroidLibcHooks64._PROP_VALUE_MAX - 1]
        return raw.decode("utf-8", "ignore").encode("utf-8")

    def _system_property_get(self, emu: "AndroidEmulator64") -> int:
        name_ptr, value_ptr = emu.arg(0), emu.arg(1)
        name = emu.mem.read_cstr(name_ptr)
        raw = self._prop_value_bytes(emu.device.getprop(name))
        emu.mem.write(value_ptr, raw + b"\x00")
        emu.log.libc("__system_property_get(%r) => %r", name, raw.decode("utf-8"))
        return len(raw)

    def _system_property_find(self, emu: "AndroidEmulator64") -> int:
        name = emu.mem.read_cstr(emu.arg(0))
        info = emu.device.find(name)
        emu.log.libc("__system_property_find(%r) => %#x", name, info)
        return info

    def _system_property_read(self, emu: "AndroidEmulator64") -> int:
        info, name_out, value_out = emu.arg(0), emu.arg(1), emu.arg(2)
        found = emu.device.name_value(info)
        if found is None:
            emu.log.libc("__system_property_read(%#x) => 0 (no such prop_info)", info)
            return 0
        name, value = found
        raw = self._prop_value_bytes(value)
        if name_out:
            emu.mem.write(name_out, name.encode("utf-8")[:31] + b"\x00")
        if value_out:
            emu.mem.write(value_out, raw + b"\x00")
        emu.log.libc("__system_property_read(%r) => %r", name, raw.decode("utf-8"))
        return len(raw)

    def _system_property_read_callback(self, emu: "AndroidEmulator64") -> "int | None":
        info, callback, cookie = emu.arg(0), emu.arg(1), emu.arg(2)
        found = emu.device.read_info(info)
        if found is None or callback == 0:
            emu.log.libc("__system_property_read_callback(%#x, cb=%#x) => noop (no prop or NULL cb)", info, callback)
            return None
        name, value, serial = found
        emu.set_arg(0, cookie)
        emu.set_arg(1, self._intern_cstr(name))
        emu.set_arg(2, self._intern_cstr(value))
        emu.set_arg(3, serial)
        emu.log.libc("__system_property_read_callback(%r) -> cb %#x", name, callback)
        emu.pc = callback
        return None

    def _log_record(self, emu: "AndroidEmulator64", priority: int, tag: str, message: str) -> int:
        emu.log.libc("[%s/%s] %s", self._LOG_LEVELS.get(priority, "?"), tag, message, level=LogLevel.INFO)
        return max(len(message.encode("utf-8")), 1)

    def _android_log_print(self, emu: "AndroidEmulator64") -> int:
        priority, tag_ptr, fmt_ptr = emu.arg(0), emu.arg(1), emu.arg(2)
        tag = emu.mem.read_cstr(tag_ptr) if tag_ptr else "?"
        message = cformat.RegisterArgs64(emu, 3).format(emu.mem.read_cstr(fmt_ptr)) if fmt_ptr else ""
        return self._log_record(emu, priority, tag, message)

    def _android_log_write(self, emu: "AndroidEmulator64") -> int:
        priority, tag_ptr, text_ptr = emu.arg(0), emu.arg(1), emu.arg(2)
        tag = emu.mem.read_cstr(tag_ptr) if tag_ptr else "?"
        text = emu.mem.read_cstr(text_ptr) if text_ptr else ""
        return self._log_record(emu, priority, tag, text)

    def _android_log_vprint(self, emu: "AndroidEmulator64") -> int:
        priority, tag_ptr, fmt_ptr, ap = emu.arg(0), emu.arg(1), emu.arg(2), emu.arg(3)
        tag = emu.mem.read_cstr(tag_ptr) if tag_ptr else "?"
        message = cformat.VaListArgs64(emu, ap).format(emu.mem.read_cstr(fmt_ptr)) if fmt_ptr else ""
        return self._log_record(emu, priority, tag, message)

    def _android_log_buf_write(self, emu: "AndroidEmulator64") -> int:
        priority, tag_ptr, text_ptr = emu.arg(1), emu.arg(2), emu.arg(3)
        tag = emu.mem.read_cstr(tag_ptr) if tag_ptr else "?"
        text = emu.mem.read_cstr(text_ptr) if text_ptr else ""
        return self._log_record(emu, priority, tag, text)

    def _android_log_buf_print(self, emu: "AndroidEmulator64") -> int:
        priority, tag_ptr, fmt_ptr = emu.arg(1), emu.arg(2), emu.arg(3)
        tag = emu.mem.read_cstr(tag_ptr) if tag_ptr else "?"
        message = cformat.RegisterArgs64(emu, 4).format(emu.mem.read_cstr(fmt_ptr)) if fmt_ptr else ""
        return self._log_record(emu, priority, tag, message)

    def _android_log_is_loggable(self, emu: "AndroidEmulator64") -> int:
        emu.log.libc("__android_log_is_loggable => 1")
        return 1

    def _android_log_assert(self, emu: "AndroidEmulator64") -> int:
        cond_ptr, tag_ptr, fmt_ptr = emu.arg(0), emu.arg(1), emu.arg(2)
        cond = emu.mem.read_cstr(cond_ptr) if cond_ptr else "null"
        tag = emu.mem.read_cstr(tag_ptr) if tag_ptr else "?"
        fmt = cformat.RegisterArgs64(emu, 3).format(emu.mem.read_cstr(fmt_ptr)) if fmt_ptr else ""
        emu.log.crash("__android_log_assert [%s] %s: %s", tag, cond, fmt)
        raise EmulatorCrashed(f"__android_log_assert: [{tag}] {cond}: {fmt}")

    def _emit_formatted(self, emu: "AndroidEmulator64", buf: int, size: int, text: str, name: str) -> int:
        encoded = text.encode("utf-8")
        if buf and size:
            written = min(len(encoded), size - 1)
            emu.mem.write(buf, encoded[:written] + b"\x00")
        emu.log.libc("%s => %r", name, text)
        return len(encoded)

    def _snprintf(self, emu: "AndroidEmulator64") -> int:
        buf, size, fmt = emu.arg(0), emu.arg(1), emu.arg(2)
        text = cformat.RegisterArgs64(emu, 3).format(emu.mem.read_cstr(fmt))
        return self._emit_formatted(emu, buf, size, text, "snprintf")

    def _sprintf(self, emu: "AndroidEmulator64") -> int:
        buf, fmt = emu.arg(0), emu.arg(1)
        text = cformat.RegisterArgs64(emu, 2).format(emu.mem.read_cstr(fmt))
        return self._emit_formatted(emu, buf, 1 << 62, text, "sprintf")

    def _vsnprintf(self, emu: "AndroidEmulator64") -> int:
        buf, size, fmt, ap = emu.arg(0), emu.arg(1), emu.arg(2), emu.arg(3)
        text = cformat.VaListArgs64(emu, ap).format(emu.mem.read_cstr(fmt))
        return self._emit_formatted(emu, buf, size, text, "vsnprintf")

    def _vsprintf(self, emu: "AndroidEmulator64") -> int:
        buf, fmt, ap = emu.arg(0), emu.arg(1), emu.arg(2)
        text = cformat.VaListArgs64(emu, ap).format(emu.mem.read_cstr(fmt))
        return self._emit_formatted(emu, buf, 1 << 62, text, "vsprintf")

    def _printf(self, emu: "AndroidEmulator64") -> int:
        text = cformat.RegisterArgs64(emu, 1).format(emu.mem.read_cstr(emu.arg(0)))
        sys.stdout.write(text)
        emu.log.libc("printf => %r", text)
        return len(text.encode("utf-8"))

    def _fprintf(self, emu: "AndroidEmulator64") -> int:
        text = cformat.RegisterArgs64(emu, 2).format(emu.mem.read_cstr(emu.arg(1)))
        sys.stdout.write(text)
        emu.log.libc("fprintf => %r", text)
        return len(text.encode("utf-8"))

    def _puts(self, emu: "AndroidEmulator64") -> int:
        text = emu.mem.read_cstr(emu.arg(0))
        sys.stdout.write(text + "\n")
        emu.log.libc("puts => %r", text)
        return len(text) + 1

    def _cxa_atexit(self, emu: "AndroidEmulator64") -> int:
        emu.log.libc("__cxa_atexit(fn=%#x) => 0", emu.arg(0))
        return 0

    def _cxa_finalize(self, emu: "AndroidEmulator64") -> int:
        emu.log.libc("__cxa_finalize(%#x) => 0", emu.arg(0))
        return 0

    def _register_atfork(self, emu: "AndroidEmulator64") -> int:
        emu.log.libc("__register_atfork() => 0 (no fork under emulation)")
        return 0

    def _stack_chk_fail(self, emu: "AndroidEmulator64") -> int:
        lr = emu.reg(Arm64Reg.LR)
        emu.log.crash("__stack_chk_fail: stack smashing detected (LR=%#x)", lr)
        raise EmulatorCrashed(f"__stack_chk_fail at LR={lr:#x}")

    def _errno(self, emu: "AndroidEmulator64") -> int:
        addr = emu.mem.errno_addr
        emu.log.libc("__errno() => %#x", addr)
        return addr

    def _abort(self, emu: "AndroidEmulator64") -> int:
        lr = emu.reg(Arm64Reg.LR)
        emu.log.crash("abort() called (LR=%#x)", lr)
        raise EmulatorCrashed(f"abort() at LR={lr:#x}")
