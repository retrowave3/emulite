from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING, Callable

from emulite.common.errors import SymbolMissing
from emulite.cpu.backend import HookType
from emulite.hooks.call_event import CallEvent
from emulite.hooks.call_tracer import CallTracer
from emulite.hooks.hook_handle import HookHandle
from emulite.hooks.hook_status import HookStatus
from emulite.hooks.trace_info import TraceInfo
from emulite.hooks.tracer import Tracer

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class HookManager:
    def __init__(self, emu: "AndroidEmulatorBase"):
        self._emu = emu
        self._breakpoints: dict[int, list[Callable]] = {}
        self._code_hook: "int | None" = None

    def hook_address(
        self, address: int, callback: Callable[["AndroidEmulatorBase"], None]
    ) -> HookHandle:
        emu = self._emu
        self._breakpoints.setdefault(address, []).append(callback)
        if self._code_hook is None:

            def _dispatch(_uc: object, addr: int, _size: int, _user: object) -> None:
                for handler in list(self._breakpoints.get(addr, ())):
                    handler(emu)

            self._code_hook = emu.backend.hook_add(HookType.CODE, _dispatch)
            emu.backend.flush_tb()
        emu.log.hooks("hook_address @ %#x", address)

        def remove() -> None:
            handlers = self._breakpoints.get(address)
            if handlers and callback in handlers:
                handlers.remove(callback)
                if not handlers:
                    del self._breakpoints[address]
            if not self._breakpoints and self._code_hook is not None:
                emu.backend.hook_del(self._code_hook)
                self._code_hook = None
                emu.backend.flush_tb()

        return HookHandle(remove)

    def hook_code(
        self,
        callback: Callable[["AndroidEmulatorBase", int, int], None],
        start: "int | None" = None,
        end: "int | None" = None,
    ) -> HookHandle:
        emu = self._emu
        begin, finish = self._resolve_range(start, end)

        def _trace(_uc: object, address: int, size: int, _user: object) -> None:
            callback(emu, address, size)

        handle = emu.backend.hook_add(HookType.CODE, _trace, begin=begin, end=finish)
        emu.backend.flush_tb()
        emu.log.hooks("hook_code [%#x, %#x]", begin, finish)

        def remove() -> None:
            emu.backend.hook_del(handle)
            emu.backend.flush_tb()

        return HookHandle(remove)

    def hook_module(
        self,
        callback: Callable[["AndroidEmulatorBase", int, int], None],
        module_name: "str | None" = None,
    ) -> HookHandle:
        emu = self._emu
        installs: list[HookHandle] = []
        for module in emu.modules:
            if module_name and not fnmatch.fnmatch(module.name, module_name):
                continue
            installs.append(self.hook_code(callback, module.base, module.base + module.size - 1))
        if not installs:
            raise SymbolMissing(f"no loaded module matching {module_name!r} to hook")
        emu.log.hooks("hook_module %r over %d module(s)", module_name, len(installs))
        return HookHandle.combine(installs)

    def trace_code(
        self,
        callback: Callable[["AndroidEmulatorBase", "TraceInfo"], "bool | None"],
        start: "int | None" = None,
        end: "int | None" = None,
    ) -> HookHandle:
        tracer = Tracer(self._emu, callback, self._emu.disassembler)
        handle = self.hook_code(tracer.step, start, end)

        def remove() -> None:
            tracer.flush()
            handle.unhook()

        return HookHandle(remove)

    def trace_module(
        self,
        callback: Callable[["AndroidEmulatorBase", "TraceInfo"], "bool | None"],
        module_name: "str | None" = None,
    ) -> HookHandle:
        modules = [
            m for m in self._emu.modules if not module_name or fnmatch.fnmatch(m.name, module_name)
        ]
        if not modules:
            raise SymbolMissing(f"no loaded module matching {module_name!r} to trace")
        tracer = Tracer(self._emu, callback, self._emu.disassembler)
        installs = [self.hook_code(tracer.step, m.base, m.base + m.size - 1) for m in modules]
        self._emu.log.hooks("trace_module %r over %d module(s)", module_name, len(installs))
        combined = HookHandle.combine(installs)

        def remove() -> None:
            tracer.flush()
            combined.unhook()

        return HookHandle(remove)

    def hook_symbol(
        self,
        symbol: str,
        on_call: Callable[["AndroidEmulatorBase"], "HookStatus | None"],
        post_call: "Callable[[AndroidEmulatorBase], None] | None" = None,
        module_name: "str | None" = None,
    ) -> HookHandle:
        emu = self._emu
        installs: list[HookHandle] = []
        for module in emu.modules:
            if module_name and not fnmatch.fnmatch(module.name, module_name):
                continue
            for slot, name in module.get_import_relocations():
                if name == symbol:
                    installs.append(
                        self._install_got(module.name, symbol, slot, on_call, post_call)
                    )
        if not installs:
            raise SymbolMissing(f"no import {symbol!r} to hook (modules matching {module_name!r})")
        emu.log.hooks("hook_symbol %s in %d slot(s)", symbol, len(installs))
        return HookHandle.combine(installs)

    def _install_got(
        self,
        module_name: str,
        symbol: str,
        slot: int,
        on_call: Callable,
        post_call: "Callable | None",
    ) -> HookHandle:
        emu = self._emu
        reg = emu.arch.registers
        original = emu.mem.read_ptr(slot)
        saved_lr: list[int] = []

        def after_handler() -> None:
            saved = saved_lr.pop()
            try:
                post_call(emu)
            finally:
                emu.set_reg(reg.LR, saved)

        after_tramp = (
            emu.trap.alloc_slot(after_handler, f"hookret:{module_name}:{symbol}")
            if post_call
            else 0
        )

        def on_handler() -> "int | None":
            status = on_call(emu)
            if status is None or status.call_original:
                if post_call:
                    saved_lr.append(emu.reg(reg.LR))
                    emu.set_reg(reg.LR, after_tramp)
                emu.set_reg(reg.PC, original)
            return None

        trampoline = emu.trap.alloc_slot(on_handler, f"hook:{module_name}:{symbol}")
        emu.mem.write_ptr(slot, trampoline)
        emu.log.hooks("hook_symbol %s @ GOT %#x (orig %#x)", symbol, slot, original)

        def remove() -> None:
            emu.mem.write_ptr(slot, original)
            emu.trap.free_slot(trampoline)
            if after_tramp:
                emu.trap.free_slot(after_tramp)

        return HookHandle(remove)

    def replace(
        self,
        address: int,
        on_call: Callable[["AndroidEmulatorBase"], "HookStatus | None"],
        post_call: "Callable[[AndroidEmulatorBase], None] | None" = None,
    ) -> HookHandle:
        emu = self._emu
        reg = emu.arch.registers
        saved_lr: list[int] = []

        def after_handler() -> None:
            saved = saved_lr.pop()
            try:
                post_call(emu)
            finally:
                emu.set_reg(reg.LR, saved)

        after_tramp = (
            emu.trap.alloc_slot(after_handler, f"replaceret:{address:#x}") if post_call else 0
        )

        def on_entry(e: "AndroidEmulatorBase") -> None:
            status = on_call(e)
            if status is None or status.call_original:
                if post_call:
                    saved_lr.append(e.reg(reg.LR))
                    e.set_reg(reg.LR, after_tramp)
                return
            e.set_reg(reg.PC, e.reg(reg.LR))

        handle = self.hook_address(address, on_entry)
        emu.log.hooks("replace @ %#x (post_call=%s)", address, post_call is not None)

        def remove() -> None:
            handle.unhook()
            if after_tramp:
                emu.trap.free_slot(after_tramp)

        return HookHandle(remove)

    def hook_memory(
        self,
        callback: Callable[["AndroidEmulatorBase", str, int, int, int], "bool | None"],
        start: "int | None" = None,
        end: "int | None" = None,
        reads: bool = True,
        writes: bool = True,
    ) -> HookHandle:
        emu = self._emu
        if not reads and not writes:
            raise ValueError("hook_memory requires reads=True, writes=True, or both")
        begin, finish = self._resolve_range(start, end)
        installs: list[HookHandle] = []
        if reads:

            def _on_read(
                _uc: object, _access: int, address: int, size: int, value: int, _user: object
            ) -> None:
                if callback(emu, "read", address, size, value) is False:
                    emu.stop()

            installs.append(self._install_mem(HookType.MEM_READ, _on_read, begin, finish))
        if writes:

            def _on_write(
                _uc: object, _access: int, address: int, size: int, value: int, _user: object
            ) -> None:
                if callback(emu, "write", address, size, value) is False:
                    emu.stop()

            installs.append(self._install_mem(HookType.MEM_WRITE, _on_write, begin, finish))
        emu.log.hooks("hook_memory [%#x, %#x] reads=%s writes=%s", begin, finish, reads, writes)
        return HookHandle.combine(installs)

    def watchpoint(
        self,
        address: int,
        callback: Callable[["AndroidEmulatorBase", str, int, int, int], "bool | None"],
        length: int = 8,
        reads: bool = True,
        writes: bool = True,
    ) -> HookHandle:
        if length <= 0:
            raise ValueError("watchpoint length must be positive")
        return self.hook_memory(
            callback, start=address, end=address + length - 1, reads=reads, writes=writes
        )

    def hook_mem_fault(
        self, callback: Callable[["AndroidEmulatorBase", int, int], "bool"]
    ) -> HookHandle:
        emu = self._emu

        def _on_fault(
            _uc: object, _access: int, address: int, size: int, _value: int, _user: object
        ) -> bool:
            return bool(callback(emu, address, size))

        handle = self._install_mem(HookType.MEM_FAULT, _on_fault, 1, 0)
        emu.log.hooks("hook_mem_fault installed")
        return handle

    def _install_mem(
        self, hook_type: HookType, wrapper: Callable, start: int, end: int
    ) -> HookHandle:
        emu = self._emu
        handle = emu.backend.hook_add(hook_type, wrapper, begin=start, end=end)
        return HookHandle(lambda: emu.backend.hook_del(handle))

    def call_trace(
        self,
        callback: Callable[["AndroidEmulatorBase", "CallEvent"], "bool | None"],
        module_name: "str | None" = None,
        *,
        start: "int | None" = None,
        end: "int | None" = None,
    ) -> HookHandle:
        tracer = CallTracer(self._emu, callback, self._emu.disassembler)
        if start is not None or end is not None:
            handle = self.hook_code(tracer.step, start, end)
        else:
            handle = self.hook_module(tracer.step, module_name)

        def remove() -> None:
            tracer.flush()
            handle.unhook()

        return HookHandle(remove)

    def _resolve_range(self, start: "int | None", end: "int | None") -> tuple[int, int]:
        if start is None and end is None:
            return 1, 0
        maximum = (1 << (self._emu.arch.pointer_size * 8)) - 1
        begin = 1 if start is None else start
        finish = maximum if end is None else end
        if not 0 <= begin <= maximum or not 0 <= finish <= maximum:
            raise ValueError(
                f"hook range must fit in {self._emu.arch.pointer_size * 8}-bit address space"
            )
        if begin > finish:
            raise ValueError("hook range start must not exceed end")
        return begin, finish
