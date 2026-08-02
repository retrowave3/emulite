from __future__ import annotations

import struct
from collections.abc import Callable

from emulite.android.enums.errno import Errno
from emulite.common.errors import EmulatorCrashed, MissingSlot
from emulite.common.log import Logger
from emulite.cpu.backend import Backend, HookType
from emulite.memory import RX, MemoryLayout, MemoryManager


class SvcTrap:
    _STRIDE = 8
    _MAX_SLOTS = MemoryLayout.PAGE_SIZE // _STRIDE

    def __init__(self, backend: Backend, mem: MemoryManager, log: Logger):
        self._be = backend
        self._mem = mem
        self._arch = mem.arch
        self._reg = mem.arch.registers
        self._log = log
        self._slots: list[tuple[Callable[[], int | None], str] | None] = [None]
        self._free_slots: list[int] = []
        self._syscall: Callable[[], int | None] | None = None
        self._base = MemoryLayout.TRAMPOLINE_BASE
        mem.map(self._base, MemoryLayout.PAGE_SIZE, RX, "trampolines")
        backend.hook_add(HookType.INTR, self._on_interrupt)

    def set_syscall_handler(self, handler: Callable[[], int | None]) -> None:
        self._syscall = handler

    def alloc_slot(self, handler: Callable[[], int | None], name: str = "") -> int:
        """Allocate a guest-callable trampoline for ``handler``."""
        if self._free_slots:
            imm = self._free_slots.pop()
            self._slots[imm] = (handler, name)
        else:
            imm = len(self._slots)
            if imm > self._MAX_SLOTS:
                raise MissingSlot(f"trampoline page full ({self._MAX_SLOTS} slots) — free some via free_slot")
            self._slots.append((handler, name))
        addr = self._base + (imm - 1) * self._STRIDE
        self._mem.write(addr, struct.pack("<II", self._arch.encode_svc(imm), self._arch.ret_instruction))
        self._log.trap("slot #%d %s @ %#x", imm, name, addr)
        return addr

    def free_slot(self, addr: int) -> None:
        """Free a trampoline previously returned by :meth:`alloc_slot`."""
        offset = addr - self._base
        if offset < 0 or offset % self._STRIDE:
            raise MissingSlot(f"invalid bridge slot address {addr:#x}")
        imm = offset // self._STRIDE + 1
        if not 1 <= imm < len(self._slots) or self._slots[imm] is None:
            raise MissingSlot(f"bridge slot #{imm} at {addr:#x} is unallocated or already freed")
        self._slots[imm] = None
        self._free_slots.append(imm)

    def _on_interrupt(self, _uc: object, intno: int, _user: object = None) -> None:
        pc = self._be.reg_read(self._reg.PC)
        imm = self._arch.trapped_svc(self._be, self._mem, pc)
        if imm is None:
            raise EmulatorCrashed(f"unexpected interrupt intno={intno} at {pc:#x} (not an svc)")

        if imm == 0:
            result = self._syscall() if self._syscall else -Errno.ENOSYS
        else:
            slot = self._slots[imm] if imm < len(self._slots) else None
            if slot is None:
                raise MissingSlot(f"bridge slot #{imm} at {pc:#x} (unallocated or freed)")
            result = slot[0]()

        if result is not None:
            mask = (1 << (self._arch.pointer_size * 8)) - 1
            self._be.reg_write(self._reg.RET_REG, result & mask)
