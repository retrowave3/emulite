from __future__ import annotations

from emulite.cpu.backend import RW
from emulite.memory.memory_manager import MemoryManager


class HeapAllocator:
    _ARENA_SIZE = 0x0400_0000
    _ALIGN = 16

    @staticmethod
    def _round_up(value: int, alignment: int) -> int:
        return (value + alignment - 1) & ~(alignment - 1)

    def __init__(self, mem: MemoryManager):
        self._mem = mem
        self._base = mem.mmap(self._ARENA_SIZE, RW, "malloc-arena")
        self._cursor = self._base
        self._end = self._base + self._ARENA_SIZE
        self._sizes: dict[int, int] = {}
        self._free: dict[int, int] = {}

    def _is_foreign(self, addr: int) -> bool:
        return addr != 0 and not (self._base <= addr < self._end)

    def malloc(self, size: int) -> int:
        if size == 0:
            return 0
        need = self._round_up(size, self._ALIGN)
        addr = self._take_free(need)
        if addr is None:
            if need > self._ARENA_SIZE or self._cursor + need > self._end:
                return 0
            addr = self._cursor
            self._cursor += need
        self._sizes[addr] = size
        return addr

    def _take_free(self, need: int) -> "int | None":
        for addr in sorted(self._free):
            block = self._free[addr]
            if block >= need:
                del self._free[addr]
                if block - need >= self._ALIGN:
                    self._free[addr + need] = block - need
                return addr
        return None

    def calloc(self, count: int, size: int) -> int:
        total = count * size
        if total > (1 << (self._mem.arch.pointer_size * 8)) - 1:
            return 0
        addr = self.malloc(total)
        if addr:
            self._mem.write(addr, b"\x00" * total)
        return addr

    def realloc(self, addr: int, size: int) -> int:
        if addr == 0:
            return self.malloc(size)
        if self._is_foreign(addr):
            raise ValueError(f"realloc of foreign pointer {addr:#x} (not from our arena)")
        if size == 0:
            self.free(addr)
            return 0
        old_size = self._sizes.get(addr, 0)
        new_addr = self.malloc(size)
        if new_addr and old_size:
            self._mem.write(new_addr, self._mem.read(addr, min(old_size, size)))
        if new_addr:
            self.free(addr)
        return new_addr

    def free(self, addr: int) -> None:
        size = self._sizes.pop(addr, None)
        if size is not None:
            self._insert_free(addr, self._round_up(size, self._ALIGN))

    def _insert_free(self, addr: int, size: int) -> None:
        if addr + size in self._free:
            size += self._free.pop(addr + size)
        for prev in list(self._free):
            if prev + self._free[prev] == addr:
                size += self._free.pop(prev)
                addr = prev
                break
        if addr + size == self._cursor:
            self._cursor = addr
        else:
            self._free[addr] = size

    def usable_size(self, addr: int) -> int:
        if self._is_foreign(addr):
            raise ValueError(f"malloc_usable_size of foreign pointer {addr:#x}")
        size = self._sizes.get(addr)
        return self._round_up(size, self._ALIGN) if size is not None else 0

    def memalign(self, alignment: int, size: int) -> int:
        if alignment < 1 or (alignment & (alignment - 1)):
            raise ValueError(f"memalign: alignment {alignment} is not a power of two")
        alignment = max(alignment, self._ALIGN)
        need = self._round_up(size, self._ALIGN)
        start = self._round_up(self._cursor, alignment)
        if need > self._ARENA_SIZE or start + need > self._end:
            return 0
        if start > self._cursor:
            self._free[self._cursor] = start - self._cursor
        self._cursor = start + need
        self._sizes[start] = size
        return start
