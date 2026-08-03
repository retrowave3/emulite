from __future__ import annotations

import os
import struct

from emulite.android.enums.auxv import Auxv
from emulite.common.errors import EmulatorCrashed
from emulite.common.log import Logger
from emulite.cpu.arch.base import Arch
from emulite.cpu.backend import RW, Backend, MemoryProtectionFlag
from emulite.memory.memory_region import MemoryRegion
from emulite.memory.native_pointer import NativePointer


class MemoryManager:
    """Own guest mappings and provide typed little-endian memory access."""

    def __init__(self, backend: Backend, arch: Arch, log: Logger) -> None:
        self._be = backend
        self._arch = arch
        self._layout = arch.layout
        self._reg = arch.registers
        self._log = log
        self._heap = self._layout.HEAP_BASE  # brk cursor
        self._heap_mapped_end = self._heap
        self._mmap = self._layout.MMAP_BASE  # anonymous-mmap cursor
        self._lib = self._layout.LIB_BASE  # module-placement cursor
        self._poison = self._layout.POISON_BASE  # unresolved-strong-symbol poison cursor (never mapped)
        self._errno_addr = 0
        self._regions: list[MemoryRegion] = []
        self.argc = 0
        self.argv_ptr = 0
        self.envp_ptr = 0

    @property
    def arch(self) -> Arch:
        return self._arch

    def map(self, address: int, size: int, perms: MemoryProtectionFlag = RW, label: str = "", replace: bool = False) -> None:
        """Map a fixed, page-aligned guest address range."""
        self._validate_address(address)
        if address % self._layout.PAGE_SIZE:
            raise ValueError(f"map address must be page-aligned: {address:#x}")
        size = self._validated_size(size, "map")
        self._validate_range(address, size, "map")
        if replace:  # MAP_FIXED semantics: discard any existing mapping
            self._unmap_overlap(address, address + size)  # in [address, address+size) before mapping over it
        self._be.mem_map(address, size, perms)
        self._record(address, size, perms, label)
        self._log.memory("map   %#x..%#x perms=%d %s", address, address + size, perms, label)

    def _unmap_overlap(self, base: int, end: int) -> None:
        for region in [region for region in self._regions if region.base < end and region.end > base]:
            lo, hi = max(region.base, base), min(region.end, end)
            self._be.mem_unmap(lo, hi - lo)
            self._carve(lo, hi)

    def protect(self, address: int, size: int, perms: MemoryProtectionFlag) -> None:
        """Change permissions for every page touched by the requested range."""
        self._validate_address(address)
        if size <= 0:
            raise ValueError(f"protect size must be positive: {size}")
        start = self._layout.page_align_down(address)
        size = self._layout.page_align_up(size + (address - start))
        address = start
        self._validate_range(address, size, "protect")
        self._be.mem_protect(address, size, perms)
        pieces = [(max(r.base, address), min(r.end, address + size), r.label) for r in self._regions if r.base < address + size and r.end > address]
        self._carve(address, address + size)
        for begin, end, label in pieces or [(address, address + size, "")]:
            self._regions.append(MemoryRegion(begin, end - begin, perms, label))
        self._regions.sort(key=lambda r: r.base)
        self._log.memory("prot  %#x..%#x perms=%d", address, address + size, perms)

    def unmap(self, address: int, size: int) -> None:
        """Unmap every page touched by the requested range."""
        self._validate_address(address)
        if size <= 0:
            raise ValueError(f"unmap size must be positive: {size}")
        start = self._layout.page_align_down(address)
        size = self._layout.page_align_up(size + (address - start))
        address = start
        self._validate_range(address, size, "unmap")
        self._be.mem_unmap(address, size)
        self._carve(address, address + size)
        self._log.memory("unmap %#x..%#x", address, address + size)

    def _carve(self, base: int, end: int) -> None:
        kept: list[MemoryRegion] = []
        for region in self._regions:
            if region.end <= base or region.base >= end:
                kept.append(region)
                continue
            if region.base < base:
                kept.append(MemoryRegion(region.base, base - region.base, region.perms, region.label))
            if region.end > end:
                kept.append(MemoryRegion(end, region.end - end, region.perms, region.label))
        self._regions = kept

    def _record(self, base: int, size: int, perms: MemoryProtectionFlag, label: str) -> None:
        self._carve(base, base + size)
        self._regions.append(MemoryRegion(base, size, perms, label))
        self._regions.sort(key=lambda r: r.base)

    def iter_regions(self) -> tuple[MemoryRegion, ...]:
        """Return an immutable snapshot of the currently tracked regions."""
        return tuple(self._regions)

    def find_region(self, address: int) -> MemoryRegion | None:
        return next((r for r in self._regions if r.contains(address)), None)

    def permission_at(self, address: int) -> MemoryProtectionFlag:
        region = self.find_region(address)
        return region.perms if region else MemoryProtectionFlag.NONE

    def mmap(self, size: int, perms: MemoryProtectionFlag = RW, label: str = "mmap") -> int:
        """Allocate a page-aligned range from the anonymous mapping arena."""
        need = self._validated_size(size, "mmap")
        hole = self._find_mmap_hole(need)
        if hole is not None:
            self.map(hole, need, perms, label)
            return hole
        end = self._mmap + need
        if end > self._layout.LIB_BASE:
            raise EmulatorCrashed(f"mmap arena exhausted: {size:#x} at {self._mmap:#x} would cross into LIB_BASE {self._layout.LIB_BASE:#x}")
        base, self._mmap = self._mmap, end
        self.map(base, need, perms, label)
        return base

    def _find_mmap_hole(self, need: int) -> int | None:
        cursor = self._layout.MMAP_BASE
        for region in sorted((r for r in self._regions if self._layout.MMAP_BASE <= r.base < self._mmap), key=lambda r: r.base):
            if region.base - cursor >= need:
                return cursor
            cursor = max(cursor, region.end)
        return cursor if self._mmap - cursor >= need else None

    def reserve_lib(self, size: int, align: int = 0) -> int:
        """Reserve an address range in the library arena without mapping it."""
        if size <= 0:
            raise ValueError(f"library reservation size must be positive: {size}")
        if align < 0 or (align and align & (align - 1)):
            raise ValueError(f"library alignment must be zero or a power of two: {align}")
        align = max(align, self._layout.PAGE_SIZE)
        base = (self._lib + align - 1) & ~(align - 1)
        end = base + self._layout.page_align_up(size) + self._layout.PAGE_SIZE
        if end > self._layout.RETURN_SENTINEL:
            raise EmulatorCrashed(f"library arena exhausted: {size:#x} at {self._lib:#x} would cross into RETURN_SENTINEL {self._layout.RETURN_SENTINEL:#x}")
        self._lib = end
        return base

    def poison_pointer(self, label: str = "") -> int:
        addr = self._poison
        self._poison += 16
        if self._poison >= self._layout.POISON_BASE + self._layout.PAGE_SIZE:
            self._poison = self._layout.POISON_BASE
        self._log.memory("poison %#x <- %s", addr, label)
        return addr

    def brk(self, addr: int = 0) -> int:
        """Query or update the process break while mapping complete backing pages."""
        if addr == 0:
            return self._heap
        if addr < self._layout.HEAP_BASE:
            raise ValueError(f"brk cannot move below HEAP_BASE {self._layout.HEAP_BASE:#x}: {addr:#x}")
        if addr > self._layout.MMAP_BASE:
            raise EmulatorCrashed(f"brk exhausted: {addr:#x} would cross into MMAP_BASE {self._layout.MMAP_BASE:#x}")
        mapped_end = self._layout.page_align_up(addr)
        if mapped_end > self._heap_mapped_end:
            self.map(self._heap_mapped_end, mapped_end - self._heap_mapped_end, RW, "heap")
        elif mapped_end < self._heap_mapped_end:
            self.unmap(mapped_end, self._heap_mapped_end - mapped_end)
        self._heap_mapped_end = mapped_end
        self._heap = addr
        return self._heap

    def setup_stack(self, argv: list[str], envp: list[str], auxv: list[tuple[int, int]], stack_guard: int) -> dict[int, int]:
        bottom = self._layout.STACK_TOP - self._layout.STACK_SIZE
        self.map(bottom, self._layout.STACK_SIZE, RW, "stack")
        top = self._layout.STACK_TOP - 0x100  # guard gap so reads near the top stay in-bounds

        def push(data: bytes, align: int = 1) -> int:
            nonlocal top
            top = (top - len(data)) & ~(align - 1)
            if top < bottom:
                raise EmulatorCrashed(f"initial stack data exceeds STACK_SIZE {self._layout.STACK_SIZE:#x}")
            self.write(top, data)
            return top

        random_ptr = push(struct.pack("<Q", stack_guard) + os.urandom(8), align=16)
        platform_ptr = push(self._arch.platform_string.encode("ascii") + b"\x00")
        argv_ptrs = [push(value.encode("utf-8") + b"\x00") for value in argv]
        envp_ptrs = [push(value.encode("utf-8") + b"\x00") for value in envp]

        resolved = dict(auxv)
        resolved[Auxv.AT_RANDOM] = random_ptr
        resolved[Auxv.AT_PLATFORM] = platform_ptr

        words = [len(argv), *argv_ptrs, 0, *envp_ptrs, 0]
        for at_type, at_value in resolved.items():
            words += [at_type, at_value]
        words += [Auxv.AT_NULL, 0]

        pointer_size = self._arch.pointer_size
        write_word = self.write_u64 if pointer_size == 8 else self.write_u32
        sp = (top - len(words) * pointer_size) & ~0xF
        if sp < bottom:
            raise EmulatorCrashed(f"initial stack table exceeds STACK_SIZE {self._layout.STACK_SIZE:#x}")
        for index, value in enumerate(words):
            write_word(sp + index * pointer_size, value)
        self.argc = len(argv)
        self.argv_ptr = sp + pointer_size
        self.envp_ptr = sp + pointer_size * (2 + len(argv))
        self._be.reg_write(self._reg.SP, sp)
        self._log.memory("stack %#x..%#x sp=%#x argc=%d envc=%d auxc=%d", bottom, self._layout.STACK_TOP, sp, len(argv), len(envp), len(resolved))
        return resolved

    def setup_tls(self, stack_guard: int) -> int:
        base = self.mmap(self._layout.TLS_SIZE, RW, "tls")
        self._errno_addr = base + 0x200
        self._arch.setup_tls(self._be, self, base, stack_guard, self._errno_addr)
        self._log.tls("tls @ %#x tls-reg set, canary=%#x", base, stack_guard)
        return base

    @property
    def errno_addr(self) -> int:
        return self._errno_addr

    def set_errno(self, value: int) -> None:
        if self._errno_addr:
            self.write_u32(self._errno_addr, value & 0xFFFFFFFF)

    def get_errno(self) -> int:
        return self.read_u32(self._errno_addr) if self._errno_addr else 0

    def ptr(self, address: int) -> NativePointer:
        return NativePointer(self, address)

    def read(self, address: int, size: int) -> bytes:
        return self._be.mem_read(address, size)

    def write(self, address: int, data: bytes | bytearray | memoryview) -> None:
        self._be.mem_write(address, bytes(data))

    def read_u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    def read_u64(self, address: int) -> int:
        return struct.unpack("<Q", self.read(address, 8))[0]

    def read_ptr(self, address: int) -> int:
        return self.read_u64(address) if self._arch.pointer_size == 8 else self.read_u32(address)

    def read_s32(self, address: int) -> int:
        return struct.unpack("<i", self.read(address, 4))[0]

    def read_s64(self, address: int) -> int:
        return struct.unpack("<q", self.read(address, 8))[0]

    def read_u8(self, address: int) -> int:
        return self.read(address, 1)[0]

    def read_u16(self, address: int) -> int:
        return struct.unpack("<H", self.read(address, 2))[0]

    def read_s8(self, address: int) -> int:
        return struct.unpack("<b", self.read(address, 1))[0]

    def read_s16(self, address: int) -> int:
        return struct.unpack("<h", self.read(address, 2))[0]

    def read_float(self, address: int) -> float:
        return struct.unpack("<f", self.read(address, 4))[0]

    def read_double(self, address: int) -> float:
        return struct.unpack("<d", self.read(address, 8))[0]

    def write_u8(self, address: int, value: int) -> None:
        self.write(address, bytes([value & 0xFF]))

    def write_u16(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<H", value & 0xFFFF))

    def write_u32(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def write_u64(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def write_ptr(self, address: int, value: int) -> None:
        (self.write_u64 if self._arch.pointer_size == 8 else self.write_u32)(address, value)

    def write_s8(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<b", value))

    def write_s16(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<h", value))

    def write_s32(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<i", value))

    def write_s64(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<q", value))

    def write_float(self, address: int, value: float) -> None:
        self.write(address, struct.pack("<f", value))

    def write_double(self, address: int, value: float) -> None:
        self.write(address, struct.pack("<d", value))

    def alloc(self, data: bytes | bytearray | memoryview, label: str = "alloc") -> int:
        addr = self.mmap(max(len(data), 1), label=label)
        self.write(addr, data)
        return addr

    def alloc_cstr(self, text: str) -> int:
        return self.alloc(text.encode("utf-8") + b"\x00", label="cstr")

    def read_cstr(self, address: int) -> str:
        return self.read_cstr_bytes(address).decode("utf-8", "replace")

    def read_cstr_bytes(self, address: int) -> bytes:
        max_length = 0x10000
        out = bytearray()
        while len(out) < max_length:
            current = address + len(out)
            chunk_size = min(self._layout.PAGE_SIZE - current % self._layout.PAGE_SIZE, max_length - len(out))
            try:
                chunk = self.read(current, chunk_size)
            except EmulatorCrashed:
                break
            nul = chunk.find(b"\x00")
            if nul != -1:
                out += chunk[:nul]
                break
            out += chunk
        return bytes(out)

    def write_cstr(self, address: int, text: str) -> None:
        self.write(address, text.encode("utf-8") + b"\x00")

    def _validate_address(self, address: int) -> None:
        if address < 0 or address >= 1 << (self._arch.pointer_size * 8):
            raise ValueError(f"address is outside the {self._arch.pointer_size * 8}-bit guest address space: {address:#x}")

    def _validated_size(self, size: int, operation: str) -> int:
        if size <= 0:
            raise ValueError(f"{operation} size must be positive: {size}")
        return self._layout.page_align_up(size)

    def _validate_range(self, address: int, size: int, operation: str) -> None:
        if address + size > 1 << (self._arch.pointer_size * 8):
            raise ValueError(f"{operation} range exceeds the {self._arch.pointer_size * 8}-bit guest address space: {address:#x}+{size:#x}")
