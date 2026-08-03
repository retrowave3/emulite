from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from emulite.memory.memory_manager import MemoryManager


class NativePointer:
    """An integer-like guest pointer with convenient typed memory accessors."""

    __slots__ = ("_mem", "address")

    def __init__(self, mem: MemoryManager, address: int) -> None:
        self._mem = mem
        self.address = address & ((1 << (mem.arch.pointer_size * 8)) - 1)

    def __int__(self) -> int:
        return self.address

    __index__ = __int__

    def __bool__(self) -> bool:
        return self.address != 0

    def __eq__(self, other: object) -> bool:
        return int(self) == int(other) if isinstance(other, (NativePointer, int)) else NotImplemented

    def __hash__(self) -> int:
        return hash(self.address)

    def __repr__(self) -> str:
        return f"NativePointer(0x{self.address:x})"

    def __format__(self, format_spec: str) -> str:
        return format(self.address, format_spec)

    @property
    def is_null(self) -> bool:
        return self.address == 0

    def add(self, offset: int) -> NativePointer:
        return NativePointer(self._mem, self.address + offset)

    __add__ = add

    def read(self, size: int, offset: int = 0) -> bytes:
        return self._mem.read(self.address + offset, size)

    def read_u8(self, offset: int = 0) -> int:
        return self._mem.read_u8(self.address + offset)

    def read_u16(self, offset: int = 0) -> int:
        return self._mem.read_u16(self.address + offset)

    def read_u32(self, offset: int = 0) -> int:
        return self._mem.read_u32(self.address + offset)

    def read_u64(self, offset: int = 0) -> int:
        return self._mem.read_u64(self.address + offset)

    def read_s8(self, offset: int = 0) -> int:
        return self._mem.read_s8(self.address + offset)

    def read_s16(self, offset: int = 0) -> int:
        return self._mem.read_s16(self.address + offset)

    def read_s32(self, offset: int = 0) -> int:
        return self._mem.read_s32(self.address + offset)

    def read_s64(self, offset: int = 0) -> int:
        return self._mem.read_s64(self.address + offset)

    def read_float(self, offset: int = 0) -> float:
        return self._mem.read_float(self.address + offset)

    def read_double(self, offset: int = 0) -> float:
        return self._mem.read_double(self.address + offset)

    def read_pointer(self, offset: int = 0) -> NativePointer:
        return NativePointer(self._mem, self._mem.read_ptr(self.address + offset))  # 8 bytes arm64, 4 arm32

    def read_cstr_bytes(self, offset: int = 0) -> bytes:
        return self._mem.read_cstr_bytes(self.address + offset)

    def read_cstr(self, offset: int = 0) -> str:
        return self._mem.read_cstr(self.address + offset)

    def write(self, data: bytes | bytearray | memoryview, offset: int = 0) -> None:
        self._mem.write(self.address + offset, data)

    def write_u8(self, value: int, offset: int = 0) -> None:
        self._mem.write_u8(self.address + offset, value)

    def write_u16(self, value: int, offset: int = 0) -> None:
        self._mem.write_u16(self.address + offset, value)

    def write_u32(self, value: int, offset: int = 0) -> None:
        self._mem.write_u32(self.address + offset, value)

    def write_u64(self, value: int, offset: int = 0) -> None:
        self._mem.write_u64(self.address + offset, value)

    def write_s8(self, value: int, offset: int = 0) -> None:
        self._mem.write_s8(self.address + offset, value)

    def write_s16(self, value: int, offset: int = 0) -> None:
        self._mem.write_s16(self.address + offset, value)

    def write_s32(self, value: int, offset: int = 0) -> None:
        self._mem.write_s32(self.address + offset, value)

    def write_s64(self, value: int, offset: int = 0) -> None:
        self._mem.write_s64(self.address + offset, value)

    def write_float(self, value: float, offset: int = 0) -> None:
        self._mem.write_float(self.address + offset, value)

    def write_double(self, value: float, offset: int = 0) -> None:
        self._mem.write_double(self.address + offset, value)

    def write_pointer(self, target: NativePointer | int, offset: int = 0) -> None:
        self._mem.write_ptr(self.address + offset, int(target))

    def write_cstr(self, text: str, offset: int = 0) -> None:
        self._mem.write_cstr(self.address + offset, text)
