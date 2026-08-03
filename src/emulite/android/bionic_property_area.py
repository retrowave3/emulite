from __future__ import annotations

from emulite.cpu.flags.memory_protection_flag import MemoryProtectionFlag
from emulite.memory import MemoryManager


class AndroidPropertyArea:
    """Bionic-compatible property records stored in guest memory."""

    SERIAL, VALUE, NAME = 0, 4, 96  # prop_info field offsets
    PROP_VALUE_MAX = 92  # sizeof(prop_info.value)
    LONG_FLAG = 0x10000  # serial & (1 << 16)
    LONG_OFFSET = 60  # prop_info.long_property.offset
    _LONG_MESSAGE = b"Read with __system_property_read_callback"
    BT_NAMELEN, BT_PROP, BT_NAME = 0, 4, 20
    _PA_MAGIC = 0x504F5250  # "PROP"
    _PA_VERSION = 0xFC6ED0AB  # PROP_AREA_VERSION
    _PA_DATA = 128  # sizeof(prop_area)
    _REGION_BYTES = 0x40000

    def __init__(self, mem: MemoryManager):
        self._mem = mem
        self._base = mem.mmap(self._REGION_BYTES, perms=MemoryProtectionFlag.READ, label="properties")
        self._cursor = self._PA_DATA
        self._by_name: dict[str, int] = {}  # name -> prop_info*
        self._infos: set[int] = set()
        mem.write_u32(self._base + 8, self._PA_MAGIC)  # prop_area.magic_
        mem.write_u32(self._base + 12, self._PA_VERSION)  # prop_area.version_

    @property
    def region_label(self) -> str:
        return "properties"

    def intern(self, name: str, value: str) -> int:
        info = self._by_name.get(name)
        if info is None:
            info = self._write_info(name, value)
            self._by_name[name] = info
            self._infos.add(info)
        return info

    def invalidate(self, name: str) -> None:
        self._by_name.pop(name, None)

    def read(self, info: int) -> tuple[str, str, int] | None:
        if info not in self._infos:
            return None
        serial = self._mem.read_u32(info + self.SERIAL)
        name = self._mem.read_cstr(info + self.NAME)
        if serial & self.LONG_FLAG:
            offset = self._mem.read_u32(info + self.LONG_OFFSET)
            value = self._mem.read_cstr(info + self.LONG_OFFSET + offset)
        else:
            value = self._mem.read_cstr(info + self.VALUE)
        return (name, value, serial)

    def _write_info(self, name: str, value: str) -> int:
        raw_name = name.encode("utf-8")
        raw_value = value.encode("utf-8")
        leaf = raw_name.rsplit(b".", 1)[-1]
        info_offset = self._align4(self._cursor + self.BT_NAME + len(leaf) + 1)
        struct_bytes = self.NAME + len(raw_name) + 1
        info_bytes = struct_bytes if len(raw_value) < self.PROP_VALUE_MAX else self._align8(struct_bytes) + len(raw_value) + 1
        end = self._align8(info_offset + info_bytes)
        if end > self._REGION_BYTES:
            raise MemoryError(f"prop_info area exhausted at {end:#x} of {self._REGION_BYTES:#x}")
        info = self._base + self._write_leaf_bt(raw_name)
        if len(raw_value) < self.PROP_VALUE_MAX:
            self._mem.write_u32(info + self.SERIAL, len(raw_value) << 24)
            self._mem.write(info + self.VALUE, raw_value + b"\x00")
            self._mem.write(info + self.NAME, raw_name + b"\x00")
            self._advance(struct_bytes)
        else:
            long_at = self._align8(struct_bytes)
            self._mem.write_u32(info + self.SERIAL, (len(raw_value) << 24) | self.LONG_FLAG)
            self._mem.write(info + self.VALUE, self._LONG_MESSAGE + b"\x00")
            self._mem.write_u32(info + self.LONG_OFFSET, long_at - self.LONG_OFFSET)
            self._mem.write(info + self.NAME, raw_name + b"\x00")
            self._mem.write(info + long_at, raw_value + b"\x00")
            self._advance(long_at + len(raw_value) + 1)
        self._mem.write_u32(self._base + 0, self._cursor - self._PA_DATA)  # prop_area.bytes_used_
        return info

    def _write_leaf_bt(self, raw_name: bytes) -> int:
        leaf = raw_name.rsplit(b".", 1)[-1]
        bt = self._cursor
        self._mem.write_u32(self._base + bt + self.BT_NAMELEN, len(leaf))
        self._mem.write(self._base + bt + self.BT_NAME, leaf + b"\x00")
        info = self._align4(bt + self.BT_NAME + len(leaf) + 1)
        self._mem.write_u32(self._base + bt + self.BT_PROP, info)  # prop_bt.prop = offset to the prop_info
        self._cursor = info
        return info

    def _advance(self, size: int) -> None:
        self._cursor = self._align8(self._cursor + size)

    @staticmethod
    def _align4(value: int) -> int:
        return (value + 3) & ~3

    @staticmethod
    def _align8(value: int) -> int:
        return (value + 7) & ~7
