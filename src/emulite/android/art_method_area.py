from emulite.cpu.flags.memory_protection_flag import RW


class ArtMethodArea:
    DECLARING_CLASS, ACCESS_FLAGS, DEX_METHOD_INDEX = 0x00, 0x04, 0x08
    METHOD_INDEX, DATA, ENTRY_POINT = 0x0C, 0x10, 0x18
    SIZE = 0x20  # sizeof(ArtMethod)
    _REGION_BYTES = 0x10000

    def __init__(self, mem: object):
        self._mem = mem
        self._base = mem.mmap(self._REGION_BYTES, perms=RW, label="art-methods")
        self._cursor = 0

    def create(
        self,
        *,
        declaring_class: int,
        access_flags: int,
        dex_index: int,
        method_index: int,
        data: int,
        entry: int,
    ) -> int:
        ptr = self._base + self._cursor
        self._cursor += self.SIZE
        if self._cursor > self._REGION_BYTES:
            raise MemoryError(
                f"ArtMethod area exhausted at {self._cursor:#x} of {self._REGION_BYTES:#x}"
            )
        self._mem.write_u32(ptr + self.DECLARING_CLASS, declaring_class & 0xFFFFFFFF)
        self._mem.write_u32(ptr + self.ACCESS_FLAGS, access_flags & 0xFFFFFFFF)
        self._mem.write_u32(ptr + self.DEX_METHOD_INDEX, dex_index & 0xFFFFFFFF)
        self._mem.write_u32(ptr + self.METHOD_INDEX, method_index & 0xFFFF)
        self._mem.write_u64(ptr + self.DATA, data & 0xFFFFFFFFFFFFFFFF)
        self._mem.write_u64(ptr + self.ENTRY_POINT, entry & 0xFFFFFFFFFFFFFFFF)
        return ptr
