from __future__ import annotations

import struct

from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat


class EventFdIO(FileIO):
    def __init__(self, initval: int, semaphore: bool):
        super().__init__("<eventfd>", OpenFlag.O_RDWR)
        self._counter = [initval & 0xFFFFFFFFFFFFFFFF]
        self.semaphore = semaphore

    def read(self, count: int) -> bytes:
        if self._counter[0] == 0:
            return b""
        value = 1 if self.semaphore else self._counter[0]
        self._counter[0] -= value
        return struct.pack("<Q", value)

    def write(self, data: bytes) -> int:
        if len(data) >= 8:
            self._counter[0] = (self._counter[0] + struct.unpack("<Q", data[:8])[0]) & 0xFFFFFFFFFFFFFFFF
        return len(data)

    def can_read(self) -> bool:
        return self._counter[0] > 0

    def fstat(self) -> FileStat:
        return FileStat.for_anon_inode()
