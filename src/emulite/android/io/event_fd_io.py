from __future__ import annotations

import struct

from emulite.android.enums.errno import Errno
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat


class EventFdIO(FileIO):
    def __init__(self, initval: int, semaphore: bool, nonblocking: bool = False):
        super().__init__("<eventfd>", OpenFlag.O_RDWR | (OpenFlag.O_NONBLOCK if nonblocking else OpenFlag.O_RDONLY))
        self._counter = initval & 0xFFFFFFFFFFFFFFFF
        self.semaphore = semaphore

    def read(self, count: int) -> bytes | int:
        if count != 8:
            return -Errno.EINVAL
        if self._counter == 0:
            return -Errno.EAGAIN
        value = 1 if self.semaphore else self._counter
        self._counter -= value
        return struct.pack("<Q", value)

    def write(self, data: bytes) -> int:
        if len(data) != 8:
            return -Errno.EINVAL
        value = struct.unpack("<Q", data)[0]
        if value == 0xFFFFFFFFFFFFFFFF:
            return -Errno.EINVAL
        if self._counter > 0xFFFFFFFFFFFFFFFE - value:
            return -Errno.EAGAIN
        self._counter += value
        return 8

    def can_read(self) -> bool:
        return self._counter > 0

    def fstat(self) -> FileStat:
        return FileStat.for_anon_inode()
