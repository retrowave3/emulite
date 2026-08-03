from __future__ import annotations

from emulite.android.enums.errno import Errno
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat


class PipeIO(FileIO):
    def __init__(self, fifo: bytearray, readable: bool, nonblocking: bool = False):
        flags = OpenFlag.O_RDONLY if readable else OpenFlag.O_WRONLY
        super().__init__("<pipe>", flags | (OpenFlag.O_NONBLOCK if nonblocking else OpenFlag.O_RDONLY))
        self.fifo = fifo
        self.readable = readable

    def read(self, count: int) -> bytes | int:
        if not self.readable:
            return -Errno.EBADF
        if count < 0:
            return -Errno.EINVAL
        chunk = bytes(self.fifo[: min(count, self._MAX_RW)])
        del self.fifo[: len(chunk)]
        return chunk

    def write(self, data: bytes) -> int:
        if self.readable:
            return -Errno.EBADF
        data = data[: self._MAX_RW]
        self.fifo.extend(data)
        return len(data)

    def can_read(self) -> bool:
        return self.readable and bool(self.fifo)

    def fstat(self) -> FileStat:
        return FileStat.for_fifo()
