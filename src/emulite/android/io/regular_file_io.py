from __future__ import annotations

from emulite.android.enums.errno import Errno
from emulite.android.io.buffer_backed_io import BufferBackedIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat


class RegularFileIO(BufferBackedIO):
    def __init__(self, path: str, buffer: bytearray, writable: bool, oflags: OpenFlag = OpenFlag.O_RDONLY, append: bool = False):
        super().__init__(path, buffer, oflags)
        self._writable = writable
        self._append = append

    def read(self, count: int) -> bytes:
        return self._buffered_read(count)

    def write(self, data: bytes) -> int:
        if not self._writable:
            return -Errno.EBADF
        if self._append:
            self._cursor = len(self._buffer)
        return self._buffered_write(data)

    def pread(self, offset: int, count: int) -> bytes:
        return bytes(self._buffer[offset : offset + min(count, self._MAX_RW)])

    def pwrite(self, offset: int, data: bytes) -> int:
        if not self._writable:
            return -Errno.EBADF
        end = offset + len(data)
        if end > len(self._buffer):
            self._buffer.extend(b"\x00" * (end - len(self._buffer)))
        self._buffer[offset:end] = data
        return len(data)

    def ftruncate(self, length: int) -> int:
        if not self._writable:
            return -Errno.EBADF
        if length < len(self._buffer):
            del self._buffer[length:]
        else:
            self._buffer.extend(b"\x00" * (length - len(self._buffer)))
        return 0

    def fstat(self) -> FileStat:
        return FileStat.for_file(len(self._buffer))
