from __future__ import annotations

from emulite.android.enums.errno import Errno
from emulite.filesystem.enums.seek_whence import SeekWhence
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag


class BufferBackedIO(FileIO):
    # A FileIO whose contents live in an in-memory bytearray with a seek cursor (RegularFileIO, DeviceIO).
    # Subclasses layer their own guards on top of _buffered_read/_buffered_write (writable/append, device kind).

    def __init__(self, path: str, buffer: bytearray, oflags: OpenFlag = OpenFlag.O_RDONLY):
        super().__init__(path, oflags)
        self._buffer = buffer
        self._cursor = 0

    def _buffered_read(self, count: int) -> bytes | int:
        if count < 0:
            return -Errno.EINVAL
        chunk = bytes(self._buffer[self._cursor : self._cursor + min(count, self._MAX_RW)])
        self._cursor += len(chunk)
        return chunk

    def _buffered_write(self, data: bytes) -> int:
        data = data[: self._MAX_RW]
        end = self._cursor + len(data)
        if end > len(self._buffer):
            self._buffer.extend(b"\x00" * (end - len(self._buffer)))
        self._buffer[self._cursor : end] = data
        self._cursor = end
        return len(data)

    def lseek(self, offset: int, whence: SeekWhence) -> int:
        if whence not in (SeekWhence.SEEK_SET, SeekWhence.SEEK_CUR, SeekWhence.SEEK_END):
            return -Errno.EINVAL
        new_cursor = (0, self._cursor, len(self._buffer))[whence] + offset
        if new_cursor < 0:
            return -Errno.EINVAL
        self._cursor = new_cursor
        return self._cursor
