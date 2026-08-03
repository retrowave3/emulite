from __future__ import annotations

from emulite.android.enums.errno import Errno
from emulite.android.io.pipe_state import PipeState
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat


class PipeIO(FileIO):
    def __init__(self, state: PipeState | bytearray, readable: bool, nonblocking: bool = False):
        flags = OpenFlag.O_RDONLY if readable else OpenFlag.O_WRONLY
        super().__init__("<pipe>", flags | (OpenFlag.O_NONBLOCK if nonblocking else OpenFlag.O_RDONLY))
        self._state = state if isinstance(state, PipeState) else PipeState(state, readers=1, writers=1)
        self._readable = readable
        self._closed = False
        if isinstance(state, PipeState):
            if readable:
                state.readers += 1
            else:
                state.writers += 1

    def read(self, count: int) -> bytes | int:
        if not self._readable or self._closed:
            return -Errno.EBADF
        if count < 0:
            return -Errno.EINVAL
        if count == 0:
            return b""
        if not self._state.buffer:
            return b"" if self._state.writers == 0 else -Errno.EAGAIN
        chunk = bytes(self._state.buffer[: min(count, self._MAX_RW)])
        del self._state.buffer[: len(chunk)]
        return chunk

    def write(self, data: bytes) -> int:
        if self._readable or self._closed:
            return -Errno.EBADF
        if not data:
            return 0
        if self._state.readers == 0:
            return -Errno.EPIPE
        data = data[: self._MAX_RW]
        self._state.buffer.extend(data)
        return len(data)

    def can_read(self) -> bool:
        return self._readable and (bool(self._state.buffer) or self._state.writers == 0)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._readable:
            self._state.readers -= 1
        else:
            self._state.writers -= 1

    def fstat(self) -> FileStat:
        return FileStat.for_fifo()
