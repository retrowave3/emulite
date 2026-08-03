from __future__ import annotations

from collections.abc import Callable

from emulite.android.enums.errno import Errno
from emulite.android.io.enums.epoll_control_operation import EpollControlOperation
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat


class EpollIO(FileIO):
    _EPOLLIN = 0x1

    def __init__(self, handle_for: Callable[[int], FileIO | None]):
        super().__init__("<epoll>", OpenFlag.O_RDONLY)
        self._handle_for = handle_for
        self._watched: dict[int, tuple[FileIO, int, int]] = {}

    def control(self, operation: EpollControlOperation, fd: int, handle: FileIO, events: int, data: int) -> int:
        if operation is EpollControlOperation.ADD:
            if fd in self._watched:
                return -Errno.EEXIST
            self._watched[fd] = (handle, events, data)
            return 0
        if fd not in self._watched:
            return -Errno.ENOENT
        if operation is EpollControlOperation.DELETE:
            del self._watched[fd]
        else:
            self._watched[fd] = (handle, events, data)
        return 0

    def ready(self) -> list[tuple[int, int, int]]:
        out: list[tuple[int, int, int]] = []
        for fd, (registered, events, data) in list(self._watched.items()):
            handle = self._handle_for(fd)
            if handle is not registered:
                del self._watched[fd]
            elif events & self._EPOLLIN and handle.can_read():
                out.append((fd, self._EPOLLIN, data))
        return out

    def can_read(self) -> bool:
        return bool(self.ready())

    def fstat(self) -> FileStat:
        return FileStat.for_anon_inode()
