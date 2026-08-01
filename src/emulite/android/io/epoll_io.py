from __future__ import annotations

from typing import TYPE_CHECKING

from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat

if TYPE_CHECKING:
    from emulite.android.android_file_system import AndroidFileSystem


class EpollIO(FileIO):
    def __init__(self, vfs: "AndroidFileSystem"):
        super().__init__("<epoll>", OpenFlag.O_RDONLY)
        self._vfs = vfs
        self.watched: dict[int, tuple[int, int]] = {}

    def ready(self) -> "list[tuple[int, int, int]]":
        out = []
        for fd, (events, data) in self.watched.items():
            handle = self._vfs._fds.get(fd)
            if handle is not None and handle.can_read():
                out.append((fd, events & 0x1 or 0x1, data))  # report EPOLLIN
        return out

    def can_read(self) -> bool:
        return bool(self.ready())

    def fstat(self) -> FileStat:
        return FileStat.for_anon_inode()
