from __future__ import annotations

from emulite.android.enums.errno import Errno
from emulite.filesystem.enums.fcntl_cmd import FcntlCmd
from emulite.filesystem.enums.seek_whence import SeekWhence
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat
from emulite.filesystem.types.ioctl_context import IoctlContext


class FileIO:
    """Shared state for an open file description."""

    _MAX_RW = 0x7FFFF000  # Linux MAX_RW_COUNT
    _STATUS_FLAGS = OpenFlag.O_APPEND | OpenFlag.O_ASYNC | OpenFlag.O_DIRECT | OpenFlag.O_NOATIME | OpenFlag.O_NONBLOCK

    def __init__(self, path: str, oflags: OpenFlag = OpenFlag.O_RDONLY):
        self.path = path
        self.oflags = OpenFlag(oflags)

    @property
    def is_stdio(self) -> bool:
        return False

    def read(self, count: int) -> bytes | int:
        return -Errno.EBADF

    def write(self, data: bytes) -> int:
        return -Errno.EBADF

    def lseek(self, offset: int, whence: SeekWhence) -> int:
        return -Errno.ESPIPE

    def fstat(self) -> FileStat:
        return FileStat.for_file(0)

    def ioctl(self, request: int, arg: int, context: IoctlContext) -> int:
        return -Errno.ENOTTY

    def fcntl(self, cmd: FcntlCmd, arg: int) -> int:
        if cmd == FcntlCmd.F_GETFL:
            return int(self.oflags)
        if cmd == FcntlCmd.F_SETFL:  # access mode is fixed at open; only status bits change
            preserved = self.oflags & ~self._STATUS_FLAGS
            self.oflags = OpenFlag(preserved | (OpenFlag(arg) & self._STATUS_FLAGS))
            return 0
        if cmd in (FcntlCmd.F_GETLK, FcntlCmd.F_SETLK, FcntlCmd.F_SETLKW):
            return 0
        return -Errno.EINVAL

    def getdents64(self, count: int) -> bytes | int:
        return -Errno.ENOTDIR

    def ftruncate(self, length: int) -> int:
        return -Errno.EINVAL

    def pread(self, offset: int, count: int) -> bytes | int:
        return -Errno.ESPIPE

    def pwrite(self, offset: int, data: bytes) -> int:
        return -Errno.ESPIPE

    def can_read(self) -> bool:
        return True

    def close(self) -> None:
        pass

    def connect(self, addr: int, addrlen: int) -> int:
        return -Errno.ENOTSOCK

    def bind(self, addr: int, addrlen: int) -> int:
        return -Errno.ENOTSOCK

    def listen(self, backlog: int) -> int:
        return -Errno.ENOTSOCK

    def accept(self, addr: int, addrlen: int, flags: int) -> int:
        return -Errno.ENOTSOCK

    def sendto(self, data: bytes, flags: int, dest_addr: int, addrlen: int) -> int:
        return -Errno.ENOTSOCK

    def recvfrom(self, count: int, flags: int, src_addr: int, addrlen: int) -> bytes | int:
        return -Errno.ENOTSOCK

    def getsockopt(self, level: int, optname: int, optval: int, optlen: int) -> int:
        return -Errno.ENOTSOCK

    def setsockopt(self, level: int, optname: int, optval: int, optlen: int) -> int:
        return -Errno.ENOTSOCK

    def getsockname(self, addr: int, addrlen: int) -> int:
        return -Errno.ENOTSOCK

    def getpeername(self, addr: int, addrlen: int) -> int:
        return -Errno.ENOTSOCK

    def shutdown(self, how: int) -> int:
        return -Errno.ENOTSOCK
