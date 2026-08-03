from __future__ import annotations

from collections.abc import Callable

from emulite.android.enums.errno import Errno
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat
from emulite.filesystem.types.ioctl_context import IoctlContext


class SocketIO(FileIO):
    def __init__(self, domain: int, sock_type: int, protocol: int):
        super().__init__("<socket>", OpenFlag.O_RDWR)
        self.domain, self.sock_type, self.protocol = domain, sock_type, protocol
        self.peer: SocketIO | None = None
        self.handler: Callable[[bytes], bytes] | None = None  # a named-socket sink (logdw/dns/...)
        self.inbox = bytearray()
        self.connected_path: str | None = None

    def deliver(self, data: bytes) -> None:
        self.inbox.extend(data)

    def sendto(self, data: bytes, flags: int, dest_addr: int, addrlen: int) -> int:
        if self.handler is not None:
            reply = self.handler(bytes(data)) or b""
            if reply:
                self.inbox.extend(reply)
        elif self.peer is not None:
            self.peer.deliver(bytes(data))
        return len(data)

    def recvfrom(self, count: int, flags: int, src_addr: int, addrlen: int) -> bytes | int:
        if count < 0:
            return -Errno.EINVAL
        chunk = bytes(self.inbox[: min(count, self._MAX_RW)])
        if not (flags & 0x2):  # MSG_PEEK reads without consuming
            del self.inbox[: len(chunk)]
        return chunk

    def read(self, count: int) -> bytes | int:
        return self.recvfrom(count, 0, 0, 0)

    def write(self, data: bytes) -> int:
        return self.sendto(data, 0, 0, 0)

    def can_read(self) -> bool:
        return bool(self.inbox)

    def ioctl(self, request: int, arg: int, context: IoctlContext) -> int:
        if request & 0xFFFF == 0x541B and arg:  # FIONREAD -> bytes available to read
            context.mem.write_u32(arg, len(self.inbox))
            return 0
        return -Errno.ENOTTY

    def fstat(self) -> FileStat:
        return FileStat.for_socket()
