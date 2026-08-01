from __future__ import annotations

import os

from emulite.android.enums.errno import Errno
from emulite.android.io.binder import BinderDriver
from emulite.android.io.buffer_backed_io import BufferBackedIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat


class DeviceIO(BufferBackedIO):
    def __init__(self, path: str, kind: str, rdev: int):
        super().__init__(path, bytearray(), OpenFlag.O_RDWR)
        self.kind = kind
        self.rdev = rdev
        self._binder: "BinderDriver | None" = None

    def read(self, count: int) -> bytes:
        count = min(count, self._MAX_RW)
        if self.kind == "urandom" or self.kind == "random":
            return os.urandom(count)
        if self.kind == "zero":
            return b"\x00" * count
        if self.kind == "null":
            return b""
        return self._buffered_read(count)

    def write(self, data: bytes) -> int:
        if self.kind == "null" or self.kind == "zero":
            return len(data)  # discard
        return self._buffered_write(data)

    def ioctl(self, request: int, arg: int, fs: object) -> int:
        if self.kind == "binder":
            if self._binder is None:
                self._binder = BinderDriver(
                    fs._emu
                )  # fs is the AndroidFileSystem (holds the emulator)
            return self._binder.ioctl(request, arg)
        return -Errno.ENOTTY

    def fstat(self) -> FileStat:
        return FileStat.for_char_device(self.rdev)
