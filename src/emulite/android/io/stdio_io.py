from __future__ import annotations

import sys

from emulite.android.enums.errno import Errno
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.structs.file_stat import FileStat


class StdioIO(FileIO):
    _NULL_RDEV = 259  # /dev/null, makedev(1, 3)

    def __init__(self, fd: int):
        super().__init__(("<stdin>", "<stdout>", "<stderr>")[fd])
        self.fd = fd

    @property
    def is_stdio(self) -> bool:
        return True

    def read(self, count: int) -> bytes:
        return b""

    def write(self, data: bytes) -> int:
        if self.fd == 0:
            return -Errno.EBADF  # stdin isn't writable
        printable = all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in data)
        sys.stdout.write(data.decode("utf-8", "replace") if printable else f"[fd{self.fd}-hex {len(data)}] {data.hex()}\n")
        return len(data)

    def fstat(self) -> FileStat:
        return FileStat.for_char_device(self._NULL_RDEV)
