from __future__ import annotations

import sys

from emulite.android.enums.errno import Errno
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.structs.file_stat import FileStat
from emulite.filesystem.types.ioctl_context import IoctlContext


class TtyIO(FileIO):
    _TTY_RDEV = 1280  # makedev(5, 0)

    def read(self, count: int) -> bytes:
        return b""

    def write(self, data: bytes) -> int:
        sys.stdout.write(data.decode("utf-8", "replace"))
        return len(data)

    def ioctl(self, request: int, arg: int, context: IoctlContext) -> int:
        cmd = request & 0xFFFF
        if cmd == 0x5413 and arg:  # TIOCGWINSZ -> a 24x80 window (ws_row | ws_col<<16)
            context.mem.write_u32(arg, 24 | (80 << 16))
            context.mem.write_u32(arg + 4, 0)  # ws_xpixel / ws_ypixel
            return 0
        if 0x5401 <= cmd <= 0x5460:  # the terminal ioctl range (TCGETS/TCSETS/TIOC*) -> ok
            return 0
        return -Errno.ENOTTY

    def fstat(self) -> FileStat:
        return FileStat.for_char_device(self._TTY_RDEV)
