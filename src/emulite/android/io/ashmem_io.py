from __future__ import annotations

from emulite.android.enums.errno import Errno
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat
from emulite.filesystem.types.ioctl_context import IoctlContext


class AshmemIO(FileIO):
    _ASHMEM_RDEV = 2615  # misc device, major 10
    _MAX_NAME_LENGTH = 255
    _SUPPORTED_COMMANDS = frozenset((0x05, 0x07, 0x08, 0x09, 0x0A))

    def __init__(self) -> None:
        super().__init__("/dev/ashmem", OpenFlag.O_RDWR)
        self.ashmem_size = 0
        self.ashmem_name = "dev/ashmem"

    def ioctl(self, request: int, arg: int, context: IoctlContext) -> int:
        if request >> 8 & 0xFF != 0x77:  # ASHMEM_IOC_MAGIC
            return -Errno.ENOTTY
        command = request & 0xFF  # __ASHMEMIOC command byte
        if command == 0x03:  # ASHMEM_SET_SIZE (size passed by value)
            if arg < 0:
                return -Errno.EINVAL
            self.ashmem_size = arg
            return 0
        if command == 0x04:  # ASHMEM_GET_SIZE
            return self.ashmem_size
        if command == 0x01 and arg:  # ASHMEM_SET_NAME
            self.ashmem_name = context.mem.read_cstr(arg)[: self._MAX_NAME_LENGTH]
            return 0
        if command == 0x02 and arg:  # ASHMEM_GET_NAME
            context.mem.write_cstr(arg, self.ashmem_name)
            return 0
        if command in (0x01, 0x02):
            return -Errno.EINVAL
        return 0 if command in self._SUPPORTED_COMMANDS else -Errno.ENOTTY

    def fstat(self) -> FileStat:
        return FileStat.for_char_device(self._ASHMEM_RDEV)
