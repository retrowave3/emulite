from __future__ import annotations

from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat


class AshmemIO(FileIO):
    _ASHMEM_RDEV = 2615  # misc device, major 10

    def __init__(self) -> None:
        super().__init__("/dev/ashmem", OpenFlag.O_RDWR)
        self.ashmem_size = 0
        self.ashmem_name = "dev/ashmem"

    def ioctl(self, request: int, arg: int, fs: object) -> int:
        command = request & 0xFF  # __ASHMEMIOC command byte
        if command == 0x03:  # ASHMEM_SET_SIZE (size passed by value)
            self.ashmem_size = arg
            return 0
        if command == 0x04:  # ASHMEM_GET_SIZE
            return self.ashmem_size
        if command == 0x01 and arg:  # ASHMEM_SET_NAME
            self.ashmem_name = fs._emu.mem.read_cstr(arg)
            return 0
        if command == 0x02 and arg:  # ASHMEM_GET_NAME
            fs._emu.mem.write_cstr(arg, self.ashmem_name)
            return 0
        return 0  # SET_PROT_MASK / PIN / UNPIN / ... -> accept

    def fstat(self) -> FileStat:
        return FileStat.for_char_device(self._ASHMEM_RDEV)
