from __future__ import annotations

from emulite.filesystem.enums.dirent_type import DirentType
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat


class DirectoryIO(FileIO):
    def __init__(self, path: str):
        super().__init__(path, OpenFlag.O_RDONLY)
        self.dir_path = path
        self.entries: list[tuple[int, DirentType, str]] | None = None
        self.index = 0

    def fstat(self) -> FileStat:
        return FileStat.for_directory()
