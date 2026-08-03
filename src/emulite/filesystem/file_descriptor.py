from dataclasses import dataclass

from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.fd_flag import FdFlag


@dataclass(slots=True)
class FileDescriptor:
    """A descriptor entry with flags that are not shared by dup()."""

    handle: FileIO
    flags: FdFlag = FdFlag.NONE
