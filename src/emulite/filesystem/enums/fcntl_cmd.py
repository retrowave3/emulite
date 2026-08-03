from __future__ import annotations

from enum import IntEnum


class FcntlCmd(IntEnum):
    F_DUPFD = 0  # duplicate the fd (lowest free >= arg)
    F_GETFD = 1  # get the fd flags (FD_CLOEXEC)
    F_SETFD = 2  # set the fd flags
    F_GETFL = 3  # get the file status flags (O_*)
    F_SETFL = 4  # set the file status flags
    F_GETLK = 5  # get a record lock
    F_SETLK = 6  # set a record lock (non-blocking)
    F_SETLKW = 7  # set a record lock (blocking)
    F_DUPFD_CLOEXEC = 1030
