from __future__ import annotations

from enum import IntEnum


class Errno(IntEnum):
    EPERM = 1  # operation not permitted
    ENOENT = 2  # no such file or directory
    ESRCH = 3  # no such process
    EBADF = 9  # bad file descriptor
    EAGAIN = 11  # resource temporarily unavailable / would block
    ENOMEM = 12  # out of memory
    EEXIST = 17  # file exists
    ENOTDIR = 20  # not a directory
    EINVAL = 22  # invalid argument
    ENOTTY = 25  # inappropriate ioctl for device (not a terminal)
    ESPIPE = 29  # illegal seek (on a pipe / socket / fifo)
    ERANGE = 34  # numerical result out of range
    ENOSYS = 38  # function not implemented
    ENOTSOCK = 88  # socket operation on a non-socket
    ENOPROTOOPT = 92  # protocol not available (unknown getsockopt option)
    EAFNOSUPPORT = 97  # address family not supported
    ECONNREFUSED = 111  # connection refused (no listener at that address)
