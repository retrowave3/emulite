from __future__ import annotations

from enum import IntEnum


class Errno(IntEnum):
    """Positive Linux errno values; syscall failures return their negation."""

    EPERM = 1  # operation not permitted
    ENOENT = 2  # no such file or directory
    ESRCH = 3  # no such process
    EINTR = 4  # interrupted system call
    EIO = 5  # input/output error
    ENXIO = 6  # no such device or address
    E2BIG = 7  # argument list too long
    ENOEXEC = 8  # executable format error
    EBADF = 9  # bad file descriptor
    ECHILD = 10  # no child processes
    EAGAIN = 11  # resource temporarily unavailable / would block
    ENOMEM = 12  # out of memory
    EACCES = 13  # permission denied
    EFAULT = 14  # bad address
    EBUSY = 16  # device or resource busy
    EEXIST = 17  # file exists
    EXDEV = 18  # invalid cross-device link
    ENODEV = 19  # no such device
    ENOTDIR = 20  # not a directory
    EISDIR = 21  # is a directory
    EINVAL = 22  # invalid argument
    ENFILE = 23  # system-wide open-file limit reached
    EMFILE = 24  # process open-file limit reached
    ENOTTY = 25  # inappropriate ioctl for device (not a terminal)
    ETXTBSY = 26  # text file busy
    EFBIG = 27  # file too large
    ENOSPC = 28  # no space left on device
    ESPIPE = 29  # illegal seek (on a pipe / socket / fifo)
    EROFS = 30  # read-only file system
    EMLINK = 31  # too many links
    EPIPE = 32  # broken pipe
    EDOM = 33  # math argument outside domain
    ERANGE = 34  # numerical result out of range
    ENAMETOOLONG = 36  # file name too long
    ENOLCK = 37  # no locks available
    ENOSYS = 38  # function not implemented
    ENOTEMPTY = 39  # directory not empty
    ELOOP = 40  # too many symbolic links
    EOVERFLOW = 75  # value too large for data type
    EILSEQ = 84  # invalid byte sequence
    ENOTSOCK = 88  # socket operation on a non-socket
    ENOPROTOOPT = 92  # protocol not available (unknown getsockopt option)
    EAFNOSUPPORT = 97  # address family not supported
    ENOTCONN = 107  # socket is not connected
    ETIMEDOUT = 110  # connection timed out
    ECONNREFUSED = 111  # connection refused (no listener at that address)
    EALREADY = 114  # operation already in progress
    EINPROGRESS = 115  # operation now in progress
