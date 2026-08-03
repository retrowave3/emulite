from __future__ import annotations

import itertools
import os
import posixpath
import struct
import zlib
from collections.abc import Callable
from typing import TYPE_CHECKING, ClassVar

from emulite.android.enums.auxv import Auxv
from emulite.android.enums.errno import Errno
from emulite.android.io.ashmem_io import AshmemIO
from emulite.android.io.device_io import DeviceIO
from emulite.android.io.directory_io import DirectoryIO
from emulite.android.io.enums.epoll_control_operation import EpollControlOperation
from emulite.android.io.epoll_io import EpollIO
from emulite.android.io.event_fd_io import EventFdIO
from emulite.android.io.pipe_io import PipeIO
from emulite.android.io.pipe_state import PipeState
from emulite.android.io.regular_file_io import RegularFileIO
from emulite.android.io.socket_io import SocketIO
from emulite.android.io.stdio_io import StdioIO
from emulite.android.io.tty_io import TtyIO
from emulite.common.log import LogLevel
from emulite.cpu.backend import CpuArch, MemoryProtectionFlag
from emulite.filesystem.enums.dirent_type import DirentType
from emulite.filesystem.enums.fcntl_cmd import FcntlCmd
from emulite.filesystem.enums.seek_whence import SeekWhence
from emulite.filesystem.file_descriptor import FileDescriptor
from emulite.filesystem.file_io import FileIO
from emulite.filesystem.flags.fd_flag import FdFlag
from emulite.filesystem.flags.open_flag import OpenFlag
from emulite.filesystem.structs.file_stat import FileStat
from emulite.filesystem.structs.stat_result import StatResult
from emulite.loader.module.native_module import NativeModule
from emulite.memory import MemoryLayout

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class AndroidFileSystem:
    """Android-oriented virtual filesystem and guest descriptor table."""

    _REG_MODE, _CHR_MODE, _DIR_MODE = FileStat.REG_MODE, FileStat.CHR_MODE, FileStat.DIR_MODE
    _DEV_RDEV: ClassVar[dict[str, int]] = {"urandom": 265, "random": 264, "null": 259, "zero": 261, "ashmem": 2615, "binder": 2616, "tty": 1280}
    _KNOWN_DIRS: ClassVar[tuple[str, ...]] = ("/proc", "/proc/self", "/proc/self/fd", "/proc/self/task", "/proc/net", "/dev")
    _DIR_INO: ClassVar[dict[str, int]] = {"fd": 100000, "dev": 200000, "self": 300000, "task": 310000, "proc": 400000, "net": 500000, "host": 600000}
    _ANON_NAMES: ClassVar[dict[str, str]] = {"malloc-arena": "[anon:libc_malloc]", "tls": "[anon:bionic_tls]", "heap": "[heap]", "art-methods": "[anon:dalvik-LinearAlloc]"}
    _DEV_BACKED: ClassVar[dict[str, tuple[str, str, int]]] = {"properties": ("/dev/__properties__/u:object_r:default_prop:s0", "00:0d", 1596)}
    _HIDDEN_REGIONS: ClassVar[frozenset[str]] = frozenset({"trampolines", "JNIEnv", "JavaVM", "dl_phdr_info", "r_debug", "link_map", "main-exe", "linker64", "linker"})
    _ANON_FD_LINK: ClassVar[dict[str, str]] = {"<eventfd>": "anon_inode:[eventfd]", "<epoll>": "anon_inode:[eventpoll]", "<stdin>": "/dev/null", "<stdout>": "/dev/null", "<stderr>": "/dev/null"}

    def __init__(self, rootfs: str | None, emu: AndroidEmulatorBase):
        self._rootfs = os.path.realpath(rootfs) if rootfs else None
        self._emu = emu
        self._log = emu.log
        self._fds: dict[int, FileDescriptor] = {fd: FileDescriptor(StdioIO(fd)) for fd in range(3)}
        self._overlay: dict[str, bytearray] = {}
        self._made_dirs: set[str] = self._app_directories()
        self._deleted: set[str] = set()
        self._socket_handlers: dict[str, Callable[[bytes], bytes]] = {}
        self._providers: dict[str, Callable[[], bytes]] = {
            "/proc/self/maps": self._proc_maps,
            "/proc/self/smaps": self._proc_smaps,
            "/proc/self/status": self._proc_status,
            "/proc/self/stat": self._proc_self_stat,
            "/proc/self/cmdline": self._proc_cmdline,
            "/proc/self/cgroup": self._proc_cgroup,
            "/proc/self/oom_score_adj": lambda: f"{self._emu.profile.oom_score_adj}\n".encode(),
            "/proc/self/wchan": lambda: b"0",
            "/proc/self/comm": self._proc_comm,
            "/proc/self/auxv": self._proc_auxv,
            "/proc/self/attr/current": self._proc_attr_current,
            "/proc/self/mounts": self._proc_mounts,
            "/proc/mounts": self._proc_mounts,
            "/proc/cpuinfo": self._proc_cpuinfo,
            "/proc/meminfo": self._proc_meminfo,
            "/proc/stat": self._proc_stat_global,
            "/proc/uptime": self._proc_uptime,
            "/proc/version": self._proc_version,
            "/proc/net/tcp": lambda: self._proc_net_tcp(6),
            "/proc/net/tcp6": lambda: self._proc_net_tcp(6),
            "/sys/fs/selinux/enforce": lambda: b"1",
            "/sys/fs/selinux/policyvers": lambda: self._emu.device.selinux_policyvers.encode(),
            "/sys/fs/selinux/checkreqprot": lambda: b"0",
            "/sys/fs/selinux/mls": lambda: b"1",
        }
        self._devices = {
            "/dev/urandom": "urandom",
            "/dev/random": "random",
            "/dev/null": "null",
            "/dev/zero": "zero",
            "/dev/tty": "tty",
            "/dev/console": "tty",
            "/dev/ashmem": "ashmem",
            "/dev/binder": "binder",
            "/dev/hwbinder": "binder",
            "/dev/vndbinder": "binder",
        }
        app_process = "app_process64" if emu.arch.cpu_arch is CpuArch.ARM64 else "app_process32"
        self._symlinks = {"/proc/self/exe": f"/system/bin/{app_process}"}

    def add_file(self, path: str, data: bytes) -> None:
        self._overlay[self._canonical(self._normalize(path))] = bytearray(data)

    def open(self, path: str, flags: int) -> int:
        norm = self._canonical(self._normalize(path))
        open_flags = OpenFlag(flags)
        access = open_flags & OpenFlag.O_ACCMODE
        writable = access in (OpenFlag.O_WRONLY, OpenFlag.O_RDWR)
        exists = self.exists(norm)
        if open_flags & OpenFlag.O_CREAT and open_flags & OpenFlag.O_EXCL and exists:
            return -Errno.EEXIST
        if open_flags & OpenFlag.O_CREAT:
            self._deleted.discard(norm)
        if (open_flags & OpenFlag.O_DIRECTORY) or self._is_dir(norm):
            return self._open_directory(norm, FdFlag.FD_CLOEXEC if open_flags & OpenFlag.O_CLOEXEC else FdFlag.NONE)
        handle = self._make_handle(norm, open_flags, writable, bool(open_flags & OpenFlag.O_APPEND))
        if isinstance(handle, int):
            return handle
        handle.oflags = OpenFlag(open_flags & ~(OpenFlag.O_CREAT | OpenFlag.O_EXCL | OpenFlag.O_NOCTTY | OpenFlag.O_TRUNC | OpenFlag.O_CLOEXEC))
        if writable and open_flags & OpenFlag.O_TRUNC and isinstance(handle, RegularFileIO):
            handle.ftruncate(0)
        fd = self._install(handle, FdFlag.FD_CLOEXEC if open_flags & OpenFlag.O_CLOEXEC else FdFlag.NONE)
        self._log.vfs("open(%r, flags=%#x) => fd %d", norm, flags, fd)
        return fd

    def _open_directory(self, norm: str, flags: FdFlag = FdFlag.NONE) -> int:
        if not self._is_dir(norm):
            exists = norm in self._providers or norm in self._overlay or self._host_path(norm)
            return -Errno.ENOTDIR if exists else -Errno.ENOENT
        fd = self._install(DirectoryIO(norm), flags)
        self._log.vfs("opendir(%r) => fd %d", norm, fd)
        return fd

    def _make_handle(self, norm: str, flags: OpenFlag, writable: bool, append: bool) -> FileIO | int:
        if norm in self._devices:
            kind = self._devices[norm]
            return AshmemIO() if kind == "ashmem" else TtyIO(norm) if kind == "tty" else DeviceIO(norm, kind, self._DEV_RDEV[kind])
        if norm in self._overlay:
            return RegularFileIO(norm, self._overlay[norm], writable, flags, append)
        if norm in self._providers:
            return RegularFileIO(norm, bytearray(self._providers[norm]()), writable=False)
        host = self._host_path(norm)
        if host is not None and writable:
            return RegularFileIO(norm, self._overlay.setdefault(norm, bytearray(self._read_host(host))), True, flags, append)
        if host is not None:
            return RegularFileIO(norm, bytearray(self._read_host(host)), writable=False)
        if flags & OpenFlag.O_CREAT:
            return RegularFileIO(norm, self._overlay.setdefault(norm, bytearray()), writable, flags, append)
        self._log.vfs("open(%r) => -ENOENT", norm, level=LogLevel.WARN)
        return -Errno.ENOENT

    def close(self, fd: int) -> int:
        descriptor = self._fds.pop(fd, None)
        if descriptor is None:
            return -Errno.EBADF
        if all(other.handle is not descriptor.handle for other in self._fds.values()):
            descriptor.handle.close()
        self._log.vfs("close(%d) => 0", fd)
        return 0

    def _install(self, handle: FileIO, flags: FdFlag = FdFlag.NONE) -> int:
        fd = next(i for i in itertools.count(3) if i not in self._fds)
        self._fds[fd] = FileDescriptor(handle, flags)
        return fd

    def socket(self, domain: int, sock_type: int, protocol: int) -> int:
        if domain != 1:
            return -Errno.EAFNOSUPPORT
        handle = SocketIO(domain, sock_type & 0xF, protocol)
        if sock_type & OpenFlag.O_NONBLOCK:
            handle.oflags |= OpenFlag.O_NONBLOCK
        return self._install(handle, FdFlag.FD_CLOEXEC if sock_type & OpenFlag.O_CLOEXEC else FdFlag.NONE)

    def socketpair(self, domain: int, sock_type: int, protocol: int) -> tuple[int, int] | int:
        if domain != 1:
            return -Errno.EAFNOSUPPORT
        left, right = (SocketIO(domain, sock_type & 0xF, protocol) for _ in range(2))
        if sock_type & OpenFlag.O_NONBLOCK:
            left.oflags |= OpenFlag.O_NONBLOCK
            right.oflags |= OpenFlag.O_NONBLOCK
        left.peer, right.peer = right, left
        fd_flags = FdFlag.FD_CLOEXEC if sock_type & OpenFlag.O_CLOEXEC else FdFlag.NONE
        return self._install(left, fd_flags), self._install(right, fd_flags)

    def pipe(self, flags: int = 0) -> tuple[int, int]:
        state = PipeState()
        nonblocking = bool(flags & OpenFlag.O_NONBLOCK)
        fd_flags = FdFlag.FD_CLOEXEC if flags & OpenFlag.O_CLOEXEC else FdFlag.NONE
        return self._install(PipeIO(state, readable=True, nonblocking=nonblocking), fd_flags), self._install(PipeIO(state, readable=False, nonblocking=nonblocking), fd_flags)

    def eventfd(self, initval: int, *, semaphore: bool = False, nonblocking: bool = False, close_on_exec: bool = False) -> int:
        handle = EventFdIO(initval, semaphore=semaphore, nonblocking=nonblocking)
        return self._install(handle, FdFlag.FD_CLOEXEC if close_on_exec else FdFlag.NONE)

    def epoll_create(self, flags: int = 0) -> int:
        return self._install(EpollIO(self.handle), FdFlag.FD_CLOEXEC if flags & OpenFlag.O_CLOEXEC else FdFlag.NONE)

    def epoll_ctl(self, epfd: int, op: int, fd: int, events: int, data: int) -> int:
        ep = self.handle(epfd)
        if not isinstance(ep, EpollIO):
            return -Errno.EBADF
        handle = self.handle(fd)
        if handle is None:
            return -Errno.EBADF
        if handle is ep:
            return -Errno.EINVAL
        try:
            operation = EpollControlOperation(op)
        except ValueError:
            return -Errno.EINVAL
        return ep.control(operation, fd, handle, events, data)

    def epoll_wait(self, epfd: int, maxevents: int) -> list[tuple[int, int, int]] | None:
        ep = self.handle(epfd)
        if not isinstance(ep, EpollIO):
            return None
        return ep.ready()[:maxevents]

    def handle(self, fd: int) -> FileIO | None:
        descriptor = self._fds.get(fd)
        return descriptor.handle if descriptor is not None else None

    def ioctl(self, fd: int, request: int, argp: int) -> int:
        handle = self.handle(fd)
        return handle.ioctl(request, argp, self._emu) if handle is not None else -Errno.EBADF

    def unlink(self, path: str) -> int:
        norm = self._normalize(path)
        if norm in self._overlay:
            del self._overlay[norm]
        elif not (self._host_path(norm) or norm in self._made_dirs):
            return -Errno.ENOENT
        self._made_dirs.discard(norm)
        self._deleted.add(norm)
        self._log.vfs("unlink(%r) => 0", norm)
        return 0

    def rename(self, old_path: str, new_path: str) -> int:
        old, new = self._normalize(old_path), self._normalize(new_path)
        if old in self._overlay:
            self._overlay[new] = self._overlay.pop(old)
        else:
            host = self._host_path(old)
            if host is None:
                return -Errno.ENOENT
            self._overlay[new] = bytearray(self._read_host(host))
        self._deleted.add(old)
        self._deleted.discard(new)
        self._log.vfs("rename(%r -> %r) => 0", old, new)
        return 0

    def register_socket(self, path: str, handler: Callable[[bytes], bytes]) -> None:
        self._socket_handlers[path] = handler

    def connect(self, fd: int, path: str) -> int:
        handle = self.handle(fd)
        if not isinstance(handle, SocketIO):
            return -Errno.ENOTSOCK
        handler = self._socket_handlers.get(path)
        if handler is None and not self._is_known_socket(path):
            self._log.vfs("connect(fd %d, %r) => -ECONNREFUSED (no listener)", fd, path)
            return -Errno.ECONNREFUSED
        handle.connected_path = path
        handle.handler = handler
        self._log.vfs("connect(fd %d, %r) => 0%s", fd, path, " [handler]" if handler else "")
        return 0

    @staticmethod
    def _is_known_socket(path: str) -> bool:
        return path.startswith("/dev/socket/")

    def socket_handle(self, fd: int) -> SocketIO | None:
        handle = self.handle(fd)
        return handle if isinstance(handle, SocketIO) else None

    def close_range(self, first: int, last: int) -> int:
        targets = [fd for fd in self._fds if first <= fd <= last]
        for fd in targets:
            self.close(fd)
        return len(targets)

    def dup(self, fd: int, min_fd: int = 3) -> int:
        descriptor = self._fds.get(fd)
        if descriptor is None:
            return -Errno.EBADF
        new_fd = next(i for i in itertools.count(min_fd) if i not in self._fds)
        self._fds[new_fd] = FileDescriptor(descriptor.handle)
        return new_fd

    def dup_to(self, oldfd: int, newfd: int, *, close_on_exec: bool = False) -> int:
        descriptor = self._fds.get(oldfd)
        if descriptor is None:
            return -Errno.EBADF
        if oldfd == newfd:
            return newfd
        self.close(newfd)
        flags = FdFlag.FD_CLOEXEC if close_on_exec else FdFlag.NONE
        self._fds[newfd] = FileDescriptor(descriptor.handle, flags)
        return newfd

    def fcntl(self, fd: int, cmd: int, arg: int) -> int:
        descriptor = self._fds.get(fd)
        if descriptor is None:
            return -Errno.EBADF
        try:
            command = FcntlCmd(cmd)
        except ValueError:
            return -Errno.EINVAL
        if command in (FcntlCmd.F_DUPFD, FcntlCmd.F_DUPFD_CLOEXEC):
            result = self.dup(fd, min_fd=arg)
            if result >= 0 and command is FcntlCmd.F_DUPFD_CLOEXEC:
                self._fds[result].flags = FdFlag.FD_CLOEXEC
            return result
        if command is FcntlCmd.F_GETFD:
            return int(descriptor.flags)
        if command is FcntlCmd.F_SETFD:
            descriptor.flags = FdFlag(arg & FdFlag.FD_CLOEXEC)
            return 0
        return descriptor.handle.fcntl(command, arg)

    def pread(self, fd: int, count: int, offset: int) -> bytes | int:
        handle = self.handle(fd)
        if handle is None or handle.oflags & OpenFlag.O_ACCMODE == OpenFlag.O_WRONLY:
            return -Errno.EBADF
        return handle.pread(offset, count)

    def pwrite(self, fd: int, data: bytes, offset: int) -> int:
        handle = self.handle(fd)
        if handle is None or handle.oflags & OpenFlag.O_ACCMODE == OpenFlag.O_RDONLY:
            return -Errno.EBADF
        return handle.pwrite(offset, data)

    def ftruncate(self, fd: int, length: int) -> int:
        handle = self.handle(fd)
        if handle is None or handle.oflags & OpenFlag.O_ACCMODE == OpenFlag.O_RDONLY:
            return -Errno.EBADF
        return handle.ftruncate(length)

    def truncate(self, path: str, length: int) -> int:
        if length < 0:
            return -Errno.EINVAL
        fd = self.open(path, OpenFlag.O_WRONLY)
        if fd < 0:
            return fd
        result = self.ftruncate(fd, length)
        self.close(fd)
        return result

    def read(self, fd: int, count: int) -> bytes | int:
        handle = self.handle(fd)
        if handle is None:
            return -Errno.EBADF
        if handle.oflags & OpenFlag.O_ACCMODE == OpenFlag.O_WRONLY:
            return -Errno.EBADF
        return handle.read(count)

    def write(self, fd: int, data: bytes) -> int:
        handle = self.handle(fd)
        if handle is None or handle.oflags & OpenFlag.O_ACCMODE == OpenFlag.O_RDONLY:
            return -Errno.EBADF
        return handle.write(data)

    def seek(self, fd: int, offset: int, whence: int) -> int:
        handle = self.handle(fd)
        if handle is None:
            return -Errno.EBADF
        try:
            origin = SeekWhence(whence)
        except ValueError:
            return -Errno.EINVAL
        return handle.lseek(offset, origin)

    def _canonical(self, norm: str) -> str:
        profile = self._emu.profile
        for prefix in (f"/proc/{profile.process_pid}", f"/proc/self/task/{profile.process_tid}"):
            if norm == prefix or norm.startswith(prefix + "/"):
                return "/proc/self" + norm[len(prefix) :]
        return norm

    def _is_dir(self, norm: str) -> bool:
        norm = self._canonical(norm)
        if norm == "/" or norm in self._KNOWN_DIRS or norm in self._made_dirs or self._host_dir(norm) is not None:
            return True
        prefix = norm.rstrip("/") + "/"
        virtual_paths = itertools.chain(self._providers, self._overlay, self._devices, self._symlinks)
        return any(path.startswith(prefix) for path in virtual_paths)

    def mkdir(self, path: str, mode: int = 0x1FF) -> int:
        norm = self._normalize(path)
        if self._is_dir(norm) or norm in self._providers or norm in self._overlay or self._host_path(norm):
            return -Errno.EEXIST
        parent = posixpath.dirname(norm)
        if parent != "/" and not self._is_dir(parent):
            return -Errno.ENOENT
        self._made_dirs.add(norm)
        return 0

    def _dir_entries(self, norm: str) -> list[tuple[int, DirentType, str]] | None:
        norm = self._canonical(norm)
        inode_bases = self._DIR_INO
        dot = [(1, DirentType.DT_DIR, "."), (2, DirentType.DT_DIR, "..")]
        if norm == "/proc/self/fd":
            return dot + [(inode_bases["fd"] + fd, DirentType.DT_LNK, str(fd)) for fd in sorted(self._fds)]
        if norm == "/proc/self/task":
            return dot + [(inode_bases["task"], DirentType.DT_DIR, str(self._emu.profile.process_tid))]
        if norm == "/dev":
            return dot + [(inode_bases["dev"] + i, DirentType.DT_CHR, name[len("/dev/") :]) for i, name in enumerate(sorted(self._devices))]
        if norm == "/proc/self":
            names = sorted({p[len("/proc/self/") :].split("/")[0] for p in self._providers if p.startswith("/proc/self/")} | {"fd", "task"})
            return dot + [(inode_bases["self"] + i, DirentType.DT_DIR if self._is_dir(f"/proc/self/{n}") else DirentType.DT_REG, n) for i, n in enumerate(names)]
        if norm == "/proc":
            top = sorted({p[len("/proc/") :].split("/")[0] for p in self._providers} | {"self", "net"})
            return dot + [(inode_bases["proc"] + i, DirentType.DT_DIR if self._is_dir(f"/proc/{n}") else DirentType.DT_REG, n) for i, n in enumerate(top)]
        if norm == "/proc/net":
            return dot + [(inode_bases["net"], DirentType.DT_REG, "tcp"), (inode_bases["net"] + 1, DirentType.DT_REG, "tcp6")]
        host = self._host_dir(norm)
        if host is None and not self._is_dir(norm):
            return None
        entries, seen, inode = list(dot), {".", ".."}, inode_bases["host"]
        if host is not None:
            for name in sorted(os.listdir(host)):
                full = os.path.join(host, name)
                dtype = DirentType.DT_DIR if os.path.isdir(full) else (DirentType.DT_LNK if os.path.islink(full) else DirentType.DT_REG)
                entries.append((inode, dtype, name))
                seen.add(name)
                inode += 1
        prefix = norm.rstrip("/") + "/"
        virtual_paths = set(self._providers) | set(self._overlay) | self._made_dirs | set(self._devices) | set(self._symlinks)
        for path in sorted(virtual_paths):
            if not path.startswith(prefix):
                continue
            tail = path[len(prefix) :]
            name = tail.split("/", 1)[0]
            if not name or name in seen:
                continue
            child = prefix + name
            if self._is_dir(child):
                dtype = DirentType.DT_DIR
            elif child in self._symlinks:
                dtype = DirentType.DT_LNK
            elif child in self._devices:
                dtype = DirentType.DT_CHR
            else:
                dtype = DirentType.DT_REG
            entries.append((inode, dtype, name))
            seen.add(name)
            inode += 1
        return entries

    def getdents(self, fd: int) -> list[tuple[int, DirentType, str]] | None:
        handle = self.handle(fd)
        if not isinstance(handle, DirectoryIO):
            return None
        if handle.entries is None:
            handle.entries = self._dir_entries(handle.dir_path) or []
        return handle.entries[handle.index :]

    def advance_dir(self, fd: int, count: int) -> None:
        handle = self.handle(fd)
        if isinstance(handle, DirectoryIO):
            handle.index += count

    def fstat(self, fd: int) -> StatResult | None:
        handle = self.handle(fd)
        if handle is None:
            return None
        stat = handle.fstat()
        path = getattr(handle, "path", "")
        if path and path.startswith("/"):
            uid, gid, ino = self._path_identity(self._canonical(self._normalize(path)))
        else:
            uid, gid, ino = (self._emu.profile.process_uid, self._emu.profile.process_gid, self._anon_inode(handle))
        return StatResult(stat.mode, stat.size, stat.rdev, uid, gid, ino)

    def stat_path(self, path: str) -> StatResult | None:
        norm = self._canonical(self._normalize(path))
        base = self._stat_base(norm)
        return StatResult(*base, *self._path_identity(norm)) if base is not None else None

    def _stat_base(self, norm: str) -> tuple[int, int, int] | None:
        if norm in self._devices:
            return (self._CHR_MODE, 0, self._DEV_RDEV.get(self._devices[norm], 0))
        if norm in self._overlay:
            return (self._REG_MODE, len(self._overlay[norm]), 0)
        if norm in self._providers:
            return (self._REG_MODE, len(self._providers[norm]()), 0)
        if self._is_dir(norm):
            return (self._DIR_MODE, 4096, 0)
        host = self._host_path(norm)
        return (self._REG_MODE, os.path.getsize(host), 0) if host else None

    def _path_identity(self, norm: str) -> tuple[int, int, int]:
        uid = self._emu.profile.process_uid if self._is_app_path(norm) else 0
        gid = self._emu.profile.process_gid if uid else 0
        return (uid, gid, (zlib.crc32(norm.encode()) & 0x00FFFFFF) | 0x0C000000)

    def _is_app_path(self, norm: str) -> bool:
        return any(norm == root or norm.startswith(root + "/") for root in self._app_roots())

    def _app_roots(self) -> tuple[str, ...]:
        p = self._emu.profile
        return tuple(r for r in (p.data_dir, f"/data/data/{p.package_name}", f"/data/app/{p.package_name}", p.external_files_dir) if r)

    def _app_directories(self) -> set[str]:
        p = self._emu.profile
        dirs = {"/data", "/data/user", "/data/user/0", "/data/data", "/data/app", "/sdcard", "/sdcard/Android", "/sdcard/Android/data"}
        for base in (p.data_dir, f"/data/data/{p.package_name}"):
            if not base:
                continue
            dirs |= {base, f"{base}/files", f"{base}/cache", f"{base}/code_cache", f"{base}/shared_prefs", f"{base}/databases"}
        app_root = f"/data/app/{p.package_name}"
        dirs |= {app_root, f"{app_root}/lib"}
        dirs.update(path for path in (p.native_lib_dir, p.external_files_dir) if path)
        return {self._normalize(path) for path in dirs}

    def exists(self, path: str) -> bool:
        return self.stat_path(path) is not None or self._normalize(path) in self._symlinks

    def readlink(self, path: str) -> str | None:
        norm = self._normalize(path)
        fd_target = self._fd_link(norm)
        if fd_target is not None:
            return fd_target
        return self._symlinks.get(norm)

    def _fd_link(self, norm: str) -> str | None:
        for prefix in ("/proc/self/fd/", f"/proc/{self._emu.profile.process_pid}/fd/"):
            if norm.startswith(prefix):
                tail = norm[len(prefix) :]
                if not (tail.isascii() and tail.isdigit()):
                    return None
                handle = self.handle(int(tail))
                if handle is None:
                    return None
                path = getattr(handle, "path", None)
                if path and path.startswith("/"):
                    return path
                if path in self._ANON_FD_LINK:
                    return self._ANON_FD_LINK[path]
                if path == "<socket>":  # Linux: socket:[<inode>]
                    return f"socket:[{self._anon_inode(handle)}]"
                if path == "<pipe>":
                    return f"pipe:[{self._anon_inode(handle)}]"
                return None
        return None

    @staticmethod
    def _anon_inode(handle: object) -> int:
        return 1000000 + (id(handle) % 9000000)

    def _normalize(self, path: str) -> str:
        if "\x00" in path:
            return "\x00"
        path = path.replace("\\", "/")
        if not path.startswith("/"):
            path = "/" + path
        return posixpath.normpath(path)

    def _host_path(self, norm: str) -> str | None:
        candidate = self._host_candidate(norm)
        return candidate if candidate and os.path.isfile(candidate) else None

    def _host_dir(self, norm: str) -> str | None:
        candidate = self._host_candidate(norm)
        return candidate if candidate and os.path.isdir(candidate) else None

    def _host_candidate(self, norm: str) -> str | None:
        if not self._rootfs or norm in self._deleted:
            return None
        candidate = os.path.realpath(os.path.join(self._rootfs, norm.lstrip("/")))
        if os.path.commonpath([self._rootfs, candidate]) != self._rootfs:
            self._log.vfs("blocked traversal: %r escapes the rootfs", norm, level=LogLevel.WARN)
            return None
        return candidate

    def _read_host(self, host: str) -> bytes:
        with open(host, "rb") as handle:
            return handle.read()

    def device_path(self, module: NativeModule) -> str:
        host = module.path.replace("\\", "/")
        if self._rootfs:
            root = self._rootfs.replace("\\", "/")
            if host.startswith(root):
                return "/" + host[len(root) :].lstrip("/")
        name = os.path.basename(host)
        if name in ("libc.so", "libm.so", "libdl.so", "libc++.so", "libc++_shared.so"):
            return f"/apex/com.android.runtime/{self._lib()}/bionic/{name}"
        return f"{self._emu.profile.native_lib_dir}/{name}"

    def _lib(self) -> str:
        return "lib64" if self._emu.arch.cpu_arch is CpuArch.ARM64 else "lib"

    def _map_entries(self) -> list[tuple[int, int, int, int, str, int, str]]:
        rw = MemoryProtectionFlag.READ | MemoryProtectionFlag.WRITE
        entries: list = []
        for index, module in enumerate(self._emu.loader.loaded_modules):
            inode = 200000 + index
            dev = "fd:03" if "/data/" in self.device_path(module) else "07:08"
            for start, size, perms in module.segments:
                entries.append((start, size, perms, start - module.base, dev, inode, self.device_path(module)))
        for region in self._emu.mem.iter_regions():
            if region.label.endswith(" LOAD") or region.label == "stack" or region.label in self._HIDDEN_REGIONS:
                continue
            if region.label in self._DEV_BACKED:
                name, dev, inode = self._DEV_BACKED[region.label]
            else:
                name, dev, inode = self._ANON_NAMES.get(region.label, ""), "00:00", 0
            entries.append((region.base, region.end - region.base, int(region.perms), 0, dev, inode, name))
        layout = self._emu.arch.layout
        entries.append((layout.STACK_TOP - layout.STACK_SIZE, layout.STACK_SIZE, rw, 0, "00:00", 0, "[stack]"))
        entries.sort(key=lambda entry: entry[0])
        return entries

    def _proc_maps(self) -> bytes:
        lines = [self._maps_line(*entry) for entry in self._map_entries()]
        return ("\n".join(lines) + "\n").encode()

    def _proc_smaps(self) -> bytes:
        lines = []
        for start, size, perms, offset, dev, inode, name in self._map_entries():
            lines.append(self._maps_line(start, size, perms, offset, dev, inode, name))
            kb = size // 1024
            rss = kb if perms & MemoryProtectionFlag.READ else 0
            dirty = kb if perms & MemoryProtectionFlag.WRITE else 0
            flags = "rd" + (" wr" if perms & MemoryProtectionFlag.WRITE else "") + (" ex" if perms & MemoryProtectionFlag.EXEC else "")
            lines += [
                f"Size:{kb:>19} kB",
                "KernelPageSize:        4 kB",
                "MMUPageSize:           4 kB",
                f"Rss:{rss:>20} kB",
                f"Pss:{rss:>20} kB",
                "Shared_Clean:          0 kB",
                f"Private_Dirty:{dirty:>10} kB",
                f"Referenced:{rss:>13} kB",
                f"Anonymous:{(rss if inode == 0 else 0):>14} kB",
                "Swap:                  0 kB",
                f"VmFlags: {flags} mr mw me",
            ]
        return ("\n".join(lines) + "\n").encode()

    @staticmethod
    def _maps_line(start: int, size: int, perms: int, offset: int, dev: str, inode: int, name: str) -> str:
        flags = ("r" if perms & MemoryProtectionFlag.READ else "-") + ("w" if perms & MemoryProtectionFlag.WRITE else "-") + ("x" if perms & MemoryProtectionFlag.EXEC else "-") + "p"
        return f"{start:08x}-{start + size:08x} {flags} {offset:08x} {dev} {inode:<11} {name}"

    def _mapped_kb(self) -> int:
        total = sum(size for module in self._emu.loader.loaded_modules for _, size, _ in module.segments)
        return (total + MemoryLayout.STACK_SIZE + 0x200000) // 1024

    def _proc_status(self) -> bytes:
        p = self._emu.profile
        u, g = p.process_uid, p.process_gid
        vm = self._mapped_kb()
        return (
            f"Name:\t{p.thread_name}\n"
            "Umask:\t0077\n"
            "State:\tS (sleeping)\n"
            f"Tgid:\t{p.process_pid}\n"
            f"Pid:\t{p.process_pid}\n"
            f"PPid:\t{p.parent_process_pid}\n"
            "TracerPid:\t0\n"
            f"Uid:\t{u}\t{u}\t{u}\t{u}\n"
            f"Gid:\t{g}\t{g}\t{g}\t{g}\n"
            "FDSize:\t256\n"
            f"Groups:\t{' '.join(str(gid) for gid in p.supplementary_groups)} \n"
            f"VmPeak:\t{vm + 40000:8d} kB\n"
            f"VmSize:\t{vm:8d} kB\n"
            f"VmRSS:\t{vm // 2:8d} kB\n"
            "Threads:\t1\n"
            f"SigQ:\t0/{self._emu.device.sigpending_limit}\n"
            "SigBlk:\t0000000000001204\n"
            "SigCgt:\t0000000e400086f8\n"
            "CapInh:\t0000000000000000\n"
            "CapPrm:\t0000000000000000\n"
            "CapEff:\t0000000000000000\n"
            "CapBnd:\t0000000000000000\n"
            "NoNewPrivs:\t1\n"
            "Seccomp:\t2\n"
            f"voluntary_ctxt_switches:\t{p.voluntary_ctxt_switches}\n"
            f"nonvoluntary_ctxt_switches:\t{p.nonvoluntary_ctxt_switches}\n"
        ).encode()

    def _proc_self_stat(self) -> bytes:
        p = self._emu.profile
        fields = [str(p.process_pid), f"({p.thread_name})", "S", str(p.parent_process_pid)]
        fields += ["0"] * 48
        start_uptime_s = max(0, self._emu.device.clock.boot_uptime_s - p.process_age_s)
        fields[21] = str(start_uptime_s * 100)
        if self._emu.mem.argv_ptr:
            fields[27] = str(self._emu.mem.argv_ptr - self._emu.arch.pointer_size)
        return (" ".join(fields) + "\n").encode()

    def _proc_stat_global(self) -> bytes:
        dev = self._emu.device
        per_cpu = dev.cpu_stat()
        fmt = lambda u, n, s, idle, io, sq: f"{u} {n} {s} {idle} {io} 0 {sq} 0 0 0"
        agg = [sum(col) for col in zip(*per_cpu)]
        lines = [f"cpu  {fmt(*agg)}"] + [f"cpu{i} {fmt(*pc)}" for i, pc in enumerate(per_cpu)]
        c = dev.stat_counters()
        lines += [
            f"intr {c['intr']}",
            f"ctxt {c['ctxt']}",
            f"btime {dev.clock.boot_realtime_s}",
            f"processes {c['processes']}",
            f"procs_running {c['procs_running']}",
            "procs_blocked 0",
            f"softirq {c['softirq']} 0 0 0 0 0 0 0 0 0",
        ]
        return ("\n".join(lines) + "\n").encode()

    def _proc_uptime(self) -> bytes:
        cpus = self._emu.device.cpu_count
        up = self._emu.device.clock.monotonic_ns() / 1_000_000_000
        return f"{up:.2f} {up * cpus * 0.9:.2f}\n".encode()

    def _proc_cmdline(self) -> bytes:
        return ((self._emu.profile.program_name or "") + "\x00").encode()

    def _proc_comm(self) -> bytes:
        return (self._emu.profile.thread_name[:15] + "\n").encode()

    def _proc_auxv(self) -> bytes:
        fmt = "<II" if self._emu.arch.pointer_size == 4 else "<QQ"
        out = bytearray()
        for a_type, a_val in self._emu.auxv.items():
            out += struct.pack(fmt, a_type, a_val)
        return bytes(out + struct.pack(fmt, Auxv.AT_NULL, 0))

    def _proc_cgroup(self) -> bytes:
        pkg = self._emu.profile.package_name
        return (
            (f"5:cpuacct:/uid_{self._emu.profile.process_uid}/pid_{self._emu.profile.process_pid}\n2:cpu:/\n0::/uid_{self._emu.profile.process_uid}/pid_{self._emu.profile.process_pid}\n").encode()
            if pkg
            else b""
        )

    def _proc_attr_current(self) -> bytes:
        return self._emu.profile.selinux_context.encode() + b"\x00"

    def _proc_mounts(self) -> bytes:
        return (
            b"rootfs / rootfs ro,seclabel 0 0\n"
            b"/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0\n"
            b"/dev/block/dm-1 /vendor ext4 ro,seclabel,relatime 0 0\n"
            b"/dev/block/by-name/userdata /data f2fs rw,seclabel,nosuid,nodev,noatime 0 0\n"
            b"tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0\n"
            b"proc /proc proc rw,relatime,gid=3009,hidepid=2 0 0\n"
        )

    def _proc_net_tcp(self, _family: int) -> bytes:
        return (b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000\n")

    def _proc_cpuinfo(self) -> bytes:
        d = self._emu.device
        count = d.cpu_count
        topology = d.cpu_topology()
        features = d.cpu_features(self._emu.arch.cpu_arch is CpuArch.ARM)
        blocks = []
        for index in range(count):
            part, variant = topology[index if index < len(topology) else 0]
            blocks.append(
                f"processor\t: {index}\n"
                f"BogoMIPS\t: {d.get('ro.cpuinfo.bogomips', '38.40')}\n"
                f"Features\t: {features}\n"
                f"CPU implementer\t: {d.get('ro.cpuinfo.implementer', '0x41')}\n"
                f"CPU architecture: 8\n"
                f"CPU variant\t: {variant}\n"
                f"CPU part\t: {part}\n"
                f"CPU revision\t: 0\n"
            )
        blocks.append(f"Hardware\t: {d.get('ro.cpuinfo.hardware', 'ARMv8')}\n")
        return "\n".join(blocks).encode()

    def _proc_meminfo(self) -> bytes:
        d = self._emu.device
        total = int(d.get("ro.mem.total_kb", "7635200") or "7635200")
        free = int(d.get("ro.mem.free_kb", "2894560") or "2894560")
        cached = total // 4
        return (
            f"MemTotal:       {total:8d} kB\n"
            f"MemFree:        {free:8d} kB\n"
            f"MemAvailable:   {free + cached:8d} kB\n"
            f"Buffers:          {total // 64:6d} kB\n"
            f"Cached:         {cached:8d} kB\n"
            f"SwapCached:            0 kB\n"
            f"Active:         {total // 5:8d} kB\n"
            f"Inactive:       {total // 6:8d} kB\n"
            f"AnonPages:      {total // 8:8d} kB\n"
            f"Mapped:         {total // 10:8d} kB\n"
            f"Shmem:          {total // 40:8d} kB\n"
            f"Slab:           {total // 30:8d} kB\n"
            f"SReclaimable:   {total // 50:8d} kB\n"
            f"KernelStack:       16384 kB\n"
            f"PageTables:        45056 kB\n"
            f"SwapTotal:       2097148 kB\n"
            f"SwapFree:        2097148 kB\n"
            f"CommitLimit:    {total // 2:8d} kB\n"
            f"VmallocTotal:  262930368 kB\n"
        ).encode()

    def _proc_version(self) -> bytes:
        d = self._emu.device
        user = d.get("ro.build.user", "android-build")
        host = d.get("ro.build.host", "abfarm")
        release = d.get("ro.kernel.osrelease", "5.10.0")
        version = d.get("ro.kernel.version", "#1 SMP")
        return (f"Linux version {release} ({user}@{host}) (Android clang version 14.0.7) {version}\n").encode()
