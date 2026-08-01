from __future__ import annotations

import inspect
import os
from typing import TYPE_CHECKING, Callable

from emulite.android.enums.errno import Errno
from emulite.android.enums.sockopt import SockOpt
from emulite.android.flags.clone_flag import CloneFlag
from emulite.android.flags.mmap_flag import MmapFlag
from emulite.android.structs.dirent64 import Dirent64
from emulite.android.structs.epoll_event import EpollEvent
from emulite.android.structs.iovec32 import Iovec32
from emulite.android.structs.msghdr32 import Msghdr32
from emulite.android.structs.pollfd import Pollfd
from emulite.android.structs.rlimit32 import RLimit32
from emulite.android.structs.rusage32 import Rusage32
from emulite.android.structs.sigaction32 import Sigaction32
from emulite.android.structs.sigcontext32 import Sigcontext32
from emulite.android.structs.stat32 import Stat32
from emulite.android.structs.statfs32 import StatFS32
from emulite.android.structs.statx import Statx
from emulite.android.structs.sysinfo32 import Sysinfo32
from emulite.android.structs.timespec32 import TimeSpec32
from emulite.android.structs.timeval32 import Timeval32
from emulite.android.structs.tms32 import Tms32
from emulite.android.structs.utsname import Utsname
from emulite.common.errors import UnimplementedSyscall, UnknownSyscall
from emulite.common.log import LogCategory, LogLevel
from emulite.cpu.backend import MemoryProtectionFlag
from emulite.cpu.registers.arm32_reg import Arm32Reg
from emulite.filesystem.enums.stat_type import StatType
from emulite.filesystem.structs.file_stat import FileStat
from emulite.memory import RW, MemoryLayout32

if TYPE_CHECKING:
    from emulite.android_emulator32 import AndroidEmulator32


class AndroidSyscallHandler32:
    _RLIM_INFINITY = 0xFFFFFFFF
    _SOL_SOCKET = 0x1
    _AT_FDCWD = -100
    _AT_REMOVEDIR = 0x200
    _SIG_DFL, _SIG_IGN, _SA_SIGINFO = 0, 1, 4

    def __init__(self, emu: "AndroidEmulator32", strict: bool = True):
        self._emu = emu
        self._be = emu.backend
        self._mem = emu.mem
        self._arch = emu.arch
        self._log = emu.log
        self._strict = strict
        self._profile = emu.profile
        self._clear_child_tid = 0
        self._robust_list_head = 0
        self._sigactions: dict[int, Sigaction32] = {}
        self._signal_mask = 0
        self._alt_stack = b""
        self._sched_affinity = b""
        self._thread_name: str | None = None
        self._dumpable: int | None = None
        self._umask_value = 0x3F
        self._next_tid = self._profile.process_tid + 1
        self._sigreturn_slot = 0
        self._signal_frames: list[int] = []
        self._impl = self._handlers()
        emu.trap.set_syscall_handler(self.dispatch)

    @staticmethod
    def _prot_str(prot: int) -> str:
        return "".join(ch if prot & bit else "-" for ch, bit in (("r", 1), ("w", 2), ("x", 4)))

    def dispatch(self) -> int:
        number = self._be.reg_read(self._arch.syscall_nr_reg)
        entry = self._impl.get(number)
        if entry is None:
            self._log.syscall("unknown syscall nr=%d -> throwing", number, level=LogLevel.ERROR)
            if self._strict:
                raise UnknownSyscall(number)
            return -Errno.ENOSYS

        handler, arg_count = entry
        registers = [
            self._be.reg_read(reg_id) for reg_id in self._arch.syscall_arg_regs[:arg_count]
        ]
        try:
            result = handler(*registers)
        except UnimplementedSyscall as unimplemented:
            self._log.syscall(
                "unimplemented %s (nr=%d) -> %s",
                unimplemented.name,
                unimplemented.number,
                "throwing" if self._strict else "-ENOSYS",
                level=LogLevel.ERROR,
            )
            if self._strict:
                raise
            return -Errno.ENOSYS

        result = 0 if result is None else result
        if self._log.is_enabled(LogCategory.Syscall, LogLevel.TRACE):
            self._log.syscall(
                "%s(%s) => %s",
                handler.__name__[1:],
                ", ".join(hex(value) for value in registers),
                hex(result),
                level=LogLevel.TRACE,
            )
        return result

    def _handlers(self) -> dict[int, "tuple[Callable[..., int], int]"]:
        raw: dict[int, Callable[..., int]] = {
            0: self._restart_syscall,
            1: self._exit,
            2: self._fork,
            3: self._read,
            4: self._write,
            5: self._open,
            6: self._close,
            8: self._creat,
            9: self._link,
            10: self._unlink,
            11: self._execve,
            12: self._chdir,
            14: self._mknod,
            15: self._chmod,
            16: self._lchown,
            19: self._lseek,
            20: self._getpid,
            21: self._mount,
            23: self._setuid,
            24: self._getuid,
            26: self._ptrace,
            29: self._pause,
            33: self._access,
            34: self._nice,
            36: self._sync,
            37: self._kill,
            38: self._rename,
            39: self._mkdir,
            40: self._rmdir,
            41: self._dup,
            42: self._pipe,
            43: self._times,
            45: self._brk,
            46: self._setgid,
            47: self._getgid,
            49: self._geteuid,
            50: self._getegid,
            51: self._acct,
            52: self._umount2,
            54: self._ioctl,
            55: self._fcntl,
            57: self._setpgid,
            60: self._umask,
            61: self._chroot,
            62: self._ustat,
            63: self._dup2,
            64: self._getppid,
            65: self._getpgrp,
            66: self._setsid,
            67: self._sigaction,
            70: self._setreuid,
            71: self._setregid,
            72: self._sigsuspend,
            73: self._sigpending,
            74: self._sethostname,
            75: self._setrlimit,
            77: self._getrusage,
            78: self._gettimeofday,
            79: self._settimeofday,
            80: self._getgroups,
            81: self._setgroups,
            83: self._symlink,
            85: self._readlink,
            86: self._uselib,
            87: self._swapon,
            88: self._reboot,
            91: self._munmap,
            92: self._truncate,
            93: self._ftruncate,
            94: self._fchmod,
            95: self._fchown,
            96: self._getpriority,
            97: self._setpriority,
            99: self._statfs,
            100: self._fstatfs,
            103: self._syslog,
            104: self._setitimer,
            105: self._getitimer,
            106: self._stat,
            107: self._lstat,
            108: self._fstat,
            111: self._vhangup,
            114: self._wait4,
            115: self._swapoff,
            116: self._sysinfo,
            118: self._fsync,
            119: self._sigreturn,
            120: self._clone,
            121: self._setdomainname,
            122: self._uname,
            124: self._adjtimex,
            125: self._mprotect,
            126: self._sigprocmask,
            128: self._init_module,
            129: self._delete_module,
            131: self._quotactl,
            132: self._getpgid,
            133: self._fchdir,
            134: self._bdflush,
            135: self._sysfs,
            136: self._personality,
            138: self._setfsuid,
            139: self._setfsgid,
            140: self._llseek,
            141: self._getdents,
            142: self._newselect,
            143: self._flock,
            144: self._msync,
            145: self._readv,
            146: self._writev,
            147: self._getsid,
            148: self._fdatasync,
            149: self._sysctl,
            150: self._mlock,
            151: self._munlock,
            152: self._mlockall,
            153: self._munlockall,
            154: self._sched_setparam,
            155: self._sched_getparam,
            156: self._sched_setscheduler,
            157: self._sched_getscheduler,
            158: self._sched_yield,
            159: self._sched_get_priority_max,
            160: self._sched_get_priority_min,
            161: self._sched_rr_get_interval,
            162: self._nanosleep,
            163: self._mremap,
            164: self._setresuid,
            165: self._getresuid,
            168: self._poll,
            169: self._nfsservctl,
            170: self._setresgid,
            171: self._getresgid,
            172: self._prctl,
            173: self._rt_sigreturn,
            174: self._rt_sigaction,
            175: self._rt_sigprocmask,
            176: self._rt_sigpending,
            177: self._rt_sigtimedwait,
            178: self._rt_sigqueueinfo,
            179: self._rt_sigsuspend,
            180: self._pread64,
            181: self._pwrite64,
            182: self._chown,
            183: self._getcwd,
            184: self._capget,
            185: self._capset,
            186: self._sigaltstack,
            187: self._sendfile,
            190: self._vfork,
            191: self._ugetrlimit,
            192: self._mmap2,
            193: self._truncate64,
            194: self._ftruncate64,
            195: self._stat64,
            196: self._lstat64,
            197: self._fstat64,
            198: self._lchown,
            199: self._getuid,
            200: self._getgid,
            201: self._geteuid,
            202: self._getegid,
            203: self._setreuid,
            204: self._setregid,
            205: self._getgroups,
            206: self._setgroups,
            207: self._fchown,
            208: self._setresuid,
            209: self._getresuid,
            210: self._setresgid,
            211: self._getresgid,
            212: self._chown,
            213: self._setuid,
            214: self._setgid,
            215: self._setfsuid,
            216: self._setfsgid,
            217: self._getdents64,
            218: self._pivot_root,
            219: self._mincore,
            220: self._madvise,
            221: self._fcntl64,
            224: self._gettid,
            225: self._readahead,
            226: self._setxattr,
            227: self._lsetxattr,
            228: self._fsetxattr,
            229: self._getxattr,
            230: self._lgetxattr,
            231: self._fgetxattr,
            232: self._listxattr,
            233: self._llistxattr,
            234: self._flistxattr,
            235: self._removexattr,
            236: self._lremovexattr,
            237: self._fremovexattr,
            238: self._tkill,
            239: self._sendfile64,
            240: self._futex,
            241: self._sched_setaffinity,
            242: self._sched_getaffinity,
            243: self._io_setup,
            244: self._io_destroy,
            245: self._io_getevents,
            246: self._io_submit,
            247: self._io_cancel,
            248: self._exit_group,
            249: self._lookup_dcookie,
            250: self._epoll_create,
            251: self._epoll_ctl,
            252: self._epoll_wait,
            253: self._remap_file_pages,
            256: self._set_tid_address,
            257: self._timer_create,
            258: self._timer_settime,
            259: self._timer_gettime,
            260: self._timer_getoverrun,
            261: self._timer_delete,
            262: self._clock_settime,
            263: self._clock_gettime,
            264: self._clock_getres,
            265: self._clock_nanosleep,
            266: self._statfs64,
            267: self._fstatfs64,
            268: self._tgkill,
            269: self._utimes,
            270: self._arm_fadvise64_64,
            271: self._pciconfig_iobase,
            272: self._pciconfig_read,
            273: self._pciconfig_write,
            274: self._mq_open,
            275: self._mq_unlink,
            276: self._mq_timedsend,
            277: self._mq_timedreceive,
            278: self._mq_notify,
            279: self._mq_getsetattr,
            280: self._waitid,
            281: self._socket,
            282: self._bind,
            283: self._connect,
            284: self._listen,
            285: self._accept,
            286: self._getsockname,
            287: self._getpeername,
            288: self._socketpair,
            289: self._send,
            290: self._sendto,
            291: self._recv,
            292: self._recvfrom,
            293: self._shutdown,
            294: self._setsockopt,
            295: self._getsockopt,
            296: self._sendmsg,
            297: self._recvmsg,
            298: self._semop,
            299: self._semget,
            300: self._semctl,
            301: self._msgsnd,
            302: self._msgrcv,
            303: self._msgget,
            304: self._msgctl,
            305: self._shmat,
            306: self._shmdt,
            307: self._shmget,
            308: self._shmctl,
            309: self._add_key,
            310: self._request_key,
            311: self._keyctl,
            312: self._semtimedop,
            313: self._vserver,
            314: self._ioprio_set,
            315: self._ioprio_get,
            316: self._inotify_init,
            317: self._inotify_add_watch,
            318: self._inotify_rm_watch,
            319: self._mbind,
            320: self._get_mempolicy,
            321: self._set_mempolicy,
            322: self._openat,
            323: self._mkdirat,
            324: self._mknodat,
            325: self._fchownat,
            326: self._futimesat,
            327: self._fstatat64,
            328: self._unlinkat,
            329: self._renameat,
            330: self._linkat,
            331: self._symlinkat,
            332: self._readlinkat,
            333: self._fchmodat,
            334: self._faccessat,
            335: self._pselect6,
            336: self._ppoll,
            337: self._unshare,
            338: self._set_robust_list,
            339: self._get_robust_list,
            340: self._splice,
            341: self._arm_sync_file_range,
            342: self._tee,
            343: self._vmsplice,
            344: self._move_pages,
            345: self._getcpu,
            346: self._epoll_pwait,
            347: self._kexec_load,
            348: self._utimensat,
            349: self._signalfd,
            350: self._timerfd_create,
            351: self._eventfd,
            352: self._fallocate,
            353: self._timerfd_settime,
            354: self._timerfd_gettime,
            355: self._signalfd4,
            356: self._eventfd2,
            357: self._epoll_create1,
            358: self._dup3,
            359: self._pipe2,
            360: self._inotify_init1,
            361: self._preadv,
            362: self._pwritev,
            363: self._rt_tgsigqueueinfo,
            364: self._perf_event_open,
            365: self._recvmmsg,
            366: self._accept4,
            367: self._fanotify_init,
            368: self._fanotify_mark,
            369: self._prlimit64,
            370: self._name_to_handle_at,
            371: self._open_by_handle_at,
            372: self._clock_adjtime,
            373: self._syncfs,
            374: self._sendmmsg,
            375: self._setns,
            376: self._process_vm_readv,
            377: self._process_vm_writev,
            378: self._kcmp,
            379: self._finit_module,
            380: self._sched_setattr,
            381: self._sched_getattr,
            382: self._renameat2,
            383: self._seccomp,
            384: self._getrandom,
            385: self._memfd_create,
            386: self._bpf,
            387: self._execveat,
            388: self._userfaultfd,
            389: self._membarrier,
            390: self._mlock2,
            391: self._copy_file_range,
            392: self._preadv2,
            393: self._pwritev2,
            394: self._pkey_mprotect,
            395: self._pkey_alloc,
            396: self._pkey_free,
            397: self._statx,
            398: self._rseq,
            399: self._io_pgetevents,
            400: self._migrate_pages,
            401: self._kexec_file_load,
            403: self._clock_gettime64,
            404: self._clock_settime64,
            405: self._clock_adjtime64,
            406: self._clock_getres_time64,
            407: self._clock_nanosleep_time64,
            408: self._timer_gettime64,
            409: self._timer_settime64,
            410: self._timerfd_gettime64,
            411: self._timerfd_settime64,
            412: self._utimensat_time64,
            413: self._pselect6_time64,
            414: self._ppoll_time64,
            416: self._io_pgetevents_time64,
            417: self._recvmmsg_time64,
            418: self._mq_timedsend_time64,
            419: self._mq_timedreceive_time64,
            420: self._semtimedop_time64,
            421: self._rt_sigtimedwait_time64,
            422: self._futex_time64,
            423: self._sched_rr_get_interval_time64,
            424: self._pidfd_send_signal,
            425: self._io_uring_setup,
            426: self._io_uring_enter,
            427: self._io_uring_register,
            428: self._open_tree,
            429: self._move_mount,
            430: self._fsopen,
            431: self._fsconfig,
            432: self._fsmount,
            433: self._fspick,
            434: self._pidfd_open,
            435: self._clone3,
            436: self._close_range,
            437: self._openat2,
            438: self._pidfd_getfd,
            439: self._faccessat2,
            440: self._process_madvise,
            441: self._epoll_pwait2,
            442: self._mount_setattr,
            443: self._quotactl_fd,
            444: self._landlock_create_ruleset,
            445: self._landlock_add_rule,
            446: self._landlock_restrict_self,
            448: self._process_mrelease,
            449: self._futex_waitv,
            450: self._set_mempolicy_home_node,
            0x0F0001: self._arm_breakpoint,
            0x0F0002: self._arm_cacheflush,
            0x0F0003: self._arm_usr26,
            0x0F0004: self._arm_usr32,
            0x0F0005: self._arm_set_tls,
            0x0F0006: self._arm_get_tls,
        }
        return {number: (fn, len(inspect.signature(fn).parameters)) for number, fn in raw.items()}

    def _fork(self) -> int:
        raise UnimplementedSyscall("fork (no process model)", 2)

    def _vfork(self) -> int:
        raise UnimplementedSyscall("vfork (no process model)", 190)

    def _mknod(self) -> int:
        raise UnimplementedSyscall("mknod", 14)

    def _ustat(self) -> int:
        raise UnimplementedSyscall("ustat", 62)

    def _uselib(self) -> int:
        raise UnimplementedSyscall("uselib", 86)

    def _bdflush(self) -> int:
        raise UnimplementedSyscall("bdflush", 134)

    def _sysfs(self) -> int:
        raise UnimplementedSyscall("sysfs", 135)

    def _sysctl(self) -> int:
        raise UnimplementedSyscall("_sysctl", 149)

    def _nice(self) -> int:
        raise UnimplementedSyscall("nice", 34)

    def _pause(self) -> int:
        raise UnimplementedSyscall("pause", 29)

    def _getpgrp(self) -> int:
        raise UnimplementedSyscall("getpgrp", 65)

    def _vserver(self) -> int:
        raise UnimplementedSyscall("vserver", 313)

    def _futimesat(self) -> int:
        raise UnimplementedSyscall("futimesat", 326)

    def _utimes(self) -> int:
        raise UnimplementedSyscall("utimes", 269)

    def _pciconfig_iobase(self) -> int:
        raise UnimplementedSyscall("pciconfig_iobase", 271)

    def _pciconfig_read(self) -> int:
        raise UnimplementedSyscall("pciconfig_read", 272)

    def _pciconfig_write(self) -> int:
        raise UnimplementedSyscall("pciconfig_write", 273)

    def _io_setup(self) -> int:
        raise UnimplementedSyscall("io_setup", 243)

    def _io_destroy(self) -> int:
        raise UnimplementedSyscall("io_destroy", 244)

    def _io_submit(self) -> int:
        raise UnimplementedSyscall("io_submit", 246)

    def _io_cancel(self) -> int:
        raise UnimplementedSyscall("io_cancel", 247)

    def _io_getevents(self) -> int:
        raise UnimplementedSyscall("io_getevents", 245)

    def _setxattr(self) -> int:
        raise UnimplementedSyscall("setxattr", 226)

    def _lsetxattr(self) -> int:
        raise UnimplementedSyscall("lsetxattr", 227)

    def _fsetxattr(self) -> int:
        raise UnimplementedSyscall("fsetxattr", 228)

    def _getxattr(self) -> int:
        raise UnimplementedSyscall("getxattr", 229)

    def _lgetxattr(self) -> int:
        raise UnimplementedSyscall("lgetxattr", 230)

    def _fgetxattr(self) -> int:
        raise UnimplementedSyscall("fgetxattr", 231)

    def _listxattr(self) -> int:
        raise UnimplementedSyscall("listxattr", 232)

    def _llistxattr(self) -> int:
        raise UnimplementedSyscall("llistxattr", 233)

    def _flistxattr(self) -> int:
        raise UnimplementedSyscall("flistxattr", 234)

    def _removexattr(self) -> int:
        raise UnimplementedSyscall("removexattr", 235)

    def _lremovexattr(self) -> int:
        raise UnimplementedSyscall("lremovexattr", 236)

    def _fremovexattr(self) -> int:
        raise UnimplementedSyscall("fremovexattr", 237)

    def _lookup_dcookie(self) -> int:
        raise UnimplementedSyscall("lookup_dcookie", 249)

    def _inotify_init1(self) -> int:
        raise UnimplementedSyscall("inotify_init1", 360)

    def _inotify_init(self) -> int:
        raise UnimplementedSyscall("inotify_init", 316)

    def _inotify_add_watch(self) -> int:
        raise UnimplementedSyscall("inotify_add_watch", 317)

    def _inotify_rm_watch(self) -> int:
        raise UnimplementedSyscall("inotify_rm_watch", 318)

    def _ioprio_set(self) -> int:
        raise UnimplementedSyscall("ioprio_set", 314)

    def _ioprio_get(self) -> int:
        raise UnimplementedSyscall("ioprio_get", 315)

    def _flock(self) -> int:
        raise UnimplementedSyscall("flock", 143)

    def _mknodat(self) -> int:
        raise UnimplementedSyscall("mknodat", 324)

    def _umount2(self) -> int:
        raise UnimplementedSyscall("umount2", 52)

    def _mount(self) -> int:
        raise UnimplementedSyscall("mount", 21)

    def _pivot_root(self) -> int:
        raise UnimplementedSyscall("pivot_root", 218)

    def _nfsservctl(self) -> int:
        raise UnimplementedSyscall("nfsservctl", 169)

    def _quotactl(self) -> int:
        raise UnimplementedSyscall("quotactl", 131)

    def _preadv(self) -> int:
        raise UnimplementedSyscall("preadv", 361)

    def _pwritev(self) -> int:
        raise UnimplementedSyscall("pwritev", 362)

    def _arm_sync_file_range(self) -> int:
        raise UnimplementedSyscall("arm_sync_file_range", 341)

    def _timerfd_create(self) -> int:
        raise UnimplementedSyscall("timerfd_create", 350)

    def _timerfd_settime(self) -> int:
        raise UnimplementedSyscall("timerfd_settime", 353)

    def _timerfd_gettime(self) -> int:
        raise UnimplementedSyscall("timerfd_gettime", 354)

    def _utimensat(self) -> int:
        raise UnimplementedSyscall("utimensat", 348)

    def _acct(self) -> int:
        raise UnimplementedSyscall("acct", 51)

    def _capget(self) -> int:
        raise UnimplementedSyscall("capget", 184)

    def _capset(self) -> int:
        raise UnimplementedSyscall("capset", 185)

    def _personality(self) -> int:
        raise UnimplementedSyscall("personality", 136)

    def _waitid(self) -> int:
        raise UnimplementedSyscall("waitid", 280)

    def _wait4(self) -> int:
        raise UnimplementedSyscall("wait4", 114)

    def _unshare(self) -> int:
        raise UnimplementedSyscall("unshare", 337)

    def _getitimer(self) -> int:
        raise UnimplementedSyscall("getitimer", 105)

    def _setitimer(self) -> int:
        raise UnimplementedSyscall("setitimer", 104)

    def _kexec_load(self) -> int:
        raise UnimplementedSyscall("kexec_load", 347)

    def _init_module(self) -> int:
        raise UnimplementedSyscall("init_module", 128)

    def _delete_module(self) -> int:
        raise UnimplementedSyscall("delete_module", 129)

    def _timer_create(self) -> int:
        raise UnimplementedSyscall("timer_create", 257)

    def _timer_gettime(self) -> int:
        raise UnimplementedSyscall("timer_gettime", 259)

    def _timer_getoverrun(self) -> int:
        raise UnimplementedSyscall("timer_getoverrun", 260)

    def _timer_settime(self) -> int:
        raise UnimplementedSyscall("timer_settime", 258)

    def _timer_delete(self) -> int:
        raise UnimplementedSyscall("timer_delete", 261)

    def _clock_settime(self) -> int:
        raise UnimplementedSyscall("clock_settime", 262)

    def _syslog(self) -> int:
        raise UnimplementedSyscall("syslog", 103)

    def _ptrace(self) -> int:
        raise UnimplementedSyscall("ptrace", 26)

    def _sched_setparam(self) -> int:
        raise UnimplementedSyscall("sched_setparam", 154)

    def _sched_setscheduler(self) -> int:
        raise UnimplementedSyscall("sched_setscheduler", 156)

    def _sched_rr_get_interval(self) -> int:
        raise UnimplementedSyscall("sched_rr_get_interval", 161)

    def _reboot(self) -> int:
        raise UnimplementedSyscall("reboot", 88)

    def _swapon(self) -> int:
        raise UnimplementedSyscall("swapon", 87)

    def _swapoff(self) -> int:
        raise UnimplementedSyscall("swapoff", 115)

    def _sethostname(self) -> int:
        raise UnimplementedSyscall("sethostname", 74)

    def _setdomainname(self) -> int:
        raise UnimplementedSyscall("setdomainname", 121)

    def _settimeofday(self) -> int:
        raise UnimplementedSyscall("settimeofday", 79)

    def _adjtimex(self) -> int:
        raise UnimplementedSyscall("adjtimex", 124)

    def _setpgid(self) -> int:
        raise UnimplementedSyscall("setpgid", 57)

    def _getpgid(self) -> int:
        raise UnimplementedSyscall("getpgid", 132)

    def _getsid(self) -> int:
        raise UnimplementedSyscall("getsid", 147)

    def _setsid(self) -> int:
        raise UnimplementedSyscall("setsid", 66)

    def _setgroups(self) -> int:
        raise UnimplementedSyscall("setgroups", 81)

    def _mq_open(self) -> int:
        raise UnimplementedSyscall("mq_open", 274)

    def _mq_unlink(self) -> int:
        raise UnimplementedSyscall("mq_unlink", 275)

    def _mq_timedsend(self) -> int:
        raise UnimplementedSyscall("mq_timedsend", 276)

    def _mq_timedreceive(self) -> int:
        raise UnimplementedSyscall("mq_timedreceive", 277)

    def _mq_notify(self) -> int:
        raise UnimplementedSyscall("mq_notify", 278)

    def _mq_getsetattr(self) -> int:
        raise UnimplementedSyscall("mq_getsetattr", 279)

    def _msgget(self) -> int:
        raise UnimplementedSyscall("msgget", 303)

    def _msgctl(self) -> int:
        raise UnimplementedSyscall("msgctl", 304)

    def _msgrcv(self) -> int:
        raise UnimplementedSyscall("msgrcv", 302)

    def _msgsnd(self) -> int:
        raise UnimplementedSyscall("msgsnd", 301)

    def _semget(self) -> int:
        raise UnimplementedSyscall("semget", 299)

    def _semctl(self) -> int:
        raise UnimplementedSyscall("semctl", 300)

    def _semtimedop(self) -> int:
        raise UnimplementedSyscall("semtimedop", 312)

    def _semop(self) -> int:
        raise UnimplementedSyscall("semop", 298)

    def _shmget(self) -> int:
        raise UnimplementedSyscall("shmget", 307)

    def _shmctl(self) -> int:
        raise UnimplementedSyscall("shmctl", 308)

    def _shmat(self) -> int:
        raise UnimplementedSyscall("shmat", 305)

    def _shmdt(self) -> int:
        raise UnimplementedSyscall("shmdt", 306)

    def _add_key(self) -> int:
        raise UnimplementedSyscall("add_key", 309)

    def _request_key(self) -> int:
        raise UnimplementedSyscall("request_key", 310)

    def _keyctl(self) -> int:
        raise UnimplementedSyscall("keyctl", 311)

    def _readahead(self) -> int:
        raise UnimplementedSyscall("readahead", 225)

    def _arm_fadvise64_64(self) -> int:
        raise UnimplementedSyscall("arm_fadvise64_64", 270)

    def _mincore(self) -> int:
        raise UnimplementedSyscall("mincore", 219)

    def _remap_file_pages(self) -> int:
        raise UnimplementedSyscall("remap_file_pages", 253)

    def _mbind(self) -> int:
        raise UnimplementedSyscall("mbind", 319)

    def _get_mempolicy(self) -> int:
        raise UnimplementedSyscall("get_mempolicy", 320)

    def _set_mempolicy(self) -> int:
        raise UnimplementedSyscall("set_mempolicy", 321)

    def _migrate_pages(self) -> int:
        raise UnimplementedSyscall("migrate_pages", 400)

    def _move_pages(self) -> int:
        raise UnimplementedSyscall("move_pages", 344)

    def _rt_tgsigqueueinfo(self) -> int:
        raise UnimplementedSyscall("rt_tgsigqueueinfo", 363)

    def _perf_event_open(self) -> int:
        raise UnimplementedSyscall("perf_event_open", 364)

    def _accept(self) -> int:
        raise UnimplementedSyscall("accept", 285)

    def _accept4(self) -> int:
        raise UnimplementedSyscall("accept4", 366)

    def _recvmmsg(self) -> int:
        raise UnimplementedSyscall("recvmmsg", 365)

    def _sendmmsg(self) -> int:
        raise UnimplementedSyscall("sendmmsg", 374)

    def _fanotify_init(self) -> int:
        raise UnimplementedSyscall("fanotify_init", 367)

    def _fanotify_mark(self) -> int:
        raise UnimplementedSyscall("fanotify_mark", 368)

    def _name_to_handle_at(self) -> int:
        raise UnimplementedSyscall("name_to_handle_at", 370)

    def _open_by_handle_at(self) -> int:
        raise UnimplementedSyscall("open_by_handle_at", 371)

    def _clock_adjtime(self) -> int:
        raise UnimplementedSyscall("clock_adjtime", 372)

    def _syncfs(self) -> int:
        raise UnimplementedSyscall("syncfs", 373)

    def _setns(self) -> int:
        raise UnimplementedSyscall("setns", 375)

    def _process_vm_readv(self) -> int:
        raise UnimplementedSyscall("process_vm_readv", 376)

    def _process_vm_writev(self) -> int:
        raise UnimplementedSyscall("process_vm_writev", 377)

    def _kcmp(self) -> int:
        raise UnimplementedSyscall("kcmp", 378)

    def _finit_module(self) -> int:
        raise UnimplementedSyscall("finit_module", 379)

    def _sched_setattr(self) -> int:
        raise UnimplementedSyscall("sched_setattr", 380)

    def _sched_getattr(self) -> int:
        raise UnimplementedSyscall("sched_getattr", 381)

    def _seccomp(self) -> int:
        raise UnimplementedSyscall("seccomp", 383)

    def _memfd_create(self) -> int:
        raise UnimplementedSyscall("memfd_create", 385)

    def _bpf(self) -> int:
        raise UnimplementedSyscall("bpf", 386)

    def _execveat(self) -> int:
        raise UnimplementedSyscall("execveat", 387)

    def _userfaultfd(self) -> int:
        raise UnimplementedSyscall("userfaultfd", 388)

    def _copy_file_range(self) -> int:
        raise UnimplementedSyscall("copy_file_range", 391)

    def _preadv2(self) -> int:
        raise UnimplementedSyscall("preadv2", 392)

    def _pwritev2(self) -> int:
        raise UnimplementedSyscall("pwritev2", 393)

    def _pkey_mprotect(self) -> int:
        raise UnimplementedSyscall("pkey_mprotect", 394)

    def _pkey_alloc(self) -> int:
        raise UnimplementedSyscall("pkey_alloc", 395)

    def _pkey_free(self) -> int:
        raise UnimplementedSyscall("pkey_free", 396)

    def _io_pgetevents(self) -> int:
        raise UnimplementedSyscall("io_pgetevents", 399)

    def _kexec_file_load(self) -> int:
        raise UnimplementedSyscall("kexec_file_load", 401)

    def _pidfd_send_signal(self) -> int:
        raise UnimplementedSyscall("pidfd_send_signal", 424)

    def _io_uring_setup(self) -> int:
        raise UnimplementedSyscall("io_uring_setup", 425)

    def _io_uring_enter(self) -> int:
        raise UnimplementedSyscall("io_uring_enter", 426)

    def _io_uring_register(self) -> int:
        raise UnimplementedSyscall("io_uring_register", 427)

    def _open_tree(self) -> int:
        raise UnimplementedSyscall("open_tree", 428)

    def _move_mount(self) -> int:
        raise UnimplementedSyscall("move_mount", 429)

    def _fsopen(self) -> int:
        raise UnimplementedSyscall("fsopen", 430)

    def _fsconfig(self) -> int:
        raise UnimplementedSyscall("fsconfig", 431)

    def _fsmount(self) -> int:
        raise UnimplementedSyscall("fsmount", 432)

    def _fspick(self) -> int:
        raise UnimplementedSyscall("fspick", 433)

    def _pidfd_open(self) -> int:
        raise UnimplementedSyscall("pidfd_open", 434)

    def _clone3(self) -> int:
        raise UnimplementedSyscall("clone3", 435)

    def _openat2(self) -> int:
        raise UnimplementedSyscall("openat2", 437)

    def _pidfd_getfd(self) -> int:
        raise UnimplementedSyscall("pidfd_getfd", 438)

    def _process_madvise(self) -> int:
        raise UnimplementedSyscall("process_madvise", 440)

    def _mount_setattr(self) -> int:
        raise UnimplementedSyscall("mount_setattr", 442)

    def _quotactl_fd(self) -> int:
        raise UnimplementedSyscall("quotactl_fd", 443)

    def _landlock_create_ruleset(self) -> int:
        raise UnimplementedSyscall("landlock_create_ruleset", 444)

    def _landlock_add_rule(self) -> int:
        raise UnimplementedSyscall("landlock_add_rule", 445)

    def _landlock_restrict_self(self) -> int:
        raise UnimplementedSyscall("landlock_restrict_self", 446)

    def _process_mrelease(self) -> int:
        raise UnimplementedSyscall("process_mrelease", 448)

    def _futex_waitv(self) -> int:
        raise UnimplementedSyscall("futex_waitv", 449)

    def _set_mempolicy_home_node(self) -> int:
        raise UnimplementedSyscall("set_mempolicy_home_node", 450)

    def _restart_syscall(self) -> int:
        raise UnimplementedSyscall("restart_syscall", 0)

    def _splice(self) -> int:
        raise UnimplementedSyscall("splice", 340)

    def _tee(self) -> int:
        raise UnimplementedSyscall("tee", 342)

    def _vmsplice(self) -> int:
        raise UnimplementedSyscall("vmsplice", 343)

    def _symlinkat(self) -> int:
        raise UnimplementedSyscall("symlinkat", 331)

    def _linkat(self) -> int:
        raise UnimplementedSyscall("linkat", 330)

    def _truncate(self, path_ptr: int, length: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        result = self._emu.vfs.truncate(path, length)
        self._log.syscall("truncate(%r, %d) => %d", path, length, result)
        return result

    def _clock_gettime64(self, clock_id: int, timespec_ptr: int) -> int:
        realtime = clock_id in (0, 5)
        nanos = self._clock_now(realtime)
        self._mem.write_u64(timespec_ptr, nanos // 1_000_000_000)
        self._mem.write_u64(timespec_ptr + 8, nanos % 1_000_000_000)
        self._log.syscall(
            "clock_gettime64(%s=%d) => %d.%09d",
            "REALTIME" if realtime else "MONOTONIC",
            clock_id,
            nanos // 1_000_000_000,
            nanos % 1_000_000_000,
        )
        return 0

    def _clock_getres_time64(self, _clock_id: int, res_ptr: int) -> int:
        if res_ptr:
            self._mem.write_u64(res_ptr, 0)
            self._mem.write_u64(res_ptr + 8, 1)
        self._log.syscall("clock_getres_time64() => 0 (1ns)")
        return 0

    def _clock_nanosleep_time64(self, clockid: int, flags: int, req_ptr: int, rem_ptr: int) -> int:
        sec, nsec = self._mem.read_s64(req_ptr), self._mem.read_u64(req_ptr + 8)
        request_ns = sec * 1_000_000_000 + nsec
        if flags & 1:  # TIMER_ABSTIME: advance the virtual clock to the deadline
            clock = self._emu.device.clock
            (clock.sync_realtime if clockid in (0, 5) else clock.sync_monotonic)(request_ns)
        else:
            self._clock_advance(request_ns)
            if rem_ptr:
                self._mem.write_u64(rem_ptr, 0)
                self._mem.write_u64(rem_ptr + 8, 0)
        self._log.syscall(
            "clock_nanosleep_time64(flags=%#x, %d.%09ds) => 0 (virtual)", flags, sec, nsec
        )
        return 0

    def _clock_settime64(self) -> int:
        raise UnimplementedSyscall("clock_settime64", 404)

    def _clock_adjtime64(self) -> int:
        raise UnimplementedSyscall("clock_adjtime64", 405)

    def _timer_gettime64(self) -> int:
        raise UnimplementedSyscall("timer_gettime64", 408)

    def _timer_settime64(self) -> int:
        raise UnimplementedSyscall("timer_settime64", 409)

    def _timerfd_gettime64(self) -> int:
        raise UnimplementedSyscall("timerfd_gettime64", 410)

    def _timerfd_settime64(self) -> int:
        raise UnimplementedSyscall("timerfd_settime64", 411)

    def _utimensat_time64(self) -> int:
        raise UnimplementedSyscall("utimensat_time64", 412)

    def _pselect6_time64(
        self, nfds: int, readfds: int, writefds: int, exceptfds: int, _timeout: int, _sig: int
    ) -> int:
        return self._pselect6(nfds, readfds, writefds, exceptfds, 0, 0)

    def _ppoll_time64(self, fds_ptr: int, nfds: int, _tmo: int, _sig: int, _sigsize: int) -> int:
        return self._ppoll(fds_ptr, nfds, 0, 0, 0)

    def _io_pgetevents_time64(self) -> int:
        raise UnimplementedSyscall("io_pgetevents_time64", 416)

    def _recvmmsg_time64(self) -> int:
        raise UnimplementedSyscall("recvmmsg_time64", 417)

    def _mq_timedsend_time64(self) -> int:
        raise UnimplementedSyscall("mq_timedsend_time64", 418)

    def _mq_timedreceive_time64(self) -> int:
        raise UnimplementedSyscall("mq_timedreceive_time64", 419)

    def _semtimedop_time64(self) -> int:
        raise UnimplementedSyscall("semtimedop_time64", 420)

    def _rt_sigtimedwait_time64(self) -> int:
        raise UnimplementedSyscall("rt_sigtimedwait_time64", 421)

    def _sched_rr_get_interval_time64(self) -> int:
        raise UnimplementedSyscall("sched_rr_get_interval_time64", 423)

    def _futex_time64(self, uaddr: int, op: int, val: int) -> int:
        return self._futex(uaddr, op, val)

    def _getcwd(self, buf: int, size: int) -> int:
        cwd = b"/"
        data = cwd + b"\x00"
        if len(data) > size:
            self._log.syscall("getcwd(size=%d) => -ERANGE", size, level=LogLevel.WARN)
            return -Errno.ERANGE
        self._mem.write(buf, data)
        self._log.syscall("getcwd() => %r", cwd.decode())
        return len(data)

    def _eventfd2(self, initval: int, flags: int) -> int:
        fd = self._emu.vfs.eventfd(initval, bool(flags & 1))
        self._log.syscall("eventfd2(%d, flags=%#x) => %d", initval, flags, fd)
        return fd

    def _eventfd(self, initval: int) -> int:
        return self._eventfd2(initval, 0)

    def _epoll_create1(self, flags: int) -> int:
        fd = self._emu.vfs.epoll_create()
        self._log.syscall("epoll_create1(flags=%#x) => %d", flags, fd)
        return fd

    def _epoll_create(self, _size: int) -> int:
        return self._epoll_create1(0)

    def _epoll_ctl(self, epfd: int, op: int, fd: int, event_ptr: int) -> int:
        event = EpollEvent.read_from(self._mem, event_ptr) if event_ptr else EpollEvent()
        result = self._emu.vfs.epoll_ctl(epfd, op, fd, event.events, event.data)
        self._log.syscall("epoll_ctl(epfd=%d, op=%d, fd=%d) => %d", epfd, op, fd, result)
        return result

    def _epoll_pwait(
        self,
        epfd: int,
        events_ptr: int,
        maxevents: int,
        _timeout: int,
        _sigmask: int,
        _sigsetsize: int,
    ) -> int:
        ready = self._emu.vfs.epoll_wait(epfd, maxevents)
        if ready is None:
            self._log.syscall("epoll_pwait(epfd=%d) => -EBADF", epfd, level=LogLevel.WARN)
            return -Errno.EBADF
        for i, (_fd, events, data) in enumerate(ready):
            EpollEvent(events=events, data=data).write_to(
                self._mem, events_ptr + i * EpollEvent.SIZE
            )
        self._log.syscall("epoll_pwait(epfd %d) => %d ready", epfd, len(ready))
        return len(ready)

    def _epoll_wait(self, epfd: int, events_ptr: int, maxevents: int, _timeout: int) -> int:
        return self._epoll_pwait(epfd, events_ptr, maxevents, 0, 0, 0)

    def _dup(self, oldfd: int) -> int:
        result = self._emu.vfs.dup(oldfd)
        self._log.syscall("dup(%d) => %d", oldfd, result)
        return result

    def _dup3(self, oldfd: int, newfd: int, _flags: int) -> int:
        if oldfd == newfd:
            self._log.syscall("dup3(%d, %d) => -EINVAL", oldfd, newfd, level=LogLevel.WARN)
            return -Errno.EINVAL
        if self._emu.vfs.fstat(oldfd) is None:
            self._log.syscall("dup3(%d, %d) => -EBADF", oldfd, newfd, level=LogLevel.WARN)
            return -Errno.EBADF
        self._emu.vfs.close(newfd)
        result = self._emu.vfs.dup_to(oldfd, newfd)
        self._log.syscall("dup3(%d, %d) => %d", oldfd, newfd, result)
        return result

    def _dup2(self, oldfd: int, newfd: int) -> int:
        if oldfd == newfd:
            result = newfd if self._emu.vfs.fstat(oldfd) is not None else -Errno.EBADF
            level = LogLevel.DEBUG if result >= 0 else LogLevel.WARN
            self._log.syscall("dup2(%d, %d) => %d", oldfd, newfd, result, level=level)
            return result
        return self._dup3(oldfd, newfd, 0)

    def _fcntl(self, fd: int, cmd: int, arg: int) -> int:
        if self._emu.vfs.fstat(fd) is None:
            self._log.syscall("fcntl(%d, cmd=%d) => -EBADF", fd, cmd, level=LogLevel.WARN)
            return -Errno.EBADF
        if cmd in (0, 1030):
            result = self._emu.vfs.dup(fd, min_fd=arg)
            self._log.syscall("fcntl(%d, F_DUPFD, %d) => %d", fd, arg, result)
            return result
        self._log.syscall("fcntl(%d, cmd=%d) => 0", fd, cmd)
        return 0

    def _fcntl64(self, fd: int, cmd: int, arg: int) -> int:
        return self._fcntl(fd, cmd, arg)

    def _ioctl(self, fd: int, request: int, argp: int) -> int:
        result = self._emu.vfs.ioctl(fd, request, argp)
        self._log.syscall("ioctl(fd=%d, req=%#x) => %d", fd, request, result)
        return result

    def _mkdirat(self, _dirfd: int, path_ptr: int, mode: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        result = self._emu.vfs.mkdir(path, mode)
        self._log.syscall("mkdirat(%r, mode=%o) => %d", path, mode, result)
        return result

    def _mkdir(self, path_ptr: int, mode: int) -> int:
        return self._mkdirat(self._AT_FDCWD, path_ptr, mode)

    def _unlinkat(self, _dirfd: int, path_ptr: int, flags: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        result = self._emu.vfs.unlink(path)
        self._log.syscall(
            "unlinkat(%r, flags=%#x%s) => %d",
            path,
            flags,
            " REMOVEDIR" if flags & self._AT_REMOVEDIR else "",
            result,
        )
        return result

    def _unlink(self, path_ptr: int) -> int:
        return self._unlinkat(self._AT_FDCWD, path_ptr, 0)

    def _rmdir(self, path_ptr: int) -> int:
        return self._unlinkat(self._AT_FDCWD, path_ptr, self._AT_REMOVEDIR)

    def _renameat(self, _od: int, old_ptr: int, _nd: int, new_ptr: int) -> int:
        old, new = self._mem.read_cstr(old_ptr), self._mem.read_cstr(new_ptr)
        result = self._emu.vfs.rename(old, new)
        self._log.syscall("renameat(%r, %r) => %d", old, new, result)
        return result

    def _rename(self, old_ptr: int, new_ptr: int) -> int:
        old, new = self._mem.read_cstr(old_ptr), self._mem.read_cstr(new_ptr)
        result = self._emu.vfs.rename(old, new)
        self._log.syscall("rename(%r, %r) => %d", old, new, result)
        return result

    def _link(self) -> int:
        raise UnimplementedSyscall("link", 9)

    def _symlink(self) -> int:
        raise UnimplementedSyscall("symlink", 83)

    def _write_statfs(self, buf_ptr: int) -> None:
        total_bytes = self._emu.device.filesystem_bytes
        blocks = total_bytes // 4096
        bfree = blocks * 35 // 100
        files = blocks // 4
        statfs = StatFS32(
            fs_type=0xEF53,
            bsize=4096,
            blocks=blocks,
            bfree=bfree,
            bavail=bfree,
            files=files,
            ffree=files * 70 // 100,
            namelen=255,
            frsize=4096,
            flags=0x1006,
        )
        statfs.write_to(self._mem, buf_ptr)

    def _statfs(self, path_ptr: int, buf_ptr: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        if not self._emu.vfs.exists(path):
            self._log.syscall("statfs(%r) => -ENOENT", path, level=LogLevel.WARN)
            return -Errno.ENOENT
        self._write_statfs(buf_ptr)
        self._log.syscall("statfs(%r) => 0 (ext4)", path)
        return 0

    def _statfs64(self, path_ptr: int, _sz: int, buf_ptr: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        if not self._emu.vfs.exists(path):
            self._log.syscall("statfs64(%r) => -ENOENT", path, level=LogLevel.WARN)
            return -Errno.ENOENT
        self._write_statfs(buf_ptr)
        self._log.syscall("statfs64(%r) => 0 (ext4)", path)
        return 0

    def _fstatfs(self, fd: int, buf_ptr: int) -> int:
        if self._emu.vfs.fstat(fd) is None:
            self._log.syscall("fstatfs(fd=%d) => -EBADF", fd, level=LogLevel.WARN)
            return -Errno.EBADF
        self._write_statfs(buf_ptr)
        self._log.syscall("fstatfs(fd=%d) => 0", fd)
        return 0

    def _fstatfs64(self, fd: int, _sz: int, buf_ptr: int) -> int:
        if self._emu.vfs.fstat(fd) is None:
            self._log.syscall("fstatfs64(fd=%d) => -EBADF", fd, level=LogLevel.WARN)
            return -Errno.EBADF
        self._write_statfs(buf_ptr)
        self._log.syscall("fstatfs64(fd=%d) => 0", fd)
        return 0

    def _ftruncate(self, fd: int, length: int) -> int:
        if length < 0:
            self._log.syscall("ftruncate(%d, %d) => -EINVAL", fd, length, level=LogLevel.WARN)
            return -Errno.EINVAL
        result = self._emu.vfs.ftruncate(fd, length)
        self._log.syscall("ftruncate(%d, %d) => %d", fd, length, result)
        return result

    def _truncate64(self, path_ptr: int, _pad: int, length_lo: int, length_hi: int) -> int:
        length = length_lo | (length_hi << 32)
        path = self._mem.read_cstr(path_ptr)
        result = self._emu.vfs.truncate(path, length)
        self._log.syscall("truncate64(%r, %d) => %d", path, length, result)
        return result

    def _ftruncate64(self, fd: int, _pad: int, length_lo: int, length_hi: int) -> int:
        length = length_lo | (length_hi << 32)
        if length < 0:
            self._log.syscall("ftruncate64(%d, %d) => -EINVAL", fd, length, level=LogLevel.WARN)
            return -Errno.EINVAL
        result = self._emu.vfs.ftruncate(fd, length)
        self._log.syscall("ftruncate64(%d, %d) => %d", fd, length, result)
        return result

    def _fallocate(
        self, fd: int, _mode: int, off_lo: int, off_hi: int, len_lo: int, len_hi: int
    ) -> int:
        offset = off_lo | (off_hi << 32)
        length = len_lo | (len_hi << 32)
        if self._emu.vfs.fstat(fd) is None:
            self._log.syscall(
                "fallocate(fd=%d, off=%d, len=%d) => -EBADF",
                fd,
                offset,
                length,
                level=LogLevel.WARN,
            )
            return -Errno.EBADF
        result = self._emu.vfs.ftruncate(fd, offset + length)
        self._log.syscall("fallocate(fd=%d, off=%d, len=%d) => %d", fd, offset, length, result)
        return result

    def _faccessat(self, _dirfd: int, path_ptr: int, _mode: int, _flags: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        ok = self._emu.vfs.exists(path)
        self._log.syscall("faccessat(%r) => %d", path, 0 if ok else -Errno.ENOENT)
        return 0 if ok else -Errno.ENOENT

    def _access(self, path_ptr: int, _mode: int) -> int:
        return self._faccessat(self._AT_FDCWD, path_ptr, _mode, 0)

    def _fchmodat(self, _dirfd: int, path_ptr: int, mode: int, _flags: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        if not self._emu.vfs.exists(path):
            self._log.syscall("fchmodat(%r, %o) => -ENOENT", path, mode, level=LogLevel.WARN)
            return -Errno.ENOENT
        self._log.syscall("fchmodat(%r, %o) => 0 (mode not enforced)", path, mode)
        return 0

    def _chmod(self, path_ptr: int, mode: int) -> int:
        return self._fchmodat(self._AT_FDCWD, path_ptr, mode, 0)

    def _fchmod(self, fd: int, mode: int) -> int:
        if self._emu.vfs.fstat(fd) is None:
            self._log.syscall("fchmod(fd=%d, %o) => -EBADF", fd, mode, level=LogLevel.WARN)
            return -Errno.EBADF
        self._log.syscall("fchmod(fd=%d, %o) => 0 (mode not enforced)", fd, mode)
        return 0

    def _fchownat(self, _dirfd: int, path_ptr: int, owner: int, group: int, _flags: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        if not self._emu.vfs.exists(path):
            self._log.syscall(
                "fchownat(%r, %d:%d) => -ENOENT", path, owner, group, level=LogLevel.WARN
            )
            return -Errno.ENOENT
        self._log.syscall("fchownat(%r, %d:%d) => 0 (ownership not modelled)", path, owner, group)
        return 0

    def _chown(self, path_ptr: int, owner: int, group: int) -> int:
        return self._fchownat(self._AT_FDCWD, path_ptr, owner, group, 0)

    def _lchown(self, path_ptr: int, owner: int, group: int) -> int:
        return self._fchownat(self._AT_FDCWD, path_ptr, owner, group, 0)

    def _fchown(self, fd: int, owner: int, group: int) -> int:
        if self._emu.vfs.fstat(fd) is None:
            self._log.syscall(
                "fchown(fd=%d, %d:%d) => -EBADF", fd, owner, group, level=LogLevel.WARN
            )
            return -Errno.EBADF
        self._log.syscall("fchown(fd=%d, %d:%d) => 0 (ownership not modelled)", fd, owner, group)
        return 0

    def _openat(self, _dirfd: int, path_ptr: int, flags: int, _mode: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        fd = self._emu.vfs.open(path, flags)
        self._log.syscall("openat(%r, flags=%#x) => %d", path, flags, fd)
        return fd

    def _open(self, path_ptr: int, flags: int, mode: int) -> int:
        return self._openat(self._AT_FDCWD, path_ptr, flags, mode)

    def _creat(self, path_ptr: int, mode: int) -> int:
        return self._openat(
            self._AT_FDCWD, path_ptr, 0x40 | 0x1 | 0x200, mode
        )  # O_CREAT | O_WRONLY | O_TRUNC

    def _close(self, fd: int) -> int:
        result = self._emu.vfs.close(fd)
        self._log.syscall("close(%d) => %d", fd, result)
        return result

    def _vhangup(self) -> int:
        raise UnimplementedSyscall("vhangup", 111)

    def _pipe2(self, pipefd_ptr: int, flags: int) -> int:
        read_fd, write_fd = self._emu.vfs.pipe()
        self._mem.write_u32(pipefd_ptr, read_fd)
        self._mem.write_u32(pipefd_ptr + 4, write_fd)
        self._log.syscall("pipe2(flags=%#x) => [%d, %d]", flags, read_fd, write_fd)
        return 0

    def _pipe(self, pipefd_ptr: int) -> int:
        return self._pipe2(pipefd_ptr, 0)

    def _getdents64(self, fd: int, dirp: int, count: int) -> int:
        entries = self._emu.vfs.getdents(fd)
        if entries is None:
            if self._emu.vfs.fstat(fd) is None:
                self._log.syscall("getdents64(fd=%d) => -EBADF", fd, level=LogLevel.WARN)
                return -Errno.EBADF
            self._log.syscall("getdents64(fd=%d) => -ENOTDIR", fd, level=LogLevel.WARN)
            return -Errno.ENOTDIR
        written, packed = 0, 0
        for d_ino, d_type, name in entries:
            record = Dirent64.create(d_ino, 0, name, d_type)
            if written + record.reclen > count:
                if written == 0:
                    self._log.syscall(
                        "getdents64(fd=%d, count=%d) => -EINVAL", fd, count, level=LogLevel.WARN
                    )
                    return -Errno.EINVAL
                break
            record.off = written + record.reclen
            record.write_to(self._mem, dirp + written)
            written += record.reclen
            packed += 1
        self._emu.vfs.advance_dir(fd, packed)
        self._log.syscall(
            "getdents64(fd=%d, count=%d) => %d bytes, %d entries", fd, count, written, packed
        )
        return written

    def _getdents(self, fd: int, dirp: int, count: int) -> int:
        entries = self._emu.vfs.getdents(fd)
        if entries is None:
            if self._emu.vfs.fstat(fd) is None:
                self._log.syscall("getdents(fd=%d) => -EBADF", fd, level=LogLevel.WARN)
                return -Errno.EBADF
            self._log.syscall("getdents(fd=%d) => -ENOTDIR", fd, level=LogLevel.WARN)
            return -Errno.ENOTDIR
        written, packed = 0, 0
        for d_ino, d_type, name in entries:
            encoded = name.encode("utf-8")
            reclen = (10 + len(encoded) + 1 + 1 + 3) & ~3
            if written + reclen > count:
                if written == 0:
                    self._log.syscall(
                        "getdents(fd=%d, count=%d) => -EINVAL", fd, count, level=LogLevel.WARN
                    )
                    return -Errno.EINVAL
                break
            base = dirp + written
            self._mem.write_u32(base, d_ino & 0xFFFFFFFF)
            self._mem.write_u32(base + 4, written + reclen)
            self._mem.write_u16(base + 8, reclen)
            self._mem.write(base + 10, encoded + b"\x00")
            self._mem.write(base + reclen - 1, bytes((d_type & 0xFF,)))
            written += reclen
            packed += 1
        self._emu.vfs.advance_dir(fd, packed)
        self._log.syscall(
            "getdents(fd=%d, count=%d) => %d bytes, %d entries", fd, count, written, packed
        )
        return written

    def _lseek(self, fd: int, offset: int, whence: int) -> int:
        result = self._emu.vfs.seek(fd, offset, whence)
        self._log.syscall("lseek(fd=%d, off=%d, whence=%d) => %d", fd, offset, whence, result)
        return result

    def _llseek(
        self, fd: int, offset_high: int, offset_low: int, result_ptr: int, whence: int
    ) -> int:
        offset = (offset_high << 32) | offset_low
        result = self._emu.vfs.seek(fd, offset, whence)
        if result < 0:
            self._log.syscall(
                "_llseek(fd=%d, off=%d, whence=%d) => %d",
                fd,
                offset,
                whence,
                result,
                level=LogLevel.WARN,
            )
            return result
        self._mem.write_u64(result_ptr, result)
        self._log.syscall(
            "_llseek(fd=%d, off=%d, whence=%d) => 0 (pos=%d)", fd, offset, whence, result
        )
        return 0

    def _read(self, fd: int, buf: int, count: int) -> int:
        data = self._emu.vfs.read(fd, count)
        if data is None:
            self._log.syscall("read(fd=%d) => -EBADF", fd, level=LogLevel.WARN)
            return -Errno.EBADF
        if isinstance(data, int):
            self._log.syscall("read(fd=%d) => %d (errno)", fd, data, level=LogLevel.WARN)
            return data
        self._mem.write(buf, data)
        self._log.syscall("read(fd=%d, count=%d) => %d bytes", fd, count, len(data))
        return len(data)

    def _write(self, fd: int, buf: int, count: int) -> int:
        data = self._mem.read(buf, count)
        written = self._emu.vfs.write(fd, data)
        self._log.syscall("write(fd=%d, %d bytes) => %d", fd, count, written)
        return written

    def _readv(self, fd: int, iov: int, iovcnt: int) -> int:
        iovecs = self._iovecs(iov, iovcnt)
        data = self._emu.vfs.read(fd, sum(v.length for v in iovecs))
        if data is None:
            self._log.syscall("readv(fd=%d, iovcnt=%d) => -EBADF", fd, iovcnt, level=LogLevel.WARN)
            return -Errno.EBADF
        if isinstance(data, int):
            self._log.syscall(
                "readv(fd=%d, iovcnt=%d) => %d (errno)", fd, iovcnt, data, level=LogLevel.WARN
            )
            return data
        offset = 0
        for v in iovecs:
            chunk = data[offset : offset + v.length]
            if not chunk:
                break
            self._mem.write(v.base, chunk)
            offset += len(chunk)
        self._log.syscall("readv(fd=%d, iovcnt=%d) => %d bytes", fd, iovcnt, len(data))
        return len(data)

    def _writev(self, fd: int, iov: int, iovcnt: int) -> int:
        chunks = [self._mem.read(v.base, v.length) for v in self._iovecs(iov, iovcnt) if v.length]
        data = b"".join(chunks)
        written = self._emu.vfs.write(fd, data)
        self._log.syscall("writev(fd=%d, iovcnt=%d) => %d bytes", fd, iovcnt, len(data))
        return written if written < 0 else len(data)

    def _pread64(
        self, fd: int, buf: int, count: int, _pad: int, offset_lo: int, offset_hi: int
    ) -> int:
        offset = offset_lo | (offset_hi << 32)
        if offset < 0:
            self._log.syscall(
                "pread64(fd=%d, count=%d, off=%d) => -EINVAL",
                fd,
                count,
                offset,
                level=LogLevel.WARN,
            )
            return -Errno.EINVAL
        data = self._emu.vfs.pread(fd, count, offset)
        if data is None:
            self._log.syscall(
                "pread64(fd=%d, count=%d, off=%d) => -EBADF", fd, count, offset, level=LogLevel.WARN
            )
            return -Errno.EBADF
        if isinstance(data, int):
            self._log.syscall(
                "pread64(fd=%d, count=%d, off=%d) => %d (errno)",
                fd,
                count,
                offset,
                data,
                level=LogLevel.WARN,
            )
            return data
        self._mem.write(buf, data)
        self._log.syscall(
            "pread64(fd=%d, count=%d, off=%d) => %d bytes", fd, count, offset, len(data)
        )
        return len(data)

    def _pwrite64(
        self, fd: int, buf: int, count: int, _pad: int, offset_lo: int, offset_hi: int
    ) -> int:
        offset = offset_lo | (offset_hi << 32)
        if offset < 0:
            self._log.syscall(
                "pwrite64(fd=%d, count=%d, off=%d) => -EINVAL",
                fd,
                count,
                offset,
                level=LogLevel.WARN,
            )
            return -Errno.EINVAL
        written = self._emu.vfs.pwrite(fd, self._mem.read(buf, count), offset)
        if written is None:
            self._log.syscall(
                "pwrite64(fd=%d, count=%d, off=%d) => -EBADF",
                fd,
                count,
                offset,
                level=LogLevel.WARN,
            )
            return -Errno.EBADF
        self._log.syscall("pwrite64(fd=%d, count=%d, off=%d) => %d", fd, count, offset, written)
        return written

    def _sendfile(self) -> int:
        raise UnimplementedSyscall("sendfile", 187)

    def _sendfile64(self) -> int:
        raise UnimplementedSyscall("sendfile64", 239)

    def _pselect6(
        self, nfds: int, readfds: int, writefds: int, exceptfds: int, _timeout: int, _sig: int
    ) -> int:
        nbytes = min((nfds + 7) // 8, 128)
        ready = 0
        if readfds:
            mask, result = self._mem.read(readfds, nbytes), bytearray(nbytes)
            for fd in range(nfds):
                if mask[fd // 8] & (1 << (fd % 8)):
                    handle = self._emu.vfs.handle(fd)
                    if handle is not None and handle.can_read():
                        result[fd // 8] |= 1 << (fd % 8)
                        ready += 1
            self._mem.write(readfds, bytes(result))
        if writefds:
            ready += sum(bin(byte).count("1") for byte in self._mem.read(writefds, nbytes))
        if exceptfds:
            self._mem.write(exceptfds, b"\x00" * nbytes)
        self._log.syscall("pselect6(nfds=%d) => %d ready", nfds, ready)
        return ready

    def _newselect(
        self, nfds: int, readfds: int, writefds: int, exceptfds: int, _timeout: int
    ) -> int:
        return self._pselect6(nfds, readfds, writefds, exceptfds, 0, 0)

    def _ppoll(self, fds_ptr: int, nfds: int, _tmo: int, _sig: int, _sigsize: int) -> int:
        pollin, pollout, pollnval = 0x1, 0x4, 0x20
        ready = 0
        for i in range(min(nfds, 4096)):
            entry = fds_ptr + i * Pollfd.SIZE
            poll = Pollfd.read_from(self._mem, entry)
            if poll.fd < 0:
                Pollfd.write_revents(self._mem, entry, 0)
                continue
            handle = self._emu.vfs.handle(poll.fd)
            if handle is None:
                revents = pollnval
            else:
                revents = (pollout | (pollin if handle.can_read() else 0)) & (
                    poll.events | pollnval
                )
            Pollfd.write_revents(self._mem, entry, revents)
            if revents:
                ready += 1
        self._log.syscall("ppoll(nfds=%d) => %d ready", nfds, ready)
        return ready

    def _poll(self, fds_ptr: int, nfds: int, _timeout: int) -> int:
        return self._ppoll(fds_ptr, nfds, 0, 0, 0)

    def _signalfd4(self) -> int:
        raise UnimplementedSyscall("signalfd4", 355)

    def _signalfd(self) -> int:
        raise UnimplementedSyscall("signalfd", 349)

    def _readlinkat(self, _dirfd: int, path_ptr: int, buf: int, bufsize: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        target = self._emu.vfs.readlink(path)
        if target is None:
            self._log.syscall(
                "readlinkat(%r) => -EINVAL (not a symlink)", path, level=LogLevel.WARN
            )
            return -Errno.EINVAL
        data = target.encode("utf-8")[:bufsize]
        self._mem.write(buf, data)
        self._log.syscall("readlinkat(%r) => %r", path, target)
        return len(data)

    def _readlink(self, path_ptr: int, buf: int, bufsize: int) -> int:
        return self._readlinkat(self._AT_FDCWD, path_ptr, buf, bufsize)

    def _fstatat64(self, _dirfd: int, path_ptr: int, statbuf: int, _flags: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        stat = self._emu.vfs.stat_path(path)
        if stat is None:
            self._log.syscall("fstatat64(%r) => -ENOENT", path, level=LogLevel.WARN)
            return -Errno.ENOENT
        self._write_stat(statbuf, *stat)
        self._log.syscall("fstatat64(%r) => 0 (size=%d)", path, stat[1])
        return 0

    def _stat64(self, path_ptr: int, statbuf: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        stat = self._emu.vfs.stat_path(path)
        if stat is None:
            self._log.syscall("stat64(%r) => -ENOENT", path, level=LogLevel.WARN)
            return -Errno.ENOENT
        self._write_stat(statbuf, *stat)
        self._log.syscall("stat64(%r) => 0 (size=%d)", path, stat[1])
        return 0

    def _lstat64(self, path_ptr: int, statbuf: int) -> int:
        return self._stat64(path_ptr, statbuf)

    def _stat(self, path_ptr: int, statbuf: int) -> int:
        return self._stat64(path_ptr, statbuf)

    def _lstat(self, path_ptr: int, statbuf: int) -> int:
        return self._stat64(path_ptr, statbuf)

    def _fstat64(self, fd: int, statbuf: int) -> int:
        stat = self._emu.vfs.fstat(fd)
        if stat is None:
            self._log.syscall("fstat64(fd=%d) => -EBADF", fd, level=LogLevel.WARN)
            return -Errno.EBADF
        self._write_stat(statbuf, *stat)
        self._log.syscall("fstat64(fd=%d) => 0 (mode=%o, size=%d)", fd, stat[0], stat[1])
        return 0

    def _fstat(self, fd: int, statbuf: int) -> int:
        return self._fstat64(fd, statbuf)

    def _sync(self) -> int:
        self._log.syscall("sync() => 0")
        return 0

    def _fsync(self, fd: int) -> int:
        if self._emu.vfs.fstat(fd) is None:
            self._log.syscall("fsync(%d) => -EBADF", fd, level=LogLevel.WARN)
            return -Errno.EBADF
        self._log.syscall("fsync(%d) => 0", fd)
        return 0

    def _fdatasync(self, fd: int) -> int:
        if self._emu.vfs.fstat(fd) is None:
            self._log.syscall("fdatasync(%d) => -EBADF", fd, level=LogLevel.WARN)
            return -Errno.EBADF
        self._log.syscall("fdatasync(%d) => 0", fd)
        return 0

    def _chdir(self) -> int:
        raise UnimplementedSyscall("chdir", 12)

    def _fchdir(self) -> int:
        raise UnimplementedSyscall("fchdir", 133)

    def _chroot(self) -> int:
        raise UnimplementedSyscall("chroot", 61)

    def _exit(self, status: int) -> int:
        self._log.syscall("exit(%d) -> stopping emulation", status, level=LogLevel.INFO)
        self._be.emu_stop()
        return 0

    def _exit_group(self, status: int) -> int:
        self._log.syscall("exit_group(%d) -> stopping emulation", status, level=LogLevel.INFO)
        self._be.emu_stop()
        return 0

    def _execve(self) -> int:
        raise UnimplementedSyscall("execve", 11)

    def _set_tid_address(self, tid_address: int) -> int:
        self._clear_child_tid = tid_address
        self._log.syscall(
            "set_tid_address(%#x) => %d (tid)", tid_address, self._profile.process_tid
        )
        return self._profile.process_tid

    def _futex(self, uaddr: int, op: int, val: int) -> int:
        command = op & 0x7F
        if command in (0, 9):
            current = self._mem.read_u32(uaddr)
            if current != (val & 0xFFFFFFFF):
                self._log.syscall(
                    "futex(%#x, WAIT, %#x) => -EAGAIN  (value is %#x)", uaddr, val, current
                )
                return -Errno.EAGAIN
            self._log.syscall(
                "futex(%#x, WAIT, %#x) => 0  (uncontended, single-thread)", uaddr, val
            )
            return 0
        if command in (1, 10):
            self._log.syscall(
                "futex(%#x, WAKE, n=%d) => 0  (no waiters, single-thread)", uaddr, val
            )
            return 0
        self._log.syscall(
            "futex(%#x, op=%#x) unsupported => -ENOSYS", uaddr, op, level=LogLevel.WARN
        )
        return -Errno.ENOSYS

    def _set_robust_list(self, head: int, length: int) -> int:
        self._robust_list_head = head
        self._log.syscall("set_robust_list(head=%#x, len=%d) => 0", head, length)
        return 0

    def _get_robust_list(self, pid: int, head_ptr: int, len_ptr: int) -> int:
        if head_ptr:
            self._mem.write_u32(head_ptr, self._robust_list_head)
        if len_ptr:
            self._mem.write_u32(len_ptr, 12)
        self._log.syscall("get_robust_list(pid=%d) => 0 (head=%#x)", pid, self._robust_list_head)
        return 0

    def _nanosleep(self, req_ptr: int, rem_ptr: int) -> int:
        sec, nsec = self._mem.read_s32(req_ptr), self._mem.read_s32(req_ptr + 4)
        if nsec < 0 or nsec >= 1_000_000_000:
            self._log.syscall("nanosleep(%d.%09ds) => -EINVAL", sec, nsec, level=LogLevel.WARN)
            return -Errno.EINVAL
        self._clock_advance(sec * 1_000_000_000 + nsec)
        if rem_ptr:
            self._mem.write_u32(rem_ptr, 0)
            self._mem.write_u32(rem_ptr + 4, 0)
        self._log.syscall("nanosleep(%d.%09ds) => 0 (virtual)", sec, nsec)
        return 0

    def _clock_now(self, realtime: bool) -> int:
        clock = self._emu.device.clock
        return clock.realtime_ns() if realtime else clock.monotonic_ns()

    def _clock_advance(self, nanos: int) -> None:
        self._emu.device.clock.advance(nanos)

    def _clock_gettime(self, clock_id: int, timespec_ptr: int) -> int:
        realtime = clock_id in (0, 5)
        nanos = self._clock_now(realtime)
        TimeSpec32.from_ns(nanos).write_to(self._mem, timespec_ptr)
        self._log.syscall(
            "clock_gettime(%s=%d) => %d.%09d",
            "REALTIME" if realtime else "MONOTONIC",
            clock_id,
            nanos // 1_000_000_000,
            nanos % 1_000_000_000,
        )
        return 0

    def _clock_getres(self, _clock_id: int, res_ptr: int) -> int:
        if res_ptr:
            TimeSpec32(sec=0, nsec=1).write_to(self._mem, res_ptr)
        self._log.syscall("clock_getres() => 0 (1ns)")
        return 0

    def _clock_nanosleep(self, clockid: int, flags: int, req_ptr: int, rem_ptr: int) -> int:
        sec, nsec = self._mem.read_s32(req_ptr), self._mem.read_s32(req_ptr + 4)
        request_ns = sec * 1_000_000_000 + nsec
        if flags & 1:  # TIMER_ABSTIME: advance the virtual clock to the deadline
            clock = self._emu.device.clock
            (clock.sync_realtime if clockid in (0, 5) else clock.sync_monotonic)(request_ns)
        else:
            self._clock_advance(request_ns)
            if rem_ptr:
                self._mem.write_u32(rem_ptr, 0)
                self._mem.write_u32(rem_ptr + 4, 0)
        self._log.syscall("clock_nanosleep(flags=%#x, %d.%09ds) => 0 (virtual)", flags, sec, nsec)
        return 0

    def _sched_getscheduler(self, pid: int) -> int:
        self._log.syscall("sched_getscheduler(pid=%d) => 0 (SCHED_OTHER)", pid)
        return 0

    def _sched_getparam(self, pid: int, param_ptr: int) -> int:
        if param_ptr:
            self._mem.write_u32(param_ptr, 0)
        self._log.syscall("sched_getparam(pid=%d) => 0 (priority 0)", pid)
        return 0

    def _sched_setaffinity(self, pid: int, cpuset_size: int, mask_ptr: int) -> int:
        if mask_ptr and cpuset_size:
            self._sched_affinity = self._mem.read(mask_ptr, min(cpuset_size, 128))
        self._log.syscall("sched_setaffinity(pid=%d, size=%d) => 0", pid, cpuset_size)
        return 0

    def _sched_getaffinity(self, pid: int, cpuset_size: int, mask_ptr: int) -> int:
        if self._sched_affinity:
            mask = self._sched_affinity[:cpuset_size] or self._sched_affinity
        else:
            cpu_count = int(self._emu.device.get("ro.cpu.count", "8") or "8")
            full = ((1 << cpu_count) - 1).to_bytes((cpu_count + 7) // 8, "little")
            mask = full[:cpuset_size] if cpuset_size else full
        self._mem.write(mask_ptr, mask)
        self._log.syscall(
            "sched_getaffinity(pid=%d, size=%d) => %d bytes", pid, cpuset_size, len(mask)
        )
        return len(mask)

    def _sched_yield(self) -> int:
        self._log.syscall("sched_yield() => 0 (single-threaded no-op)")
        return 0

    def _sched_get_priority_max(self, policy: int) -> int:
        if policy in (1, 2):
            self._log.syscall("sched_get_priority_max(policy=%d) => 99", policy)
            return 99
        if policy in (0, 3, 5):
            self._log.syscall("sched_get_priority_max(policy=%d) => 0", policy)
            return 0
        self._log.syscall(
            "sched_get_priority_max(policy=%d) => -EINVAL", policy, level=LogLevel.WARN
        )
        return -Errno.EINVAL

    def _sched_get_priority_min(self, policy: int) -> int:
        if policy in (1, 2):
            self._log.syscall("sched_get_priority_min(policy=%d) => 1", policy)
            return 1
        if policy in (0, 3, 5):
            self._log.syscall("sched_get_priority_min(policy=%d) => 0", policy)
            return 0
        self._log.syscall(
            "sched_get_priority_min(policy=%d) => -EINVAL", policy, level=LogLevel.WARN
        )
        return -Errno.EINVAL

    def _handler_for(self, sig: int) -> "Sigaction32 | None":
        action = self._sigactions.get(sig)
        if action is None or action.handler in (self._SIG_DFL, self._SIG_IGN):
            return None
        return action

    def _enter_signal_handler(self, action: Sigaction32, sig: int, fault_addr: int = 0) -> None:
        be = self._be
        if not self._sigreturn_slot:
            self._sigreturn_slot = self._emu.trap.alloc_slot(self._do_sigreturn, "sigreturn")
        saved_sp = be.reg_read(Arm32Reg.SP)
        saved_cpsr = be.reg_read(Arm32Reg.CPSR)
        regs = [be.reg_read(Arm32Reg.R[i]) for i in range(16)]

        top = (saved_sp - 0x1600) & ~0xF
        siginfo, uctx = top, top + 0x100
        self._mem.write(top, b"\x00" * 0x1600)
        self._mem.write_u32(siginfo, sig)
        self._mem.write_u32(siginfo + 12, fault_addr)
        Sigcontext32.save(self._mem, uctx, regs, saved_cpsr, fault_addr)
        self._signal_frames.append(uctx)

        be.reg_write(Arm32Reg.R[0], sig)
        be.reg_write(Arm32Reg.R[1], siginfo)
        be.reg_write(Arm32Reg.R[2], uctx)
        be.reg_write(Arm32Reg.SP, top)
        be.reg_write(Arm32Reg.LR, self._sigreturn_slot)
        be.reg_write(Arm32Reg.PC, action.handler)

    def _do_sigreturn(self) -> "int | None":
        if not self._signal_frames:
            self._log.syscall("rt_sigreturn => no frame (ignored)", level=LogLevel.WARN)
            return None
        uctx = self._signal_frames.pop()
        be = self._be
        regs, cpsr = Sigcontext32.restore(self._mem, uctx)
        for i in range(16):
            be.reg_write(Arm32Reg.R[i], regs[i])
        be.reg_write(Arm32Reg.CPSR, cpsr)
        be.reg_write(Arm32Reg.PC, regs[15])
        self._log.syscall("rt_sigreturn -> resume %#x", regs[15])
        return None

    def _deliver_signal(self, sig: int) -> "int | None":
        if sig == 0:
            return 0
        action = self._handler_for(sig)
        if action is not None:
            self._be.reg_write(Arm32Reg.RET_REG, 0)
            self._enter_signal_handler(action, sig)
            self._log.syscall("signal %d -> handler %#x", sig, action.handler)
            return None
        if sig in (6, 9):
            self._log.syscall("signal %d -> stopping emulation", sig, level=LogLevel.ERROR)
            self._be.emu_stop()
        else:
            self._log.syscall("signal %d accepted (no handler)", sig, level=LogLevel.WARN)
        return 0

    def _kill(self, pid: int, sig: int) -> "int | None":
        if pid > 0 and pid != self._profile.process_pid:
            self._log.syscall("kill(pid=%d, sig=%d) => -ESRCH", pid, sig, level=LogLevel.WARN)
            return -Errno.ESRCH
        return self._deliver_signal(sig)

    def _tkill(self, tid: int, sig: int) -> "int | None":
        if sig == 0:
            result = 0 if tid == self._profile.process_tid else -Errno.ESRCH
            level = LogLevel.DEBUG if result == 0 else LogLevel.WARN
            self._log.syscall(
                "tkill(tid=%d, sig=0) => %d (existence probe)", tid, result, level=level
            )
            return result
        return self._deliver_signal(sig)

    def _tgkill(self, _tgid: int, _tid: int, sig: int) -> "int | None":
        return self._deliver_signal(sig)

    def _sigaltstack(self, new_stack_ptr: int, old_stack_ptr: int) -> int:
        if old_stack_ptr and self._alt_stack:
            self._mem.write(old_stack_ptr, self._alt_stack)
        if new_stack_ptr:
            self._alt_stack = self._mem.read(new_stack_ptr, 12)
        self._log.syscall(
            "sigaltstack(ss=%#x, old=%#x) => 0  (stored; never switched to)",
            new_stack_ptr,
            old_stack_ptr,
        )
        return 0

    def _rt_sigsuspend(self) -> int:
        raise UnimplementedSyscall("rt_sigsuspend", 179)

    def _sigsuspend(self) -> int:
        raise UnimplementedSyscall("sigsuspend", 72)

    def _rt_sigaction(self, signum: int, act_ptr: int, oldact_ptr: int) -> int:
        if oldact_ptr and signum in self._sigactions:
            self._sigactions[signum].write_to(self._mem, oldact_ptr)
        if act_ptr:
            self._sigactions[signum] = Sigaction32.read_from(self._mem, act_ptr)
        current = self._sigactions.get(signum)
        self._log.syscall(
            "rt_sigaction(sig=%d) => 0  (handler=%#x)", signum, current.handler if current else 0
        )
        return 0

    def _sigaction(self, signum: int, act_ptr: int, oldact_ptr: int) -> int:
        return self._rt_sigaction(signum, act_ptr, oldact_ptr)

    def _rt_sigprocmask(self, how: int, set_ptr: int, oldset_ptr: int) -> int:
        if oldset_ptr:
            self._mem.write_u64(oldset_ptr, self._signal_mask)
        if set_ptr:
            new_bits = self._mem.read_u64(set_ptr)
            self._signal_mask = (
                (self._signal_mask | new_bits)
                if how == 0
                else (self._signal_mask & ~new_bits)
                if how == 1
                else new_bits
            )
        self._log.syscall("rt_sigprocmask(how=%d) => 0  (mask now %#x)", how, self._signal_mask)
        return 0

    def _sigprocmask(self, how: int, set_ptr: int, oldset_ptr: int) -> int:
        if oldset_ptr:
            self._mem.write_u32(oldset_ptr, self._signal_mask & 0xFFFFFFFF)
        if set_ptr:
            new_bits = self._mem.read_u32(set_ptr)
            self._signal_mask = (
                (self._signal_mask | new_bits)
                if how == 0
                else (self._signal_mask & ~new_bits)
                if how == 1
                else new_bits
            )
        self._log.syscall("sigprocmask(how=%d) => 0  (mask now %#x)", how, self._signal_mask)
        return 0

    def _rt_sigpending(self, set_ptr: int, sigsetsize: int) -> int:
        self._mem.write(set_ptr, b"\x00" * min(sigsetsize, 8))
        self._log.syscall("rt_sigpending() => 0 (none pending)")
        return 0

    def _sigpending(self, set_ptr: int) -> int:
        self._mem.write(set_ptr, b"\x00" * 4)
        self._log.syscall("sigpending() => 0 (none pending)")
        return 0

    def _rt_sigtimedwait(self) -> int:
        raise UnimplementedSyscall("rt_sigtimedwait", 177)

    def _rt_sigqueueinfo(self) -> int:
        raise UnimplementedSyscall("rt_sigqueueinfo", 178)

    def _rt_sigreturn(self) -> "int | None":
        self._do_sigreturn()
        return None

    def _sigreturn(self) -> "int | None":
        self._do_sigreturn()
        return None

    def _setpriority(self, which: int, who: int, prio: int) -> int:
        self._log.syscall("setpriority(which=%d, who=%d, prio=%d) => 0 (ignored)", which, who, prio)
        return 0

    def _getpriority(self, which: int, who: int) -> int:
        self._log.syscall("getpriority(which=%d, who=%d) => 20 (nice 0)", which, who)
        return 20

    def _setregid(self) -> int:
        raise UnimplementedSyscall("setregid", 71)

    def _setgid(self) -> int:
        raise UnimplementedSyscall("setgid", 46)

    def _setreuid(self) -> int:
        raise UnimplementedSyscall("setreuid", 70)

    def _setuid(self) -> int:
        raise UnimplementedSyscall("setuid", 23)

    def _setresuid(self) -> int:
        raise UnimplementedSyscall("setresuid", 164)

    def _getresuid(self) -> int:
        raise UnimplementedSyscall("getresuid", 165)

    def _setresgid(self) -> int:
        raise UnimplementedSyscall("setresgid", 170)

    def _getresgid(self) -> int:
        raise UnimplementedSyscall("getresgid", 171)

    def _setfsuid(self) -> int:
        raise UnimplementedSyscall("setfsuid", 138)

    def _setfsgid(self) -> int:
        raise UnimplementedSyscall("setfsgid", 139)

    def _times(self, buf: int) -> int:
        if buf:
            Tms32(
                utime=self._profile.utime_ticks, stime=self._profile.stime_ticks, cutime=0, cstime=0
            ).write_to(self._mem, buf)
        elapsed = (
            self._emu.device.clock.monotonic_ns() // 10_000_000 or 1
        )  # clock ticks (100 Hz) since boot
        self._log.syscall("times() => %d ticks", elapsed)
        return elapsed

    def _getgroups(self, size: int, list_ptr: int) -> int:
        groups = self._profile.supplementary_groups
        if size == 0:
            self._log.syscall("getgroups(size=0) => %d (count query)", len(groups))
            return len(groups)
        if size < len(groups):
            self._log.syscall("getgroups(size=%d) => -EINVAL", size, level=LogLevel.WARN)
            return -Errno.EINVAL
        for i, gid in enumerate(groups):
            self._mem.write_u32(list_ptr + i * 4, gid)
        self._log.syscall("getgroups() => %d groups", len(groups))
        return len(groups)

    def _uname(self, utsname_ptr: int) -> int:
        sysname, nodename, release, version, _machine, domainname = self._emu.device.uname()
        machine = self._emu.arch.uname_machine
        Utsname(
            sysname=sysname,
            nodename=nodename,
            release=release,
            version=version,
            machine=machine,
            domainname=domainname,
        ).write_to(self._mem, utsname_ptr)
        self._log.syscall("uname() => %s %s %s", sysname, release, machine)
        return 0

    def _rlimit_for(self, resource: int) -> "tuple[int, int] | None":
        infinity = self._RLIM_INFINITY
        limits = {
            0: (infinity, infinity),
            1: (infinity, infinity),
            2: (infinity, infinity),
            3: (MemoryLayout32.STACK_SIZE, MemoryLayout32.STACK_SIZE),
            4: (0, 0),
            5: (infinity, infinity),
            6: (self._emu.device.sigpending_limit, self._emu.device.sigpending_limit),
            7: (1024, 4096),
            8: (infinity, infinity),
            9: (infinity, infinity),
        }
        return limits.get(resource)

    def _getrlimit(self, resource: int, rlim_ptr: int) -> int:
        limit = self._rlimit_for(resource)
        if limit is None:
            self._log.syscall("getrlimit(res=%d) => -EINVAL", resource, level=LogLevel.WARN)
            return -Errno.EINVAL
        RLimit32(cur=limit[0], max=limit[1]).write_to(self._mem, rlim_ptr)
        self._log.syscall("getrlimit(res=%d) => 0 [cur=%#x max=%#x]", resource, *limit)
        return 0

    def _ugetrlimit(self, resource: int, rlim_ptr: int) -> int:
        return self._getrlimit(resource, rlim_ptr)

    def _setrlimit(self, resource: int, rlim_ptr: int) -> int:
        cur, maximum = self._mem.read_u32(rlim_ptr), self._mem.read_u32(rlim_ptr + 4)
        self._log.syscall(
            "setrlimit(res=%d, cur=%#x, max=%#x) => 0 (ignored)", resource, cur, maximum
        )
        return 0

    def _getrusage(self, who: int, usage_ptr: int) -> int:
        if who not in (0, 1, -1):
            self._log.syscall("getrusage(who=%d) => -EINVAL", who, level=LogLevel.WARN)
            return -Errno.EINVAL
        p = self._profile  # coherent with times() and /proc/self/status (one source)
        Rusage32(
            utime_usec=p.utime_ticks * 10_000,
            stime_usec=p.stime_ticks * 10_000,
            maxrss=45000,
            nvcsw=p.voluntary_ctxt_switches,
            nivcsw=p.nonvoluntary_ctxt_switches,
        ).write_to(self._mem, usage_ptr)
        self._log.syscall("getrusage(who=%d) => 0", who)
        return 0

    def _umask(self, mask: int) -> int:
        old, self._umask_value = self._umask_value, mask & 0x1FF
        self._log.syscall("umask(%o) => %o (old)", mask & 0x1FF, old)
        return old

    def _prctl(self, option: int, arg2: int, arg3: int, arg4: int, arg5: int) -> int:
        if option == 15:
            self._thread_name = (
                self._mem.read(arg2, 16).split(b"\x00", 1)[0].decode("utf-8", "replace")
            )
            self._log.syscall("prctl(PR_SET_NAME, %r) => 0", self._thread_name)
            return 0
        if option == 16:
            name = self._thread_name if self._thread_name is not None else self._profile.thread_name
            self._mem.write_cstr(arg2, name)
            self._log.syscall("prctl(PR_GET_NAME) => %r", name)
            return 0
        if option == 4:
            self._dumpable = arg2
            self._log.syscall("prctl(PR_SET_DUMPABLE, %d) => 0", arg2)
            return 0
        if option == 3:
            dumpable = (
                self._dumpable
                if self._dumpable is not None
                else (1 if self._emu.device.get("ro.debuggable", "0") == "1" else 0)
            )
            self._log.syscall("prctl(PR_GET_DUMPABLE) => %d", dumpable)
            return dumpable
        if option == 0x53564D41:
            region_name = self._mem.read_cstr(arg5) if arg5 else ""
            self._log.syscall(
                "prctl(PR_SET_VMA, addr=%#x, len=%#x, %r) => 0", arg3, arg4, region_name
            )
            return 0
        if option == 38:
            self._log.syscall("prctl(PR_SET_NO_NEW_PRIVS, %d) => 0", arg2)
            return 0
        if option == 41:
            self._log.syscall("prctl(PR_SET_THP_DISABLE, %d) => 0", arg2)
            return 0
        if option == 0x59616D61:
            self._log.syscall("prctl(PR_SET_PTRACER, pid=%d) => 0", arg2)
            return 0
        self._log.syscall("prctl(option=%d) unsupported => -EINVAL", option, level=LogLevel.WARN)
        return -Errno.EINVAL

    def _getcpu(self, cpu_ptr: int, node_ptr: int, _tcache: int) -> int:
        if cpu_ptr:
            self._mem.write_u32(cpu_ptr, 0)
        if node_ptr:
            self._mem.write_u32(node_ptr, 0)
        self._log.syscall("getcpu() => 0 (cpu=0, node=0)")
        return 0

    def _gettimeofday(self, timeval_ptr: int, _timezone_ptr: int) -> int:
        micros = self._clock_now(realtime=True) // 1000
        Timeval32(sec=micros // 1_000_000, usec=micros % 1_000_000).write_to(self._mem, timeval_ptr)
        self._log.syscall("gettimeofday() => %d.%06d", micros // 1_000_000, micros % 1_000_000)
        return 0

    def _getpid(self) -> int:
        self._log.syscall("getpid() => %d", self._profile.process_pid)
        return self._profile.process_pid

    def _getppid(self) -> int:
        self._log.syscall("getppid() => %d", self._profile.parent_process_pid)
        return self._profile.parent_process_pid

    def _getuid(self) -> int:
        self._log.syscall("getuid() => %d (app uid)", self._profile.process_uid)
        return self._profile.process_uid

    def _geteuid(self) -> int:
        self._log.syscall("geteuid() => %d (app euid)", self._profile.process_uid)
        return self._profile.process_uid

    def _getgid(self) -> int:
        self._log.syscall("getgid() => %d (app gid)", self._profile.process_gid)
        return self._profile.process_gid

    def _getegid(self) -> int:
        self._log.syscall("getegid() => %d (app egid)", self._profile.process_gid)
        return self._profile.process_gid

    def _gettid(self) -> int:
        self._log.syscall("gettid() => %d", self._profile.process_tid)
        return self._profile.process_tid

    def _sysinfo(self, info_ptr: int) -> int:
        total_kb = int(self._emu.device.get("ro.mem.total_kb", "7635200") or "7635200")
        free_kb = int(self._emu.device.get("ro.mem.free_kb", "2894560") or "2894560")
        mem_unit = 4096  # 32-bit totalram can't hold >4 GB in bytes, so scale (correct)
        totalram, freeram = (total_kb * 1024) // mem_unit, (free_kb * 1024) // mem_unit
        dev = self._emu.device
        uptime_s = dev.clock.uptime_s()
        loads = tuple(
            int(load * 65536) for load in dev.load_averages
        )  # sysinfo loads are 16.16 fixed-point
        Sysinfo32(
            uptime=uptime_s,
            loads=loads,
            totalram=totalram,
            freeram=freeram,
            sharedram=totalram // 16,
            bufferram=totalram // 32,
            procs=dev.total_procs,
            mem_unit=mem_unit,
        ).write_to(self._mem, info_ptr)
        self._log.syscall(
            "sysinfo() => totalram=%d pages freeram=%d procs=%d (mem_unit=%d)",
            totalram,
            freeram,
            dev.total_procs,
            mem_unit,
        )
        return 0

    def _read_sockaddr_un(self, addr_ptr: int, addrlen: int) -> str:
        if addr_ptr == 0 or addrlen < 3:
            return ""
        raw = self._mem.read(addr_ptr + 2, min(addrlen - 2, 108))
        if raw[:1] == b"\x00":
            return "@" + raw[1:].split(b"\x00")[0].decode("utf-8", "replace")
        return raw.split(b"\x00")[0].decode("utf-8", "replace")

    def _socket(self, domain: int, sock_type: int, protocol: int) -> int:
        fd = self._emu.vfs.socket(domain, sock_type, protocol)
        self._log.syscall(
            "socket(domain=%d, type=%#x, proto=%d) => %d", domain, sock_type, protocol, fd
        )
        return fd

    def _socketpair(self, domain: int, sock_type: int, protocol: int, sv_ptr: int) -> int:
        result = self._emu.vfs.socketpair(domain, sock_type, protocol)
        if isinstance(result, int):
            self._log.syscall(
                "socketpair(domain=%d) => %d (errno)", domain, result, level=LogLevel.WARN
            )
            return result
        self._mem.write_u32(sv_ptr, result[0])
        self._mem.write_u32(sv_ptr + 4, result[1])
        self._log.syscall("socketpair(domain=%d) => [%d, %d]", domain, *result)
        return 0

    def _bind(self, fd: int, _addr_ptr: int, _addrlen: int) -> int:
        result = 0 if self._emu.vfs.socket_handle(fd) is not None else -Errno.ENOTSOCK
        self._log.syscall("bind(fd=%d) => %d", fd, result)
        return result

    def _listen(self, fd: int, _backlog: int) -> int:
        result = 0 if self._emu.vfs.socket_handle(fd) is not None else -Errno.ENOTSOCK
        self._log.syscall("listen(fd=%d) => %d", fd, result)
        return result

    def _connect(self, fd: int, addr_ptr: int, addrlen: int) -> int:
        path = self._read_sockaddr_un(addr_ptr, addrlen)
        result = self._emu.vfs.connect(fd, path)
        self._log.syscall("connect(fd=%d, %r) => %d", fd, path, result)
        return result

    def _getsockname(self, fd: int, _addr_ptr: int, addrlen_ptr: int) -> int:
        if addrlen_ptr:
            self._mem.write_u32(addrlen_ptr, 2)
        self._log.syscall("getsockname(fd=%d) => 0", fd)
        return 0

    def _getpeername(self, fd: int, _addr_ptr: int, addrlen_ptr: int) -> int:
        if addrlen_ptr:
            self._mem.write_u32(addrlen_ptr, 2)
        self._log.syscall("getpeername(fd=%d) => 0", fd)
        return 0

    def _sendto(
        self, fd: int, buf_ptr: int, length: int, _flags: int, _dest: int, _addrlen: int
    ) -> int:
        sock = self._emu.vfs.socket_handle(fd)
        if sock is None:
            self._log.syscall("sendto(fd=%d) => -ENOTSOCK", fd, level=LogLevel.WARN)
            return -Errno.ENOTSOCK
        sock.sendto(self._mem.read(buf_ptr, min(length, 0x100000)), 0, 0, 0)
        self._log.syscall("sendto(fd=%d, %d bytes) => %d", fd, length, length)
        return length

    def _send(self, fd: int, buf_ptr: int, length: int, flags: int) -> int:
        return self._sendto(fd, buf_ptr, length, flags, 0, 0)

    def _recvfrom(
        self, fd: int, buf_ptr: int, length: int, flags: int, _src: int, _addrlen: int
    ) -> int:
        sock = self._emu.vfs.socket_handle(fd)
        if sock is None:
            self._log.syscall("recvfrom(fd=%d) => -ENOTSOCK", fd, level=LogLevel.WARN)
            return -Errno.ENOTSOCK
        data = sock.recvfrom(length, flags, 0, 0)
        self._mem.write(buf_ptr, data)
        self._log.syscall("recvfrom(fd=%d, %d) => %d bytes", fd, length, len(data))
        return len(data)

    def _recv(self, fd: int, buf_ptr: int, length: int, flags: int) -> int:
        return self._recvfrom(fd, buf_ptr, length, flags, 0, 0)

    def _setsockopt(self, fd: int, _level: int, _optname: int, _optval: int, _optlen: int) -> int:
        result = 0 if self._emu.vfs.socket_handle(fd) is not None else -Errno.ENOTSOCK
        self._log.syscall("setsockopt(fd=%d) => %d", fd, result)
        return result

    def _getsockopt(
        self, fd: int, level: int, optname: int, optval_ptr: int, optlen_ptr: int
    ) -> int:
        sock = self._emu.vfs.socket_handle(fd)
        if sock is None:
            self._log.syscall(
                "getsockopt(fd=%d, optname=%d) => -ENOTSOCK", fd, optname, level=LogLevel.WARN
            )
            return -Errno.ENOTSOCK
        value = self._sockopt_value(sock, level, optname)
        if value is None:
            self._log.syscall(
                "getsockopt(fd=%d, optname=%d) => -ENOPROTOOPT", fd, optname, level=LogLevel.WARN
            )
            return -Errno.ENOPROTOOPT
        if optval_ptr:
            self._mem.write_u32(optval_ptr, value & 0xFFFFFFFF)
        if optlen_ptr:
            self._mem.write_u32(optlen_ptr, 4)
        self._log.syscall(
            "getsockopt(fd=%d, optname=%d) => 0 (val=%#x)", fd, optname, value & 0xFFFFFFFF
        )
        return 0

    def _sockopt_value(self, sock: object, level: int, optname: int) -> "int | None":
        if level != self._SOL_SOCKET:
            return None
        return {
            SockOpt.SO_ERROR: 0,
            SockOpt.SO_TYPE: sock.sock_type,
            SockOpt.SO_SNDBUF: 212992,
            SockOpt.SO_RCVBUF: 212992,
            SockOpt.SO_REUSEADDR: 0,
            SockOpt.SO_KEEPALIVE: 0,
            SockOpt.SO_BROADCAST: 0,
        }.get(optname)

    def _shutdown(self, fd: int, _how: int) -> int:
        result = 0 if self._emu.vfs.socket_handle(fd) is not None else -Errno.ENOTSOCK
        self._log.syscall("shutdown(fd=%d) => %d", fd, result)
        return result

    def _iovecs(self, iov_ptr: int, iovcnt: int) -> "list[Iovec32]":
        return Iovec32.read_array(self._mem, iov_ptr, iovcnt)

    def _sendmsg(self, fd: int, msg_ptr: int, _flags: int) -> int:
        sock = self._emu.vfs.socket_handle(fd)
        if sock is None:
            self._log.syscall("sendmsg(fd=%d) => -ENOTSOCK", fd, level=LogLevel.WARN)
            return -Errno.ENOTSOCK
        hdr = Msghdr32.read_from(self._mem, msg_ptr)
        total = 0
        for v in self._iovecs(hdr.iov, hdr.iovlen):
            sock.sendto(self._mem.read(v.base, min(v.length, 0x100000)), 0, 0, 0)
            total += v.length
        self._log.syscall("sendmsg(fd %d, %d iov) => %d", fd, hdr.iovlen, total)
        return total

    def _recvmsg(self, fd: int, msg_ptr: int, flags: int) -> int:
        sock = self._emu.vfs.socket_handle(fd)
        if sock is None:
            self._log.syscall("recvmsg(fd=%d) => -ENOTSOCK", fd, level=LogLevel.WARN)
            return -Errno.ENOTSOCK
        hdr = Msghdr32.read_from(self._mem, msg_ptr)
        iovecs = self._iovecs(hdr.iov, hdr.iovlen)
        capacity = sum(v.length for v in iovecs)
        data = sock.recvfrom(capacity, flags, 0, 0)
        offset = 0
        for v in iovecs:
            chunk = data[offset : offset + v.length]
            if not chunk:
                break
            self._mem.write(v.base, chunk)
            offset += len(chunk)
        self._log.syscall("recvmsg(fd=%d, %d iov) => %d bytes", fd, hdr.iovlen, offset)
        return offset

    def _brk(self, new_break: int) -> int:
        result = self._mem.brk(new_break)
        self._log.syscall("brk(%#x) => %#x", new_break, result, level=LogLevel.INFO)
        return result

    def _munmap(self, addr: int, length: int) -> int:
        try:
            self._mem.unmap(addr, length)
        except Exception as error:
            self._log.syscall(
                "munmap(%#x, %#x) failed (%s) => -EINVAL", addr, length, error, level=LogLevel.WARN
            )
            return -Errno.EINVAL
        self._log.syscall("munmap(%#x, %#x) => 0", addr, length)
        return 0

    def _mremap(
        self, old_address: int, old_size: int, new_size: int, flags: int, new_address: int
    ) -> int:
        maymove, fixed, dontunmap = 1, 2, 4
        if old_size == 0 or new_size == 0:
            self._log.syscall(
                "mremap(%#x, %#x->%#x) => -EINVAL",
                old_address,
                old_size,
                new_size,
                level=LogLevel.WARN,
            )
            return -Errno.EINVAL
        old_aligned, new_aligned = (
            MemoryLayout32.page_align_up(old_size),
            MemoryLayout32.page_align_up(new_size),
        )
        try:
            if new_aligned <= old_aligned:
                if new_aligned < old_aligned:
                    self._mem.unmap(old_address + new_aligned, old_aligned - new_aligned)
                self._log.syscall(
                    "mremap(%#x, %#x->%#x) => %#x (in place)",
                    old_address,
                    old_size,
                    new_size,
                    old_address,
                )
                return old_address
            if not (flags & maymove) and not (flags & fixed):
                self._log.syscall(
                    "mremap(%#x) can't grow in place (no MAYMOVE) => -ENOMEM",
                    old_address,
                    level=LogLevel.WARN,
                )
                return -Errno.ENOMEM
            if flags & fixed:
                base = new_address
                self._mem.map(base, new_aligned, RW, "mremap-fixed", replace=True)
            else:
                base = self._mem.mmap(new_aligned, RW, "mremap")
            self._mem.write(base, self._mem.read(old_address, old_size))
            if not (flags & dontunmap):
                self._mem.unmap(old_address, old_aligned)
            self._log.syscall(
                "mremap(%#x, %#x->%#x, flags=%#x) => %#x",
                old_address,
                old_size,
                new_size,
                flags,
                base,
            )
            return base
        except Exception as error:
            self._log.syscall(
                "mremap(%#x) failed (%s) => -ENOMEM", old_address, error, level=LogLevel.ERROR
            )
            return -Errno.ENOMEM

    def _clone(self, flags: int, stack: int, ptid: int, tls: int, ctid: int) -> int:
        if not (flags & CloneFlag.CLONE_THREAD and flags & CloneFlag.CLONE_VM):
            raise UnimplementedSyscall("clone(new process / fork — no process model)", 120)
        tid = self._next_tid & 0xFFFF
        self._next_tid += 1
        if flags & CloneFlag.CLONE_PARENT_SETTID and ptid:
            self._mem.write_u32(ptid, tid)
        if flags & CloneFlag.CLONE_CHILD_SETTID and ctid:
            self._mem.write_u32(ctid, tid)
        self._log.syscall(
            "clone(flags=%#x, stack=%#x, tls=%#x) => %d  "
            "(thread created but NOT run — single-threaded emulation)",
            flags,
            stack,
            tls,
            tid,
            level=LogLevel.WARN,
        )
        return tid

    def _mmap2(self, addr: int, length: int, prot: int, flags: int, fd: int, pgoffset: int) -> int:
        byte_offset = pgoffset * 4096
        return self._mmap_body(addr, length, prot, flags, fd, byte_offset)

    def _mmap_body(
        self, addr: int, length: int, prot: int, flags: int, fd: int, offset: int
    ) -> int:
        if not (flags & MmapFlag.MAP_ANONYMOUS):
            if self._emu.vfs.handle(fd) is None:
                raise UnimplementedSyscall("mmap2(file-backed, unknown fd)", 192)
            base = self._mem.mmap(length, MemoryProtectionFlag(prot & 0x7) or RW, "mmap-file")
            data = self._emu.vfs.pread(fd, length, offset)
            if isinstance(data, bytes) and data:
                self._mem.write(base, data)
            self._log.syscall("mmap2(file fd=%d, len=%#x) => %#x", fd, length, base)
            return base
        perms = MemoryProtectionFlag(prot & 0x7) or RW
        if flags & MmapFlag.MAP_FIXED:
            self._mem.map(addr, length, perms, "mmap-fixed", replace=True)
            base = addr
        else:
            base = self._mem.mmap(length, perms, "mmap")
        self._log.syscall(
            "mmap2(addr=%#x, len=%#x, prot=%s, flags=%#x, fd=%d) => %#x",
            addr,
            length,
            self._prot_str(prot),
            flags,
            fd,
            base,
            level=LogLevel.INFO,
        )
        return base

    def _mprotect(self, addr: int, length: int, prot: int) -> int:
        self._mem.protect(addr, length, MemoryProtectionFlag(prot & 0x7) or RW)
        self._log.syscall("mprotect(%#x, %#x, %s) => 0", addr, length, self._prot_str(prot))
        return 0

    def _msync(self, _addr: int, _length: int, _flags: int) -> int:
        self._log.syscall("msync() => 0")
        return 0

    def _mlock(self, _addr: int, _length: int) -> int:
        self._log.syscall("mlock() => 0")
        return 0

    def _munlock(self, _addr: int, _length: int) -> int:
        self._log.syscall("munlock() => 0")
        return 0

    def _mlockall(self, _flags: int) -> int:
        self._log.syscall("mlockall() => 0")
        return 0

    def _munlockall(self) -> int:
        self._log.syscall("munlockall() => 0")
        return 0

    def _madvise(self, addr: int, length: int, advice: int) -> int:
        self._log.syscall(
            "madvise(%#x, %#x, advice=%d) => 0  (advisory, ignored)", addr, length, advice
        )
        return 0

    def _mlock2(self, _addr: int, _length: int, _flags: int) -> int:
        self._log.syscall("mlock2() => 0")
        return 0

    def _membarrier(self, _cmd: int, _flags: int, _cpu_id: int) -> int:
        self._log.syscall("membarrier() => 0 (single-threaded no-op)")
        return 0

    def _renameat2(self, _od: int, old_ptr: int, _nd: int, new_ptr: int, _flags: int) -> int:
        old, new = self._mem.read_cstr(old_ptr), self._mem.read_cstr(new_ptr)
        result = self._emu.vfs.rename(old, new)
        self._log.syscall("renameat2(%r, %r) => %d", old, new, result)
        return result

    def _getrandom(self, buf: int, length: int, flags: int) -> int:
        self._mem.write(buf, os.urandom(length))
        self._log.syscall(
            "getrandom(buf=%#x, len=%d, flags=%#x) => %d bytes of real entropy",
            buf,
            length,
            flags,
            length,
        )
        return length

    def _prlimit64(self, _pid: int, resource: int, new_limit_ptr: int, old_limit_ptr: int) -> int:
        limit = self._rlimit_for(resource)
        if limit is None:
            self._log.syscall("prlimit64(res=%d) => -EINVAL", resource, level=LogLevel.WARN)
            return -Errno.EINVAL
        if new_limit_ptr:
            self._log.syscall("prlimit64(res=%d) set ignored (sandboxed)", resource)
        if old_limit_ptr:
            cur = min(limit[0], 0xFFFFFFFFFFFFFFFF)
            maximum = min(limit[1], 0xFFFFFFFFFFFFFFFF)
            self._mem.write_u64(old_limit_ptr, cur)
            self._mem.write_u64(old_limit_ptr + 8, maximum)
        self._log.syscall("prlimit64(res=%d) => 0 [cur=%#x max=%#x]", resource, *limit)
        return 0

    def _rseq(self, rseq_ptr: int, _rseq_len: int, flags: int, _sig: int) -> int:
        if flags & 1:
            self._log.syscall("rseq(unregister) => 0")
            return 0
        if rseq_ptr:
            self._mem.write_u32(rseq_ptr, 0)
            self._mem.write_u32(rseq_ptr + 4, 0)
        self._log.syscall("rseq(register) => 0")
        return 0

    def _close_range(self, first: int, last: int, _flags: int) -> int:
        closed = self._emu.vfs.close_range(first, last)
        self._log.syscall("close_range(%d, %d) => 0 (%d closed)", first, last, closed)
        return 0

    def _faccessat2(self, _dirfd: int, path_ptr: int, _mode: int, _flags: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        ok = self._emu.vfs.exists(path)
        self._log.syscall("faccessat2(%r) => %d", path, 0 if ok else -Errno.ENOENT)
        return 0 if ok else -Errno.ENOENT

    def _epoll_pwait2(
        self,
        epfd: int,
        events_ptr: int,
        maxevents: int,
        _timeout: int,
        _sigmask: int,
        _sigsetsize: int,
    ) -> int:
        return self._epoll_pwait(epfd, events_ptr, maxevents, 0, 0, 0)

    def _write_statx(
        self,
        buf: int,
        mode: int,
        size: int,
        rdev: int,
        uid: "int | None" = None,
        gid: "int | None" = None,
        ino: int = 0,
    ) -> None:
        nlink = 2 if mode & StatType.S_IFMT == StatType.S_IFDIR else 1
        p = self._profile
        Statx(
            nlink=nlink,
            uid=p.process_uid if uid is None else uid,
            gid=p.process_gid if gid is None else gid,
            ino=ino,
            mode=mode,
            size=size,
            blocks=(size + 511) // 512,
            time_sec=self._emu.device.file_mtime,
            rdev_major=(rdev >> 8) & 0xFFF if rdev else 0,
            rdev_minor=rdev & 0xFF if rdev else 0,
        ).write_to(self._mem, buf)

    def _statx(self, dirfd: int, path_ptr: int, flags: int, _mask: int, statxbuf: int) -> int:
        path = self._mem.read_cstr(path_ptr)
        stat = (
            self._emu.vfs.fstat(dirfd)
            if not path and (flags & 0x1000)
            else self._emu.vfs.stat_path(path)
        )
        if stat is None:
            self._log.syscall("statx(%r) => -ENOENT", path, level=LogLevel.WARN)
            return -Errno.ENOENT
        self._write_statx(statxbuf, *stat)
        self._log.syscall("statx(%r) => 0 (size=%d)", path, stat[1])
        return 0

    def _arm_set_tls(self, tls: int) -> int:
        self._be.reg_write(Arm32Reg.C13_C0_3, tls)
        self._log.syscall("__ARM_NR_set_tls(%#x) => 0", tls)
        return 0

    def _arm_get_tls(self) -> int:
        tls = self._be.reg_read(Arm32Reg.C13_C0_3)
        self._log.syscall("__ARM_NR_get_tls() => %#x", tls)
        return tls

    def _arm_cacheflush(self, start: int, end: int, _flags: int) -> int:
        self._be.flush_tb()
        self._log.syscall("__ARM_NR_cacheflush(%#x, %#x) => 0 (flushed TB cache)", start, end)
        return 0

    def _arm_breakpoint(self) -> int:
        raise UnimplementedSyscall("__ARM_NR_breakpoint", 0x0F0001)

    def _arm_usr26(self) -> int:
        raise UnimplementedSyscall("__ARM_NR_usr26", 0x0F0003)

    def _arm_usr32(self) -> int:
        raise UnimplementedSyscall("__ARM_NR_usr32", 0x0F0004)

    def _write_stat(
        self,
        statbuf: int,
        mode: int,
        size: int,
        rdev: int,
        uid: "int | None" = None,
        gid: "int | None" = None,
        ino: int = 0,
    ) -> None:
        nlink = 2 if mode & StatType.S_IFMT == StatType.S_IFDIR else 1
        p = self._profile
        stat = FileStat(
            mode=mode,
            size=size,
            rdev=rdev,
            nlink=nlink,
            uid=p.process_uid if uid is None else uid,
            gid=p.process_gid if gid is None else gid,
            ino=ino,
            mtime=self._emu.device.file_mtime,
        )
        Stat32.from_file_stat(stat).write_to(self._mem, statbuf)
