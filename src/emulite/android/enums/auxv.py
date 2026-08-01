from __future__ import annotations

from enum import IntEnum


class Auxv(IntEnum):
    AT_NULL = 0  # end-of-vector terminator
    AT_PHDR = 3  # program-header table of the main executable (a linker-walker reads this first)
    AT_PHENT = 4  # size of one program-header entry (56 on arm64, 32 on arm32)
    AT_PHNUM = 5  # number of program headers
    AT_PAGESZ = 6  # page size
    AT_ENTRY = 9  # entry point of the main executable
    AT_UID = 11  # real uid
    AT_EUID = 12  # effective uid
    AT_GID = 13  # real gid
    AT_EGID = 14  # effective gid
    AT_PLATFORM = 15  # pointer to the platform string ("aarch64")
    AT_HWCAP = 16  # CPU capability bitmask (bionic ifunc resolvers read this)
    AT_CLKTCK = 17  # clock ticks per second (sysconf _SC_CLK_TCK)
    AT_SECURE = 23  # set-uid/secure-exec flag (0 = normal)
    AT_RANDOM = 25  # pointer to 16 random bytes (stack-guard/PRNG seed)
    AT_HWCAP2 = 26  # second CPU capability bitmask
