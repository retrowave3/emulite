from __future__ import annotations

from enum import IntEnum


class SockOpt(IntEnum):
    """Linux ``SOL_SOCKET`` option names."""

    SO_REUSEADDR = 2
    SO_TYPE = 3
    SO_ERROR = 4
    SO_BROADCAST = 6
    SO_SNDBUF = 7
    SO_RCVBUF = 8
    SO_KEEPALIVE = 9
    SO_LINGER = 13
    SO_REUSEPORT = 15
    SO_RCVLOWAT = 18
    SO_SNDLOWAT = 19
    SO_RCVTIMEO = 20
    SO_SNDTIMEO = 21
    SO_ACCEPTCONN = 30
    SO_PROTOCOL = 38
    SO_DOMAIN = 39
