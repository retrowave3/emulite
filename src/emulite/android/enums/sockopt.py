from __future__ import annotations

from enum import IntEnum


class SockOpt(IntEnum):
    SO_REUSEADDR = 2
    SO_TYPE = 3
    SO_ERROR = 4
    SO_BROADCAST = 6
    SO_SNDBUF = 7
    SO_RCVBUF = 8
    SO_KEEPALIVE = 9
