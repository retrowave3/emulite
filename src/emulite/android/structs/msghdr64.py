"""
sys/socket.h

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Msghdr64:
    iov: int = 0
    iovlen: int = 0

    @classmethod
    def read_from(cls, mem: object, address: int) -> "Msghdr64":
        return cls(iov=mem.read_u64(address + 16), iovlen=mem.read_u64(address + 24))
