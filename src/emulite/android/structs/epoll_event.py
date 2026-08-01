"""
sys/epoll.h

struct epoll_event {
    uint32_t events;
    epoll_data_t data;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class EpollEvent(PackedStruct):
    SIZE = 12

    events: int = 0
    data: int = 0

    @classmethod
    def read_from(cls, mem: object, address: int) -> "EpollEvent":
        return cls(events=mem.read_u32(address), data=mem.read_u64(address + 4))

    def pack(self) -> bytes:
        return struct.pack("<IQ", self.events, self.data)
