"""
link.h — 32-bit link_map (see link_map64 for the field commentary).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class LinkMap32(PackedStruct):
    SIZE = 20

    addr: int = 0  # l_addr
    name: int = 0  # l_name
    ld: int = 0  # l_ld
    next: int = 0  # l_next
    prev: int = 0  # l_prev

    def pack(self) -> bytes:
        return struct.pack("<IIIII", self.addr, self.name, self.ld, self.next, self.prev)
