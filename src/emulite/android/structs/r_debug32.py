"""
link.h — 32-bit r_debug (see r_debug64 for the field commentary).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class RDebug32(PackedStruct):
    SIZE = 20

    version: int = 1  # r_version
    map: int = 0  # r_map
    brk: int = 0  # r_brk
    state: int = 0  # r_state
    ldbase: int = 0  # r_ldbase

    def pack(self) -> bytes:
        buf = bytearray(self.SIZE)
        struct.pack_into("<i", buf, 0, self.version)
        struct.pack_into("<I", buf, 4, self.map)
        struct.pack_into("<I", buf, 8, self.brk)
        struct.pack_into("<i", buf, 12, self.state)
        struct.pack_into("<I", buf, 16, self.ldbase)
        return bytes(buf)
