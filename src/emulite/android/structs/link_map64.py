"""
link.h

struct link_map {
    ElfW(Addr) l_addr;      // load bias (base) of this module
    char *l_name;           // absolute path the linker loaded it from
    ElfW(Dyn) *l_ld;        // this module's _DYNAMIC array (l_addr-relative d_ptr fields)
    struct link_map *l_next;
    struct link_map *l_prev;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class LinkMap64(PackedStruct):
    SIZE = 40

    addr: int = 0  # l_addr — load bias
    name: int = 0  # l_name — guest const char* (on-device path)
    ld: int = 0  # l_ld   — guest ptr to this module's _DYNAMIC array
    next: int = 0  # l_next — next node (0: tail)
    prev: int = 0  # l_prev — previous node (0: head)

    def pack(self) -> bytes:
        return struct.pack("<QQQQQ", self.addr, self.name, self.ld, self.next, self.prev)
