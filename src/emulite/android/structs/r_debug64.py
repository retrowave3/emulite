"""
link.h

struct r_debug {
    int r_version;              // 1
    struct link_map *r_map;     // head of the loaded-module list
    ElfW(Addr) r_brk;           // linker breakpoint a debugger sets to catch dlopen/dlclose
    enum { RT_CONSISTENT, RT_ADD, RT_DELETE } r_state;
    ElfW(Addr) r_ldbase;        // load base of the dynamic linker
};

Reached by a debugger/anti-tamper via the main executable's PT_DYNAMIC -> DT_DEBUG.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class RDebug64(PackedStruct):
    SIZE = 40

    version: int = 1  # r_version
    map: int = 0  # r_map    — guest ptr to the head link_map node
    brk: int = 0  # r_brk    — linker rendezvous breakpoint (0: none)
    state: int = 0  # r_state  — RT_CONSISTENT while not mid-(un)load
    ldbase: int = 0  # r_ldbase — dynamic-linker load base

    def pack(self) -> bytes:
        buf = bytearray(self.SIZE)
        struct.pack_into("<i", buf, 0, self.version)
        struct.pack_into("<Q", buf, 8, self.map)
        struct.pack_into("<Q", buf, 16, self.brk)
        struct.pack_into("<i", buf, 24, self.state)
        struct.pack_into("<Q", buf, 32, self.ldbase)
        return bytes(buf)
