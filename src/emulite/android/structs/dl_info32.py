"""
dlfcn.h

typedef struct {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} Dl_info;
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class DlInfo32(PackedStruct):
    SIZE = 16

    fname: int = 0  # dli_fname  — guest const char* (on-device path)
    fbase: int = 0  # dli_fbase  — module load base
    sname: int = 0  # dli_sname  — guest const char* (nearest symbol name, or 0)
    saddr: int = 0  # dli_saddr  — nearest symbol address, or 0

    def pack(self) -> bytes:
        return struct.pack("<IIII", self.fname, self.fbase, self.sname, self.saddr)
