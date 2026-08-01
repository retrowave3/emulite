"""
link.h

struct dl_phdr_info {
    ElfW(Addr) dlpi_addr;
    const char *dlpi_name;
    const ElfW(Phdr) *dlpi_phdr;
    ElfW(Half) dlpi_phnum;
    unsigned long long dlpi_adds;
    unsigned long long dlpi_subs;
    size_t dlpi_tls_modid;
    void *dlpi_tls_data;
};
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from emulite.android.structs.packed_struct import PackedStruct


@dataclass
class DlPhdrInfo32(PackedStruct):
    SIZE = 40

    addr: int = 0  # dlpi_addr  — load bias
    name: int = 0  # dlpi_name  — guest const char* (on-device path)
    phdr: int = 0  # dlpi_phdr  — guest pointer to the resident program headers
    phnum: int = 0  # dlpi_phnum — u16 (program-header count)

    def pack(self) -> bytes:
        buf = bytearray(self.SIZE)  # extended fields (dlpi_adds/subs/tls_*) stay zero
        struct.pack_into("<I", buf, 0, self.addr)
        struct.pack_into("<I", buf, 4, self.name)
        struct.pack_into("<I", buf, 8, self.phdr)
        struct.pack_into("<H", buf, 12, self.phnum & 0xFFFF)
        return bytes(buf)
