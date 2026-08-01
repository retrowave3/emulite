"""
sys/utsname.h

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Utsname:
    _FIELD = 65  # each utsname member is a fixed 65-byte NUL-terminated buffer
    SIZE = _FIELD * 6

    sysname: str = ""
    nodename: str = ""
    release: str = ""
    version: str = ""
    machine: str = ""
    domainname: str = ""

    def write_to(self, mem: object, address: int) -> None:
        fields = (
            self.sysname,
            self.nodename,
            self.release,
            self.version,
            self.machine,
            self.domainname,
        )
        for index, value in enumerate(fields):
            mem.write_cstr(address + index * self._FIELD, value)
