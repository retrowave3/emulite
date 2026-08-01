from __future__ import annotations

from dataclasses import dataclass, field

from emulite.loader.module.native_module import NativeModule


@dataclass
class LinuxModule(NativeModule):
    init: int = 0  # DT_INIT (absolute) or 0
    init_array: list[int] = field(default_factory=list)  # DT_INIT_ARRAY entries (absolute)
    fini: int = 0  # DT_FINI (absolute) or 0
    fini_array: list[int] = field(default_factory=list)  # DT_FINI_ARRAY entries (absolute)
    preinit_array: list[int] = field(
        default_factory=list
    )  # DT_PREINIT_ARRAY (ignored for a plain .so)

    def init_functions(self) -> list[int]:
        return ([self.init] if self.init else []) + self.init_array

    def fini_functions(self) -> list[int]:
        return list(reversed(self.fini_array)) + ([self.fini] if self.fini else [])
