from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

import lief

if TYPE_CHECKING:
    from emulite.loader.module.native_module import NativeModule


class DeferredRelocation(NamedTuple):
    """A symbol relocation waiting for another module to provide its target."""

    module: NativeModule
    address: int
    symbol_name: str
    relocation_type: lief.ELF.Relocation.TYPE
    addend: int
