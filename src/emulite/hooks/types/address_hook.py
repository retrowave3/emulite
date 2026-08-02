from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class AddressHook(Protocol):
    def __call__(self, emu: AndroidEmulatorBase, /) -> None: ...
