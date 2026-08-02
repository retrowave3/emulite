from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from emulite.hooks.hook_status import HookStatus

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class ReplacementHook(Protocol):
    def __call__(self, emu: AndroidEmulatorBase, /) -> HookStatus | None: ...
