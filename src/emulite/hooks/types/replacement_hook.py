from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from emulite.hooks.types.replacement_action import ReplacementAction

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class ReplacementHook(Protocol):
    def __call__(self, emu: AndroidEmulatorBase, /) -> ReplacementAction | None: ...
