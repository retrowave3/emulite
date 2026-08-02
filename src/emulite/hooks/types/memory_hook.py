from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from emulite.hooks.types.memory_access import MemoryAccess
from emulite.hooks.types.memory_hook_action import MemoryHookAction

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class MemoryHook(Protocol):
    def __call__(self, emu: AndroidEmulatorBase, access: MemoryAccess, address: int, size: int, value: int, /) -> MemoryHookAction | bool | None: ...
