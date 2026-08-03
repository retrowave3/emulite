from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from emulite.hooks.types.memory_fault_action import MemoryFaultAction

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class MemoryFaultHook(Protocol):
    def __call__(self, emu: AndroidEmulatorBase, address: int, size: int, /) -> MemoryFaultAction: ...
