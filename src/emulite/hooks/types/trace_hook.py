from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from emulite.hooks.types.trace_action import TraceAction

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase
    from emulite.hooks.trace_info import TraceInfo


class TraceHook(Protocol):
    def __call__(self, emu: AndroidEmulatorBase, info: TraceInfo, /) -> TraceAction | None: ...
