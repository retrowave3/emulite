from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from emulite.hooks.types.trace_action import TraceAction

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase
    from emulite.hooks.call_event import CallEvent


class CallTraceHook(Protocol):
    def __call__(self, emu: AndroidEmulatorBase, event: CallEvent, /) -> TraceAction | bool | None: ...
