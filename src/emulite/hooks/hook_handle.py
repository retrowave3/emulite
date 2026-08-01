from __future__ import annotations

from collections.abc import Callable, Iterable


class HookHandle:
    def __init__(self, remove: Callable[[], None]):
        self._remove = remove
        self._active = True

    def unhook(self) -> None:
        if self._active:
            self._remove()
            self._active = False

    close = unhook

    def __enter__(self) -> HookHandle:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.unhook()

    @classmethod
    def combine(cls, handles: Iterable[HookHandle]) -> HookHandle:
        installed = list(handles)

        def remove() -> None:
            for handle in reversed(installed):
                handle.unhook()

        return cls(remove)

    @property
    def active(self) -> bool:
        return self._active
