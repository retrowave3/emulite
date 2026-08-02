from __future__ import annotations

from collections.abc import Callable, Iterable
from types import TracebackType


class HookHandle:
    """An idempotent, context-manageable registration returned by every hook API."""

    def __init__(self, remove: Callable[[], None]):
        self._remove = remove
        self._active = True

    def unhook(self) -> None:
        if self._active:
            self._remove()
            self._active = False

    close = unhook

    def __enter__(self) -> HookHandle:  # noqa: PYI034 - typing.Self requires Python 3.11
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None) -> None:
        self.unhook()

    @classmethod
    def combine(cls, handles: Iterable[HookHandle]) -> HookHandle:
        installed = list(handles)

        def remove() -> None:
            first_error: Exception | None = None
            for handle in reversed(installed):
                try:
                    handle.unhook()
                except Exception as error:  # noqa: BLE001 - all handles still need cleanup
                    if first_error is None:
                        first_error = error
            if first_error is not None:
                raise first_error

        return cls(remove)

    @property
    def active(self) -> bool:
        return self._active
