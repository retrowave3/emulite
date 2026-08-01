from __future__ import annotations

import time


class VirtualClock:
    _TICK_NS = 20_000

    def __init__(self, boot_uptime_ns: int):
        self._boot_realtime_ns = time.time_ns() - boot_uptime_ns
        self._boot_uptime_ns = boot_uptime_ns
        self._elapsed_ns = 0

    def monotonic_ns(self, advance: bool = True) -> int:
        if advance:
            self._elapsed_ns += self._TICK_NS
        return self._boot_uptime_ns + self._elapsed_ns

    def realtime_ns(self, advance: bool = True) -> int:
        return self._boot_realtime_ns + self.monotonic_ns(advance)

    def advance(self, nanos: int) -> None:
        self._elapsed_ns += max(nanos, 0)

    def sync_realtime(self, nanos: int) -> None:
        self.advance(nanos - self.realtime_ns(advance=False))

    def sync_monotonic(self, nanos: int) -> None:
        self.advance(nanos - self.monotonic_ns(advance=False))

    @property
    def boot_realtime_s(self) -> int:
        return self._boot_realtime_ns // 1_000_000_000

    @property
    def boot_uptime_s(self) -> int:
        return self._boot_uptime_ns // 1_000_000_000

    def uptime_s(self) -> int:
        return self.monotonic_ns() // 1_000_000_000
