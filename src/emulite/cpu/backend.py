from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from emulite.cpu.enums.cpu_arch import CpuArch
from emulite.cpu.enums.hook_type import HookType
from emulite.cpu.flags.memory_protection_flag import RW, RWX, RX, MemoryProtectionFlag

__all__ = ["RW", "RWX", "RX", "Backend", "CpuArch", "HookType", "MemoryProtectionFlag"]


class Backend(ABC):
    """Architecture-neutral interface implemented by CPU engines."""

    @abstractmethod
    def destroy(self) -> None: ...

    @abstractmethod
    def reg_read(self, reg_id: int) -> int: ...

    @abstractmethod
    def reg_write(self, reg_id: int, value: int) -> None: ...

    def read_sysreg(self, op0: int, op1: int, crn: int, crm: int, op2: int) -> int:
        raise NotImplementedError("this backend does not expose system registers")

    def write_sysreg(self, op0: int, op1: int, crn: int, crm: int, op2: int, value: int) -> None:
        raise NotImplementedError("this backend does not expose system registers")

    @abstractmethod
    def mem_map(self, address: int, size: int, perms: MemoryProtectionFlag) -> None: ...

    @abstractmethod
    def mem_protect(self, address: int, size: int, perms: MemoryProtectionFlag) -> None: ...

    @abstractmethod
    def mem_unmap(self, address: int, size: int) -> None: ...

    @abstractmethod
    def mem_read(self, address: int, size: int) -> bytes: ...

    @abstractmethod
    def mem_write(self, address: int, data: bytes) -> None: ...

    @abstractmethod
    def hook_add(self, hook_type: HookType, callback: Callable[..., object], begin: int = 1, end: int = 0) -> int: ...

    @abstractmethod
    def hook_del(self, handle: int) -> None: ...

    @abstractmethod
    def flush_tb(self) -> None: ...

    @abstractmethod
    def emu_start(self, begin: int, until: int, timeout: int = 0, count: int = 0) -> None: ...

    @abstractmethod
    def emu_stop(self) -> None: ...

    @abstractmethod
    def context_save(self) -> object: ...

    @abstractmethod
    def context_restore(self, context: object) -> None: ...
