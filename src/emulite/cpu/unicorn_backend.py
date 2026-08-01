from __future__ import annotations

from typing import Any, Callable

from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_MODE_ARM,
    Uc,
    UcError,
)
from unicorn.arm64_const import UC_ARM64_REG_CP_REG, UC_CPU_ARM64_MAX

from emulite.common.errors import EmulatorCrashed
from emulite.cpu.backend import Backend, CpuArch, HookType, MemoryProtectionFlag
from emulite.cpu.registers.arm32_reg import Arm32Reg
from emulite.cpu.registers.arm64_reg import Arm64Reg


class UnicornBackend(Backend):
    _HOOK_IDS = {
        HookType.INTR: UC_HOOK_INTR,
        HookType.CODE: UC_HOOK_CODE,
        HookType.MEM_READ: UC_HOOK_MEM_READ,
        HookType.MEM_WRITE: UC_HOOK_MEM_WRITE,
        HookType.MEM_FAULT: UC_HOOK_MEM_UNMAPPED,
    }
    _UC = {CpuArch.ARM: (UC_ARCH_ARM, UC_MODE_ARM), CpuArch.ARM64: (UC_ARCH_ARM64, UC_MODE_ARM)}

    def __init__(self, cpu_arch: CpuArch = CpuArch.ARM64) -> None:
        self._uc = Uc(*self._UC[cpu_arch])
        self._is_arm64 = cpu_arch is CpuArch.ARM64
        self._pc_reg = Arm32Reg.PC if cpu_arch is CpuArch.ARM else Arm64Reg.PC
        if cpu_arch is CpuArch.ARM64:
            self._uc.ctl_set_cpu_model(UC_CPU_ARM64_MAX)

    @property
    def uc(self) -> Uc:
        return self._uc

    def destroy(self) -> None:
        self._uc = None

    def reg_read(self, reg_id: int) -> int:
        return self._uc.reg_read(reg_id)

    def reg_write(self, reg_id: int, value: int) -> None:
        self._uc.reg_write(reg_id, value)

    def read_sysreg(self, op0: int, op1: int, crn: int, crm: int, op2: int) -> int:
        self._require_arm64()
        return self._uc.reg_read(UC_ARM64_REG_CP_REG, (crn, crm, op0, op1, op2))

    def write_sysreg(self, op0: int, op1: int, crn: int, crm: int, op2: int, value: int) -> None:
        self._require_arm64()
        self._uc.reg_write(UC_ARM64_REG_CP_REG, (crn, crm, op0, op1, op2, value))

    def _require_arm64(self) -> None:
        if not self._is_arm64:
            raise NotImplementedError("system registers are only modelled on the arm64 backend")

    def mem_map(self, address: int, size: int, perms: MemoryProtectionFlag) -> None:
        try:
            self._uc.mem_map(address, size, int(perms))
        except UcError as e:
            raise EmulatorCrashed(f"mem_map {size:#x} bytes at {address:#x} faulted: {e}") from e

    def mem_protect(self, address: int, size: int, perms: MemoryProtectionFlag) -> None:
        try:
            self._uc.mem_protect(address, size, int(perms))
        except UcError as e:
            raise EmulatorCrashed(
                f"mem_protect {size:#x} bytes at {address:#x} faulted: {e}"
            ) from e

    def mem_unmap(self, address: int, size: int) -> None:
        try:
            self._uc.mem_unmap(address, size)
        except UcError as e:
            raise EmulatorCrashed(f"mem_unmap {size:#x} bytes at {address:#x} faulted: {e}") from e

    def mem_read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self._uc.mem_read(address, size))
        except UcError as e:
            raise EmulatorCrashed(f"mem_read {size} bytes at {address:#x} faulted: {e}") from e

    def mem_write(self, address: int, data: bytes) -> None:
        try:
            self._uc.mem_write(address, data)
        except UcError as e:
            raise EmulatorCrashed(
                f"mem_write {len(data)} bytes at {address:#x} faulted: {e}"
            ) from e

    def hook_add(
        self, hook_type: HookType, callback: Callable, begin: int = 1, end: int = 0
    ) -> int:
        return self._uc.hook_add(self._HOOK_IDS[hook_type], callback, begin=begin, end=end)

    def hook_del(self, handle: int) -> None:
        self._uc.hook_del(handle)

    def flush_tb(self) -> None:
        self._uc.ctl_flush_tb()

    def emu_start(self, begin: int, until: int, timeout: int = 0, count: int = 0) -> None:
        try:
            self._uc.emu_start(begin, until, timeout, count)
        except UcError as e:
            pc = self._uc.reg_read(self._pc_reg)
            raise EmulatorCrashed(f"guest fault at pc={pc:#x}: {e}") from e

    def emu_stop(self) -> None:
        self._uc.emu_stop()

    def context_save(self) -> Any:
        return self._uc.context_save()

    def context_restore(self, context: Any) -> None:
        self._uc.context_restore(context)
