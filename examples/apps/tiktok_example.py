from __future__ import annotations

from pathlib import Path

from emulite import AndroidEmulator32, AndroidEmulator64, AndroidEmulatorBase, LogCategory
from emulite.hooks.hook_status import HookStatus
from emulite.hooks.trace_info import TraceInfo

ASSETS = Path(__file__).resolve().parents[2] / "rootfs" / "examples" / "android"
LIB64 = str(ASSETS / "arm64" / "libEncryptor.so")
LIB32 = str(ASSETS / "arm32" / "libEncryptor.so")


def setup_arm64() -> AndroidEmulator64:
    emu = AndroidEmulator64(log=LogCategory.NONE)
    module = emu.load(LIB64)
    emu.call_jni_onload(module)
    return emu


def setup_arm32() -> AndroidEmulator32:
    emu = AndroidEmulator32(log=LogCategory.NONE)
    module = emu.load(LIB32)
    emu.call_jni_onload(module)
    return emu


def on_trace_step(emu: AndroidEmulatorBase, info: TraceInfo):
    print(info.format())
    # return False                      # return False from the callback to stop tracing early


def before_memcpy(emu: AndroidEmulatorBase):
    dst, src, n = emu.arg(0), emu.arg(1), emu.arg(2)  # x0, x1, x2
    print(f"memcpy({dst:#x}, {src:#x}, {n})")
    return HookStatus.CALL_ORIGINAL


def after_memcpy(emu: AndroidEmulatorBase):
    pass


def before_time(emu: AndroidEmulatorBase):
    replacement_value = 123456789
    emu.set_arg(0, replacement_value)  # store result in r0/x0
    print(f"replaced time: {replacement_value}")
    return HookStatus.SKIP_ORIGINAL


def encrypt(emu: AndroidEmulatorBase, data: bytes, trace: bool = False):
    memcpy_handle = emu.hook_symbol("memcpy", before_memcpy, after_memcpy)
    time_handle = emu.hook_symbol("time", before_time)
    if trace:
        trace_handle = emu.trace_code(on_trace_step)

    encrypted = emu.call_static_native(
        "com/bytedance/frameworks/encryptor/EncryptorUtil", "ttEncrypt", "([BI)[B", data, len(data)
    )

    memcpy_handle.unhook()
    time_handle.unhook()
    if trace:
        trace_handle.unhook()

    return encrypted


emu32 = setup_arm32()
emu64 = setup_arm64()

data = b"hello world"
emu32_result = encrypt(emu32, data, trace=False)
emu64_result = encrypt(emu64, data, trace=False)

print(f"ttencrypt arm32: {bytes(emu32_result).hex()}")
print(f"ttencrypt arm64: {bytes(emu64_result).hex()}")
