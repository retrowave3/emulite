from __future__ import annotations

from pathlib import Path

from emulite import AndroidEmulator32, AndroidEmulator64, AndroidEmulatorBase, LogCategory
from emulite.hooks.trace_info import TraceInfo

ASSETS = Path(__file__).resolve().parents[2] / "rootfs" / "examples" / "android"
LIB64 = str(ASSETS / "arm64" / "libreddit-ndk.so")
LIB32 = str(ASSETS / "arm32" / "libreddit-ndk.so")


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


def decrypt_key(emu: AndroidEmulatorBase, trace: bool = False):
    if trace:
        trace_handle = emu.trace_code(on_trace_step)

    decrypted = emu.call_static_native(
        "com/reddit/media/common/apikeys/KeyUtil", "decryptGiphyApiKey", "()Ljava/lang/String;"
    )

    if trace:
        trace_handle.unhook()

    return decrypted


emu32 = setup_arm32()
emu64 = setup_arm64()

key32 = decrypt_key(emu32, trace=False)
key64 = decrypt_key(emu64, trace=False)
print(f"giphy key arm32: {key32}")
print(f"giphy key arm64: {key64}")
