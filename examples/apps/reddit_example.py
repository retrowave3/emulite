from __future__ import annotations

from pathlib import Path

from emulite import AndroidEmulator32, AndroidEmulator64, AndroidEmulatorBase, CallEvent, LogCategory, TraceAction

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


def on_call(_emu: AndroidEmulatorBase, event: CallEvent) -> TraceAction:
    print(f"  {event.format()}")
    return TraceAction.CONTINUE


def decrypt_key(emu: AndroidEmulatorBase) -> object:
    # Call events are emitted when native branches return, and the handle cleans itself up here.
    with emu.call_trace(on_call, module_name="libreddit-ndk.so"):
        return emu.call_static_native("com/reddit/media/common/apikeys/KeyUtil", "decryptGiphyApiKey", "()Ljava/lang/String;")


emu32 = setup_arm32()
emu64 = setup_arm64()

key32 = decrypt_key(emu32)
key64 = decrypt_key(emu64)
print(f"giphy key arm32: {key32}")
print(f"giphy key arm64: {key64}")
