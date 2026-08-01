from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from emulite import AndroidEmulatorBase, AndroidEmulator32, AndroidEmulator64, LogCategory

HERE = os.path.dirname(__file__)
ROOTFS = os.path.join(HERE, "..", "..", "rootfs", "android")
LIB64 = os.path.join(HERE, "..", "..", "rootfs", "examples", "android", "arm64", "libtmessages.49.so")
LIB32 = os.path.join(HERE, "..", "..", "rootfs", "examples", "android", "arm32", "libtmessages.49.so")

def setup_arm64() -> AndroidEmulator64:
    emu = AndroidEmulator64(rootfs=ROOTFS, log=LogCategory.NONE)
    module = emu.load(LIB64)
    emu.call_jni_onload(module)
    return emu

def setup_arm32() -> AndroidEmulator32:
    emu = AndroidEmulator32(rootfs=ROOTFS, log=LogCategory.NONE)
    module = emu.load(LIB32)
    emu.call_jni_onload(module)
    return emu

def run_crypto(emu: AndroidEmulatorBase):
    utils = emu.java_class("org/telegram/messenger/Utilities")
    password, salt, dst = bytearray(b"123456"), bytearray(8), bytearray(64)
    utils.call("pbkdf2", "([B[B[BI)V", password, salt, dst, 256)

    data, key, iv = bytearray(16), bytearray(32), bytearray(16)
    utils.call("aesCtrDecryptionByteArray", "([B[B[BIIJ)V", data, key, iv, 0, 16, 0)

    return dst.hex(), data.hex()


emu32 = setup_arm32()
emu64 = setup_arm64()

pbkdf2_32, aes_ctr_32 = run_crypto(emu32)
pbkdf2_64, aes_ctr_64 = run_crypto(emu64)
print(f"arm32 pbkdf2 : {pbkdf2_32}")
print(f"arm32 aes-ctr: {aes_ctr_32}")
print(f"arm64 pbkdf2 : {pbkdf2_64}")
print(f"arm64 aes-ctr: {aes_ctr_64}")
