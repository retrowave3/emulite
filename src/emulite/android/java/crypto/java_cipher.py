"""
https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
"""

from __future__ import annotations

from typing import ClassVar

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaCipher(JavaObject):
    JAVA_NAME: ClassVar[str] = "javax/crypto/Cipher"
    ENCRYPT_MODE: ClassVar[int] = 1
    DECRYPT_MODE: ClassVar[int] = 2

    def __init__(self, transformation: str = "AES/CBC/PKCS5Padding"):
        super().__init__()
        algo, mode, padding = (transformation.split("/") + ["ECB", "NoPadding"])[:3]
        self._algo, self._mode, self._padding = algo.upper(), mode.upper(), padding.upper()
        self._opmode: "int | None" = None
        self._key = b""
        self._iv = b""
        self._buffer = bytearray()

    @staticmethod
    def getInstance(transformation: object, *provider: object) -> "JavaCipher":
        name = (
            transformation.value if isinstance(transformation, JavaObject) else str(transformation)
        )
        return JavaCipher(name)

    def getAlgorithm(self) -> str:
        return f"{self._algo}/{self._mode}/{self._padding}"

    def getBlockSize(self) -> int:
        return 16 if self._algo == "AES" else 8

    def init(self, opmode: int, key: object, *params: object) -> None:
        self._opmode = int(opmode)
        self._key = (
            bytes(key.getEncoded().value)
            if hasattr(key, "getEncoded")
            else bytes(getattr(key, "value", b""))
        )
        self._iv = b""
        for spec in params:  # IvParameterSpec / GCMParameterSpec carry getIV()
            get_iv = getattr(spec, "getIV", None)
            if callable(get_iv):
                self._iv = bytes(get_iv().value)
        self._buffer = bytearray()
        return None

    def update(self, data: object, *rest: object) -> None:
        self._buffer.extend(self._raw(data, rest))  # accumulate; block ciphers finalise in doFinal
        return None

    def doFinal(self, *args: object) -> "JavaObject":
        if args:
            self._buffer.extend(self._raw(args[0], args[1:]))
        result = self._transform(bytes(self._buffer))
        self._buffer = bytearray()
        return JavaObject(JavaClass("[B"), bytearray(result))

    def _transform(self, data: bytes) -> bytes:
        if self._algo != "AES":
            raise NotImplementedError(f"javax.crypto.Cipher: algorithm {self._algo} not modelled")
        encrypting = self._opmode == self.ENCRYPT_MODE
        if self._mode == "GCM":
            if encrypting:
                enc = Cipher(algorithms.AES(self._key), modes.GCM(self._iv)).encryptor()
                return enc.update(data) + enc.finalize() + enc.tag  # append the 16-byte tag
            dec = Cipher(algorithms.AES(self._key), modes.GCM(self._iv, data[-16:])).decryptor()
            return dec.update(data[:-16]) + dec.finalize()
        if self._mode == "CBC":
            mode = modes.CBC(self._iv)
        elif self._mode == "ECB":
            mode = modes.ECB()
        elif self._mode == "CTR":
            mode = modes.CTR(self._iv)
        else:
            raise NotImplementedError(f"javax.crypto.Cipher: mode {self._mode} not modelled")
        cipher = Cipher(algorithms.AES(self._key), mode)
        if encrypting:
            padded = self._pad(data) if "PKCS" in self._padding else data
            enc = cipher.encryptor()
            return enc.update(padded) + enc.finalize()
        dec = cipher.decryptor()
        plain = dec.update(data) + dec.finalize()
        return self._unpad(plain) if "PKCS" in self._padding else plain

    @staticmethod
    def _pad(data: bytes) -> bytes:
        pad = 16 - (len(data) % 16)  # PKCS7, always adds 1..16 bytes
        return data + bytes([pad]) * pad

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        return data[: -data[-1]] if data and 1 <= data[-1] <= 16 else data

    @staticmethod
    def _raw(data: object, rest: tuple) -> bytes:
        payload = bytes(data.value) if isinstance(data, JavaObject) else bytes(data)
        if len(rest) >= 2:  # (byte[], offset, length)
            return payload[int(rest[0]) : int(rest[0]) + int(rest[1])]
        return payload
