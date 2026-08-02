"""
https://docs.oracle.com/javase/8/docs/api/javax/crypto/Mac.html
"""

from __future__ import annotations

import hashlib
import hmac
from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaMac(JavaObject):
    JAVA_NAME: ClassVar[str] = "javax/crypto/Mac"
    _DIGESTS = {"HMACSHA1": "sha1", "HMACSHA224": "sha224", "HMACSHA256": "sha256", "HMACSHA384": "sha384", "HMACSHA512": "sha512", "HMACMD5": "md5"}

    def __init__(self, algorithm: str = "HmacSHA256"):
        super().__init__()
        self._algorithm = algorithm
        self._digestmod = self._DIGESTS.get(algorithm.upper().replace("-", ""), "sha256")
        self._key = b""
        self._hmac = None

    @staticmethod
    def getInstance(algorithm: object, *provider: object) -> "JavaMac":
        name = algorithm.value if isinstance(algorithm, JavaObject) else str(algorithm)
        return JavaMac(name)

    def getAlgorithm(self) -> str:
        return self._algorithm

    def init(self, key: object, *params: object) -> None:
        self._key = bytes(key.getEncoded().value) if hasattr(key, "getEncoded") else bytes(getattr(key, "value", b""))
        self._hmac = hmac.new(self._key, digestmod=self._digestmod)
        return None

    def update(self, data: object, *rest: object) -> None:
        self._hmac.update(self._raw(data, rest))
        return None

    def doFinal(self, *args: object) -> "JavaObject":
        if args:
            self._hmac.update(self._raw(args[0], args[1:]))
        digest = self._hmac.digest()
        self._hmac = hmac.new(self._key, digestmod=self._digestmod)  # Java doFinal resets the Mac
        return JavaObject(JavaClass("[B"), bytearray(digest))

    def getMacLength(self) -> int:
        return hashlib.new(self._digestmod).digest_size

    def reset(self) -> None:
        self._hmac = hmac.new(self._key, digestmod=self._digestmod)
        return None

    @staticmethod
    def _raw(data: object, rest: tuple) -> bytes:
        payload = bytes(data.value) if isinstance(data, JavaObject) else bytes(data)
        return payload[int(rest[0]) : int(rest[0]) + int(rest[1])] if len(rest) >= 2 else payload
