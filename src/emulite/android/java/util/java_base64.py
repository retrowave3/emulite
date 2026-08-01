"""
https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
"""

from __future__ import annotations

import base64
from typing import ClassVar

from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaBase64Encoder(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Base64$Encoder"

    def __init__(self, url_safe: bool = False, padding: bool = True, mime: bool = False):
        super().__init__()
        self._url_safe = url_safe
        self._padding = padding
        self._mime = mime  # getMimeEncoder: wrap at 76 chars with CRLF separators

    def _encode(self, data: object) -> bytes:
        raw = JavaBase64._raw_bytes(data)
        out = base64.urlsafe_b64encode(raw) if self._url_safe else base64.b64encode(raw)
        if not self._padding:
            out = out.rstrip(b"=")
        if self._mime and out:  # MIME: no more than 76 chars per line, CRLF-separated
            out = b"\r\n".join(out[i : i + 76] for i in range(0, len(out), 76))
        return out

    def encode(self, data: object) -> JavaObject:
        return JavaBase64._byte_array(self._encode(data))

    def encodeToString(self, data: object) -> str:
        return self._encode(data).decode("ascii")

    def withoutPadding(self) -> "JavaBase64Encoder":
        return JavaBase64Encoder(self._url_safe, padding=False, mime=self._mime)


class JavaBase64Decoder(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Base64$Decoder"

    def __init__(self, url_safe: bool = False):
        super().__init__()
        self._url_safe = url_safe

    def decode(self, data: object) -> JavaObject:
        raw = JavaBase64._raw_bytes(data)
        padded = raw + b"=" * (-len(raw) % 4)  # tolerate missing padding, as java.util.Base64 does
        out = base64.urlsafe_b64decode(padded) if self._url_safe else base64.b64decode(padded)
        return JavaBase64._byte_array(out)


class JavaBase64(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Base64"

    @staticmethod
    def getEncoder() -> JavaBase64Encoder:
        return JavaBase64Encoder()

    @staticmethod
    def getUrlEncoder() -> JavaBase64Encoder:
        return JavaBase64Encoder(url_safe=True)

    @staticmethod
    def getMimeEncoder() -> JavaBase64Encoder:
        return JavaBase64Encoder(mime=True)

    @staticmethod
    def getDecoder() -> JavaBase64Decoder:
        return JavaBase64Decoder()

    @staticmethod
    def getUrlDecoder() -> JavaBase64Decoder:
        return JavaBase64Decoder(url_safe=True)

    @staticmethod
    def _raw_bytes(data: object) -> bytes:
        if isinstance(data, JavaObject):
            data = data.value
        if isinstance(data, str):
            return data.encode("utf-8")
        return bytes(data or b"")

    @staticmethod
    def _byte_array(data: bytes) -> JavaObject:
        return JavaObject(JavaClass("[B"), bytearray(data))
