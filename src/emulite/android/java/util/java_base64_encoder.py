"""Model of ``java.util.Base64.Encoder``."""

from __future__ import annotations

import base64
from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._base64_support import byte_array, raw_bytes


class JavaBase64Encoder(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Base64$Encoder"

    def __init__(self, url_safe: bool = False, padding: bool = True, mime: bool = False):
        super().__init__()
        self._url_safe = url_safe
        self._padding = padding
        self._mime = mime

    def _encode(self, data: object) -> bytes:
        out = base64.urlsafe_b64encode(raw_bytes(data)) if self._url_safe else base64.b64encode(raw_bytes(data))
        if not self._padding:
            out = out.rstrip(b"=")
        if self._mime and out:
            out = b"\r\n".join(out[i : i + 76] for i in range(0, len(out), 76))
        return out

    def encode(self, data: object) -> JavaObject:
        return byte_array(self._encode(data))

    def encodeToString(self, data: object) -> str:
        return self._encode(data).decode("ascii")

    def withoutPadding(self) -> JavaBase64Encoder:
        return JavaBase64Encoder(self._url_safe, padding=False, mime=self._mime)
