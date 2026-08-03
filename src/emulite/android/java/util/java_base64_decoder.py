"""Model of ``java.util.Base64.Decoder``."""

from __future__ import annotations

import base64
from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util._base64_support import byte_array, raw_bytes


class JavaBase64Decoder(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Base64$Decoder"

    def __init__(self, url_safe: bool = False):
        super().__init__()
        self._url_safe = url_safe

    def decode(self, data: object) -> JavaObject:
        raw = raw_bytes(data)
        padded = raw + b"=" * (-len(raw) % 4)
        out = base64.urlsafe_b64decode(padded) if self._url_safe else base64.b64decode(padded)
        return byte_array(out)
