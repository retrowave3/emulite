"""
https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
"""

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject
from emulite.android.java.util.java_base64_decoder import JavaBase64Decoder
from emulite.android.java.util.java_base64_encoder import JavaBase64Encoder


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
