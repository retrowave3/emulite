"""
https://cr.openjdk.org/~nbenalla/GeneratedDocs/K-V-space/docs/specs/jni/functions.html
"""

from __future__ import annotations

from enum import IntEnum


class JNIVersion(IntEnum):
    JNI_VERSION_1_1 = 0x00010001
    JNI_VERSION_1_2 = 0x00010002
    JNI_VERSION_1_4 = 0x00010004
    JNI_VERSION_1_6 = 0x00010006
    JNI_VERSION_1_8 = 0x00010008
    JNI_VERSION_9 = 0x00090000
    JNI_VERSION_10 = 0x000A0000
    JNI_VERSION_19 = 0x00130000
    JNI_VERSION_20 = 0x00140000
    JNI_VERSION_21 = 0x00150000
    JNI_VERSION_24 = 0x00180000
