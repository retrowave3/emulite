"""
https://cr.openjdk.org/~nbenalla/GeneratedDocs/K-V-space/docs/specs/jni/functions.html
"""

from __future__ import annotations

from enum import IntEnum


class JNIReturnCode(IntEnum):
    JNI_OK = 0
    JNI_ERR = -1
    JNI_EDETACHED = -2
    JNI_EVERSION = -3
    JNI_ENOMEM = -4
    JNI_EEXIST = -5
    JNI_EINVAL = -6
