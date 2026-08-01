from __future__ import annotations

from enum import IntEnum


class JavaVMFunction(IntEnum):
    DESTROY_JAVA_VM = 3
    ATTACH_CURRENT_THREAD = 4
    DETACH_CURRENT_THREAD = 5
    GET_ENV = 6
    ATTACH_CURRENT_THREAD_AS_DAEMON = 7
