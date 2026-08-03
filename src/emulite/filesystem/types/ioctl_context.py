from typing import Protocol

from emulite.common.log import Logger
from emulite.memory import MemoryManager


class IoctlContext(Protocol):
    """Emulator services available to virtual device ioctl handlers."""

    mem: MemoryManager
    log: Logger
