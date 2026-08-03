from dataclasses import dataclass

from emulite.loader.module.native_module import NativeModule


@dataclass
class VirtualModule(NativeModule):
    """A symbol-only module backed by host-provided addresses."""

    is_virtual: bool = True
