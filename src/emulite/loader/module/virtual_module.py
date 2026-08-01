from dataclasses import dataclass

from emulite.loader.module.native_module import NativeModule


@dataclass
class VirtualModule(NativeModule):
    is_virtual: bool = True
