from typing import TypeAlias

from emulite.loader.module.symbol import Symbol
from emulite.memory.native_pointer import NativePointer

NativeArgument: TypeAlias = int | str | bytes | bytearray | Symbol | NativePointer
