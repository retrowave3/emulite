from dataclasses import dataclass


@dataclass(slots=True)
class LinkerImage:
    """Guest-visible ELF image represented in the dynamic linker's debug chain."""

    base: int
    phdr_addr: int
    phnum: int
    device_path: str
    ld: int = 0
    name_ptr: int = 0
