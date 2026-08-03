from typing import ClassVar


class MemoryLayout:
    """Guest address-space constants shared by supported architectures."""

    PAGE_SIZE: ClassVar[int] = 0x1000
    HEAP_BASE: ClassVar[int] = 0x08000000  # brk() heap, grows up
    MMAP_BASE: ClassVar[int] = 0x20000000  # anonymous mmap, grows up
    LIB_BASE: ClassVar[int] = 0x40000000  # loaded modules placed from here, grows up
    RETURN_SENTINEL: ClassVar[int] = 0x50000000  # emu.call sets LR here and stops when PC reaches it
    POISON_BASE: ClassVar[int] = 0x5F000000  # never-mapped: unresolved STRONG symbols point here so a guest use faults
    TRAMPOLINE_BASE: ClassVar[int] = 0x60000000  # svc #imm ; ret bridge slots
    JNIENV_BASE: ClassVar[int] = 0x70000000  # JNIEnv function table
    JAVAVM_BASE: ClassVar[int] = 0x70010000  # JavaVM function table
    STACK_TOP: ClassVar[int] = 0x7F00000000  # main stack top (grows down)
    STACK_SIZE: ClassVar[int] = 0x00800000  # 8 MiB (RLIMIT_STACK; a 1 MiB main stack is an emulator tell)
    TLS_SIZE: ClassVar[int] = PAGE_SIZE  # thread-local storage block

    @classmethod
    def page_align_up(cls, size: int) -> int:
        return (size + cls.PAGE_SIZE - 1) & ~(cls.PAGE_SIZE - 1)

    @classmethod
    def page_align_down(cls, address: int) -> int:
        return address & ~(cls.PAGE_SIZE - 1)
