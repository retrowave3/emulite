class MemoryLayout:
    PAGE_SIZE = 0x1000
    HEAP_BASE = 0x08000000  # brk() heap, grows up
    MMAP_BASE = 0x20000000  # anonymous mmap, grows up
    LIB_BASE = 0x40000000  # loaded modules placed from here, grows up
    RETURN_SENTINEL = 0x50000000  # emu.call sets LR here and stops when PC reaches it
    POISON_BASE = (
        0x5F000000  # never-mapped: unresolved STRONG symbols point here so a guest use faults
    )
    TRAMPOLINE_BASE = 0x60000000  # svc #imm ; ret bridge slots
    JNIENV_BASE = 0x70000000  # JNIEnv function table
    JAVAVM_BASE = 0x70010000  # JavaVM function table
    STACK_TOP = 0x7F00000000  # main stack top (grows down)
    STACK_SIZE = 0x00800000  # 8 MiB (RLIMIT_STACK; a 1 MiB main stack is an emulator tell)
    TLS_SIZE = PAGE_SIZE  # thread-local storage block

    @staticmethod
    def page_align_up(size: int) -> int:
        return (size + MemoryLayout.PAGE_SIZE - 1) & ~(MemoryLayout.PAGE_SIZE - 1)

    @staticmethod
    def page_align_down(addr: int) -> int:
        return addr & ~(MemoryLayout.PAGE_SIZE - 1)


class MemoryLayout32(MemoryLayout):
    STACK_TOP = 0xBF000000  # main stack top, below the 3G/1G split (arm64: 0x7F00000000)
