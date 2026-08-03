class EmuliteError(Exception):
    pass


class EmulatorCrashed(EmuliteError):
    symbolized: bool = False


class NestedExecution(EmuliteError):
    pass


class SymbolMissing(EmuliteError):
    pass


class ElfFormatError(EmuliteError):
    pass


class JavaExceptionThrown(EmuliteError):
    def __init__(self, exception: object):
        self.exception = exception
        super().__init__(f"native method threw {exception!r}")


class JavaException(EmuliteError):
    # raise this from a JniHandler to model a Java method throwing; the dispatch turns it into a pending
    # JNI exception the native code sees via ExceptionCheck/ExceptionOccurred (like Java's `throw`).
    def __init__(self, class_name: str, message: str = ""):
        self.class_name = class_name
        self.message = message
        super().__init__(f"{class_name}: {message}" if message else class_name)


class MissingSlot(EmuliteError):
    pass


class UnknownSyscall(EmuliteError):
    def __init__(self, number: int):
        self.number = number
        super().__init__(f"unknown syscall number {number} (no handler registered)")


class UnimplementedSyscall(EmuliteError):
    def __init__(self, name: str, number: int):
        self.name = name
        self.number = number
        super().__init__(f"syscall {name} (nr={number}) is not implemented")
