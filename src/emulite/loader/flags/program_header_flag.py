from enum import IntFlag


class ProgramHeaderFlag(IntFlag):
    """ELF ``p_flags`` values from the generic ELF ABI."""

    EXECUTE = 0x1
    WRITE = 0x2
    READ = 0x4

    # Compatibility aliases for the old PfFlag API.
    PF_X = EXECUTE
    PF_W = WRITE
    PF_R = READ
