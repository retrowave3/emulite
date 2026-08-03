from dataclasses import dataclass

import lief


@dataclass(frozen=True, slots=True)
class RelocationDialect:
    """Architecture-specific ELF relocation kinds."""

    relative: lief.ELF.Relocation.TYPE
    jump_slot: lief.ELF.Relocation.TYPE
    irelative: lief.ELF.Relocation.TYPE
    uses_rela: bool
    symbolic: tuple[lief.ELF.Relocation.TYPE, ...]
    tls_desc: lief.ELF.Relocation.TYPE | None
    tls_offset: tuple[lief.ELF.Relocation.TYPE, ...]
    tls_module: tuple[lief.ELF.Relocation.TYPE, ...]
