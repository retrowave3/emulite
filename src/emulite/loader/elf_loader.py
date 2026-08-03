from __future__ import annotations

import os
import struct
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, ClassVar

import lief

from emulite.android.flags.pf_flag import PfFlag
from emulite.common.errors import ElfFormatError, EmuliteError
from emulite.common.log import Logger, LogLevel
from emulite.cpu.backend import CpuArch, MemoryProtectionFlag
from emulite.loader.module.linux_module import LinuxModule
from emulite.loader.module.native_module import NativeModule
from emulite.loader.module.symbol import Symbol
from emulite.loader.module.virtual_module import VirtualModule
from emulite.loader.types.deferred_relocation import DeferredRelocation
from emulite.loader.types.module_segment import ModuleSegment
from emulite.loader.types.relocation_dialect import RelocationDialect
from emulite.loader.types.symbol_binding import SymbolBinding
from emulite.loader.types.symbol_type import SymbolType
from emulite.memory import RW, RX, MemoryLayout, MemoryManager

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase


class ElfLoader:
    """Loads ARM ELF shared objects into guest memory and resolves their symbols."""

    _T = lief.ELF.Relocation.TYPE
    _TAG = lief.ELF.DynamicEntry.TAG
    _MACHINE: ClassVar[dict[CpuArch, lief.ELF.ARCH]] = {CpuArch.ARM64: lief.ELF.ARCH.AARCH64, CpuArch.ARM: lief.ELF.ARCH.ARM}
    _IGNORED: ClassVar[tuple[lief.ELF.Relocation.TYPE, ...]] = tuple(t for t in (getattr(_T, "AARCH64_NONE", None), getattr(_T, "ARM_NONE", None), getattr(_T, "NONE", None)) if t is not None)
    _RELOC: ClassVar[dict[CpuArch, RelocationDialect]] = {
        CpuArch.ARM64: RelocationDialect(
            relative=_T.AARCH64_RELATIVE,
            jump_slot=_T.AARCH64_JUMP_SLOT,
            irelative=_T.AARCH64_IRELATIVE,
            uses_rela=True,
            symbolic=(_T.AARCH64_GLOB_DAT, _T.AARCH64_ABS64, _T.AARCH64_JUMP_SLOT),
            tls_desc=_T.AARCH64_TLSDESC,
            tls_offset=(_T.AARCH64_TLS_TPREL64, _T.AARCH64_TLS_DTPREL64),
            tls_module=(_T.AARCH64_TLS_DTPMOD64,),
        ),
        CpuArch.ARM: RelocationDialect(
            relative=_T.ARM_RELATIVE,
            jump_slot=_T.ARM_JUMP_SLOT,
            irelative=_T.ARM_IRELATIVE,
            uses_rela=False,
            symbolic=(_T.ARM_GLOB_DAT, _T.ARM_ABS32, _T.ARM_JUMP_SLOT),
            tls_desc=getattr(_T, "ARM_TLS_DESC", None),
            tls_offset=tuple(t for t in (getattr(_T, "ARM_TLS_TPOFF32", None), getattr(_T, "ARM_TLS_DTPOFF32", None)) if t is not None),
            tls_module=tuple(t for t in (getattr(_T, "ARM_TLS_DTPMOD32", None),) if t is not None),
        ),
    }

    @staticmethod
    def _enum_name(value: object) -> str:
        name = getattr(value, "name", None)
        return name if isinstance(name, str) else str(value).rsplit(".", 1)[-1]

    @staticmethod
    def _text(value: str | bytes) -> str:
        return value.decode() if isinstance(value, bytes) else value

    @staticmethod
    def _seg_perms(elf_flags: int) -> MemoryProtectionFlag:
        perms = MemoryProtectionFlag.NONE
        if elf_flags & PfFlag.PF_R:
            perms |= MemoryProtectionFlag.READ
        if elf_flags & PfFlag.PF_W:
            perms |= MemoryProtectionFlag.WRITE
        if elf_flags & PfFlag.PF_X:
            perms |= MemoryProtectionFlag.EXEC
        return perms

    def __init__(self, mem: MemoryManager, log: Logger, rootfs: str | os.PathLike[str] | None = None, search_paths: Iterable[str | os.PathLike[str]] = ()):
        self._mem = mem
        self._arch = mem.arch
        self._log = log
        self.emu: AndroidEmulatorBase | None = None
        self._rootfs = os.fspath(rootfs) if rootfs is not None else None
        self._search = [os.fspath(path) for path in search_paths]
        self.modules: dict[str, NativeModule] = {}
        self._exports: dict[str, int] = {}
        self._data_symbols: dict[str, int] = {}
        self._weak: dict[str, bool] = {}
        self.unresolved: list[tuple[str, str]] = []
        self.deferred_relocs: list[DeferredRelocation] = []
        self.pending_init: list[NativeModule] = []
        self.pending_irelative: list[tuple[int, int]] = []
        self._tlsdesc_stub: int | None = None
        self._loading: set[str] = set()
        self.resolve_override: Callable[[str], int | None] | None = None
        self.resolve_fallback: Callable[[str], int | None] | None = None
        self.after_load: Callable[[], None] | None = None

    @property
    def loaded_modules(self) -> tuple[NativeModule, ...]:
        """Return loaded modules once each, excluding duplicate lookup aliases."""
        return tuple({id(module): module for module in self.modules.values()}.values())

    def load(self, path_or_name: str | os.PathLike[str], is_dependency: bool = False, scan_only: bool = False) -> NativeModule:
        path = os.fspath(path_or_name)
        name = os.path.basename(path.replace("\\", "/"))
        if name in self.modules:
            return self.modules[name]
        if name in self._loading:
            self._log.loader("circular dependency on %s -> using the in-progress module", name, level=LogLevel.WARN)
            module = self.modules.get(name)
            if module is None:
                raise ElfFormatError(f"circular dependency {name!r} was encountered before its module was registered")
            return module
        self._loading.add(name)
        try:
            module = self._load(path, name, is_dependency, scan_only)
        finally:
            self._loading.discard(name)
        if not self._loading:
            self.resolve_pending_symbols()
            if self.after_load is not None:
                self.after_load()
        return module

    def _load(self, path_or_name: str, name: str, is_dependency: bool, scan_only: bool = False) -> NativeModule:
        resolved = self._find_file(path_or_name)
        binary = lief.ELF.parse(resolved)
        expected = self._MACHINE.get(self._arch.cpu_arch)
        if binary is None or expected is None or binary.header.machine_type != expected:
            raise ElfFormatError(f"{name}: not a parseable {self._arch.name} ELF")

        needed = [self._text(library) for library in binary.libraries]
        loads = [s for s in binary.segments if s.type == lief.ELF.Segment.TYPE.LOAD]
        if not loads:
            raise ElfFormatError(f"{name}: ELF has no loadable segments")
        span = MemoryLayout.page_align_up(max(s.virtual_address + s.virtual_size for s in loads))
        seg_align = max((int(s.alignment) for s in loads if s.alignment > 1), default=MemoryLayout.PAGE_SIZE)
        base = self._mem.reserve_lib(span, align=seg_align)
        segments = self._map_segments(name, loads, base)

        module = LinuxModule(name, path_or_name, base, span, dependencies=needed, segments=segments, mem=self._mem, emu=self.emu)
        module.phdr_addr = base + binary.header.program_header_offset
        module.phnum = binary.header.numberof_segments
        dynamic = next((s for s in binary.segments if s.type == lief.ELF.Segment.TYPE.DYNAMIC), None)
        if dynamic is not None:
            module.dynamic_addr = base + dynamic.virtual_address
        module.entry_point = base + binary.header.entrypoint
        self.modules[name] = module
        soname_entry = binary.get(self._TAG.SONAME)
        soname = self._text(soname_entry.name) if isinstance(soname_entry, lief.ELF.DynamicSharedObject) else None
        if soname and soname != name:
            self.modules.setdefault(soname, module)

        self._register_exports(binary, base, module, expose=not scan_only)
        for dep in needed:
            try:
                self.load(dep, is_dependency=True)
            except (FileNotFoundError, EmuliteError) as e:
                self._log.loader("dependency %s unavailable (%s)", dep, e, level=LogLevel.WARN)
        self._apply_relocations(binary, base, module)
        self._discover_init(binary, base, module)
        if not scan_only and (not is_dependency or self._is_app_shipped(resolved)):
            self.pending_init.append(module)

        self._log.library_load(name, base, span)
        return module

    def add_data_symbol(self, name: str, address: int) -> None:
        self._data_symbols[name] = address
        self._log.loader("add_data_symbol %s => %#x", name, address)

    def add_search_path(self, path: str | os.PathLike[str]) -> None:
        """Add a directory searched for library names."""
        self._search.append(os.fspath(path))

    def create_virtual_module(self, name: str, symbols: dict[str, int] | None = None) -> VirtualModule:
        module = VirtualModule(name=name, path=name, base=0, size=0)
        for sym_name, address in (symbols or {}).items():
            module.exports[sym_name] = address
            self._data_symbols[sym_name] = address
        self.modules[name] = module
        return module

    def find_export(self, name: str) -> int | None:
        return self._exports.get(name)

    def resolve(self, name: str) -> int | None:
        return self._resolve(name)

    def module_by_base(self, base: int) -> NativeModule | None:
        return next((module for module in self.loaded_modules if module.base == base), None)

    def module_at(self, addr: int) -> NativeModule | None:
        return next((module for module in self.loaded_modules if module.contains(addr)), None)

    def _map_segments(self, name: str, loads: list[lief.ELF.Segment], base: int) -> list[ModuleSegment]:
        loads = sorted(loads, key=lambda s: s.virtual_address)
        page = MemoryLayout.PAGE_SIZE
        span_lo = MemoryLayout.page_align_down(base + loads[0].virtual_address)
        span_hi = MemoryLayout.page_align_up(base + max(s.virtual_address + s.virtual_size for s in loads))
        page_perms = {addr: MemoryProtectionFlag.NONE for addr in range(span_lo, span_hi, page)}
        for seg in loads:
            lo = MemoryLayout.page_align_down(base + seg.virtual_address)
            hi = MemoryLayout.page_align_up(base + seg.virtual_address + seg.virtual_size)
            perms = self._seg_perms(int(seg.flags))
            for addr in range(lo, hi, page):
                page_perms[addr] |= perms
        segments: list[ModuleSegment] = []
        for addr in range(span_lo, span_hi, page):
            perms = page_perms[addr]
            if segments and segments[-1][0] + segments[-1][1] == addr and segments[-1][2] == perms:
                base_, size_, _ = segments[-1]
                segments[-1] = ModuleSegment(base_, size_ + page, perms)
            else:
                segments.append(ModuleSegment(addr, page, perms))
        for start, size, _ in segments:
            self._mem.map(start, size, RW, f"{name} LOAD")
        for seg in loads:
            self._mem.write(base + seg.virtual_address, bytes(seg.content))
        for start, size, perms in segments:
            self._mem.protect(start, size, perms)
        return segments

    def _register_exports(self, binary: lief.ELF.Binary, base: int, module: NativeModule, expose: bool = True) -> None:
        for sym in binary.dynamic_symbols:
            if not sym.name:
                continue
            symbol_name = self._text(sym.name)
            undefined = bool(sym.imported)
            is_weak = sym.binding == lief.ELF.Symbol.BINDING.WEAK
            module.symbols.append(
                Symbol(symbol_name, 0 if undefined else base + sym.value, size=int(sym.size), sym_type=SymbolType[self._enum_name(sym.type)], binding=SymbolBinding[self._enum_name(sym.binding)], undefined=undefined)
            )
            if sym.exported:
                addr = base + sym.value
                module.exports[symbol_name] = addr
                if expose and (symbol_name not in self._exports or (self._weak[symbol_name] and not is_weak)):
                    self._exports[symbol_name] = addr
                    self._weak[symbol_name] = is_weak

    def _resolve(self, name: str) -> int | None:
        if self.resolve_override is not None:
            addr = self.resolve_override(name)
            if addr is not None:
                return addr
        addr = self._exports.get(name)
        if addr is not None:
            return addr
        if name in self._data_symbols:
            return self._data_symbols[name]
        if self.resolve_fallback is not None:
            return self.resolve_fallback(name)
        return None

    def _tlsdesc_resolver(self) -> int:
        if self._tlsdesc_stub is None:
            code = struct.pack("<II", 0xE3A00000, 0xE12FFF1E) if self._arch.pointer_size == 4 else struct.pack("<II", 0xD2800000, 0xD65F03C0)  # arm: mov r0,#0;bx lr / arm64: mov x0,#0;ret
            page = self._mem.mmap(len(code), perms=RX, label="tlsdesc-resolver")
            self._mem.write(page, code)
            self._tlsdesc_stub = page
        return self._tlsdesc_stub

    def _apply_relocations(self, binary: lief.ELF.Binary, base: int, module: NativeModule) -> None:
        dialect = self._RELOC[self._arch.cpu_arch]
        pointer_size = self._arch.pointer_size
        read_word = self._mem.read_u64 if pointer_size == 8 else self._mem.read_u32
        write_word = self._mem.write_u64 if pointer_size == 8 else self._mem.write_u32
        encoding = lief.ELF.Relocation.ENCODING
        for reloc in list(binary.dynamic_relocations) + list(binary.pltgot_relocations):
            where = base + reloc.address
            if reloc.encoding in (encoding.REL, encoding.RELR):
                addend = read_word(where)
            elif reloc.encoding in (encoding.RELA, encoding.ANDROID_SLEB):
                addend = reloc.addend
            else:
                addend = reloc.addend if dialect.uses_rela else read_word(where)
            if reloc.type == dialect.relative:
                value = base + addend
            elif reloc.type in dialect.symbolic:
                symbol_name = self._text(reloc.symbol.name) if reloc.symbol else None
                if symbol_name:
                    module.import_relocations.append((where, symbol_name))
                target = self._resolve(symbol_name) if symbol_name else None
                if target is None:
                    self.unresolved.append((module.name, symbol_name or "?"))
                    if symbol_name:
                        self.deferred_relocs.append(DeferredRelocation(module, where, symbol_name, reloc.type, addend))
                    is_weak = reloc.symbol is not None and reloc.symbol.binding == lief.ELF.Symbol.BINDING.WEAK
                    if is_weak or not symbol_name:
                        self._log.loader("unresolved WEAK %s in %s -> 0", symbol_name, module.name, level=LogLevel.WARN)
                        value = 0
                    else:
                        value = self._mem.poison_pointer(f"{module.name}:{symbol_name}")
                        self._log.loader("unresolved STRONG %s in %s -> poison %#x (faults if used)", symbol_name, module.name, value, level=LogLevel.ERROR)
                else:
                    value = target if reloc.type == dialect.jump_slot else target + addend
            elif reloc.type == dialect.irelative:
                self.pending_irelative.append((where, base + addend))
                continue
            elif reloc.type == dialect.tls_desc:
                write_word(where, self._tlsdesc_resolver())
                write_word(where + pointer_size, 0)
                self._log.loader("TLSDESC @ %#x in %s -> benign resolver (per-module TLS not modelled)", where, module.name, level=LogLevel.WARN)
                continue
            elif reloc.type in dialect.tls_module:
                value = 1
            elif reloc.type in dialect.tls_offset:
                value = ((reloc.symbol.value if reloc.symbol else 0) + addend) & 0xFFFFFFFFFFFFFFFF
            elif reloc.type in self._IGNORED:
                continue
            else:
                raise EmuliteError(f"unhandled relocation {reloc.type!r} @ {where:#x} in {module.name} — emulite refuses to silently skip it (implement this reloc type)")
            write_word(where, value)

    def resolve_pending_symbols(self) -> None:
        if not self.deferred_relocs:
            return
        dialect = self._RELOC[self._arch.cpu_arch]
        write_word = self._mem.write_u64 if self._arch.pointer_size == 8 else self._mem.write_u32
        still_missing: list[DeferredRelocation] = []
        for module, where, symbol_name, reloc_type, addend in self.deferred_relocs:
            target = self._resolve(symbol_name)
            if target is None:
                still_missing.append(DeferredRelocation(module, where, symbol_name, reloc_type, addend))
                continue
            value = target if reloc_type == dialect.jump_slot else target + addend
            write_word(where, value)
            self.unresolved = [u for u in self.unresolved if u != (module.name, symbol_name)]
            self._log.loader("deferred %s in %s resolved -> %#x", symbol_name, module.name, value)
        self.deferred_relocs = still_missing

    def _discover_init(self, binary: lief.ELF.Binary, base: int, module: LinuxModule) -> None:
        init = binary.get(self._TAG.INIT)
        if init is not None:
            module.init = base + init.value
        fini = binary.get(self._TAG.FINI)
        if fini is not None:
            module.fini = base + fini.value
        module.init_array = self._read_ptr_table(binary, base, self._TAG.INIT_ARRAY, self._TAG.INIT_ARRAYSZ)
        module.fini_array = self._read_ptr_table(binary, base, self._TAG.FINI_ARRAY, self._TAG.FINI_ARRAYSZ)
        module.preinit_array = self._read_ptr_table(binary, base, self._TAG.PREINIT_ARRAY, self._TAG.PREINIT_ARRAYSZ)
        if module.init or module.init_array or module.fini or module.fini_array:
            self._log.loader("%s init=%#x init_array=%d fini=%#x fini_array=%d preinit=%d", module.name, module.init, len(module.init_array), module.fini, len(module.fini_array), len(module.preinit_array))

    def _read_ptr_table(self, binary: lief.ELF.Binary, base: int, array_tag: lief.ELF.DynamicEntry.TAG, size_tag: lief.ELF.DynamicEntry.TAG) -> list[int]:
        array, size = binary.get(array_tag), binary.get(size_tag)
        if array is None or size is None:
            return []
        pointer_size = self._arch.pointer_size
        read_word = self._mem.read_u64 if pointer_size == 8 else self._mem.read_u32
        empty = 0xFFFFFFFFFFFFFFFF if pointer_size == 8 else 0xFFFFFFFF
        return [ptr for i in range(size.value // pointer_size) if (ptr := read_word(base + array.value + i * pointer_size)) not in (0, empty)]

    def _is_app_shipped(self, resolved: str) -> bool:
        if not self._rootfs:
            return True
        root = os.path.normcase(os.path.abspath(self._rootfs))
        return not os.path.normcase(os.path.abspath(resolved)).startswith(root + os.sep)

    def _find_file(self, path_or_name: str | os.PathLike[str]) -> str:
        path_or_name = os.fspath(path_or_name)
        if os.path.isfile(path_or_name):
            return path_or_name
        name = os.path.basename(path_or_name)
        candidates = []
        if self._rootfs:
            subs = ("system/lib", "vendor/lib", "lib", ".") if self._arch.cpu_arch is CpuArch.ARM else ("system/lib64", "vendor/lib64", "lib64", "system/lib", ".")
            for sub in subs:
                candidates.append(os.path.join(self._rootfs, sub, name))
        candidates += [os.path.join(d, name) for d in self._search]
        for c in candidates:
            if os.path.isfile(c):
                return c
        raise FileNotFoundError(name)
