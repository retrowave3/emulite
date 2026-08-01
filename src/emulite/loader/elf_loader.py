from __future__ import annotations

import os
import struct
from typing import Callable

import lief

from emulite.android.flags.pf_flag import PfFlag
from emulite.common.errors import ElfFormatError, EmuliteError
from emulite.common.log import Logger, LogLevel
from emulite.cpu.backend import Backend, CpuArch, MemoryProtectionFlag
from emulite.loader.module.linux_module import LinuxModule
from emulite.loader.module.native_module import NativeModule
from emulite.loader.module.symbol import Symbol
from emulite.loader.module.virtual_module import VirtualModule
from emulite.memory import RW, RX, MemoryLayout, MemoryManager


class ElfLoader:
    _T = lief.ELF.Relocation.TYPE
    _TAG = lief.ELF.DynamicEntry.TAG
    _MACHINE = {"arm64": lief.ELF.ARCH.AARCH64, "arm": lief.ELF.ARCH.ARM}
    _IGNORED = tuple(
        t
        for t in (
            getattr(_T, "AARCH64_NONE", None),
            getattr(_T, "ARM_NONE", None),
            getattr(_T, "NONE", None),
        )
        if t is not None
    )
    _RELOC = {
        "arm64": {
            "relative": _T.AARCH64_RELATIVE,
            "jump_slot": _T.AARCH64_JUMP_SLOT,
            "irelative": _T.AARCH64_IRELATIVE,
            "rela": True,
            "symbolic": (_T.AARCH64_GLOB_DAT, _T.AARCH64_ABS64, _T.AARCH64_JUMP_SLOT),
            "tls_desc": _T.AARCH64_TLSDESC,
            "tls_offset": (_T.AARCH64_TLS_TPREL64, _T.AARCH64_TLS_DTPREL64),
            "tls_module": (_T.AARCH64_TLS_DTPMOD64,),
        },
        "arm": {
            "relative": _T.ARM_RELATIVE,
            "jump_slot": _T.ARM_JUMP_SLOT,
            "irelative": _T.ARM_IRELATIVE,
            "rela": False,
            "symbolic": (_T.ARM_GLOB_DAT, _T.ARM_ABS32, _T.ARM_JUMP_SLOT),
            "tls_desc": getattr(_T, "ARM_TLS_DESC", None),
            "tls_offset": tuple(
                t
                for t in (
                    getattr(_T, "ARM_TLS_TPOFF32", None),
                    getattr(_T, "ARM_TLS_DTPOFF32", None),
                )
                if t is not None
            ),
            "tls_module": tuple(
                t for t in (getattr(_T, "ARM_TLS_DTPMOD32", None),) if t is not None
            ),
        },
    }

    @staticmethod
    def _enum_name(value: object) -> str:
        name = getattr(value, "name", None)
        return name if isinstance(name, str) else str(value).rsplit(".", 1)[-1]

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

    def __init__(
        self,
        backend: Backend,
        mem: MemoryManager,
        log: Logger,
        rootfs: str | None = None,
        search_paths: tuple[str, ...] = (),
    ):
        self._be = backend
        self._mem = mem
        self._arch = mem.arch
        self._log = log
        self.emu = None
        self._rootfs = rootfs
        self._search = list(search_paths)
        self.modules: dict[str, NativeModule] = {}
        self._exports: dict[str, int] = {}
        self._data_symbols: dict[str, int] = {}
        self._weak: dict[str, bool] = {}
        self.unresolved: list[tuple[str, str]] = []
        self.deferred_relocs: list[tuple[NativeModule, int, str, object, int]] = []
        self.pending_init: list[NativeModule] = []
        self.pending_irelative: list[tuple[int, int]] = []
        self._tlsdesc_stub: int | None = None
        self._loading: set[str] = set()
        self.resolve_override: Callable[[str], int | None] | None = None
        self.resolve_fallback: Callable[[str], int | None] | None = None
        self.after_load: Callable[[], None] | None = None

    def load(
        self, path_or_name: str, is_dependency: bool = False, scan_only: bool = False
    ) -> NativeModule:
        name = os.path.basename(path_or_name)
        if name in self.modules:
            return self.modules[name]
        if name in self._loading:
            self._log.loader(
                "circular dependency on %s -> using the in-progress module",
                name,
                level=LogLevel.WARN,
            )
            return self.modules.get(name)
        self._loading.add(name)
        try:
            module = self._load(path_or_name, name, is_dependency, scan_only)
        finally:
            self._loading.discard(name)
        if not self._loading:
            self.resolve_pending_symbols()
            if self.after_load is not None:
                self.after_load()
        return module

    def _load(
        self, path_or_name: str, name: str, is_dependency: bool, scan_only: bool = False
    ) -> NativeModule:
        resolved = self._find_file(path_or_name)
        binary = lief.parse(resolved)
        expected = self._MACHINE.get(self._arch.name)
        if binary is None or expected is None or binary.header.machine_type != expected:
            raise ElfFormatError(f"{name}: not a parseable {self._arch.name} ELF")

        needed = [e.name for e in binary.dynamic_entries if e.tag == self._TAG.NEEDED]
        for dep in needed:
            try:
                self.load(dep, is_dependency=True)
            except (FileNotFoundError, EmuliteError) as e:
                self._log.loader("dependency %s unavailable (%s)", dep, e, level=LogLevel.WARN)

        loads = [s for s in binary.segments if s.type == lief.ELF.Segment.TYPE.LOAD]
        span = MemoryLayout.page_align_up(max(s.virtual_address + s.virtual_size for s in loads))
        seg_align = max(
            (int(s.alignment) for s in loads if s.alignment > 1), default=MemoryLayout.PAGE_SIZE
        )
        base = self._mem.reserve_lib(span, align=seg_align)
        segments = self._map_segments(name, loads, base)

        module = LinuxModule(
            name,
            path_or_name,
            base,
            span,
            dependencies=needed,
            segments=segments,
            mem=self._mem,
            emu=self.emu,
        )
        module.phdr_addr = base + binary.header.program_header_offset
        module.phnum = binary.header.numberof_segments
        dynamic = next(
            (s for s in binary.segments if s.type == lief.ELF.Segment.TYPE.DYNAMIC), None
        )
        if dynamic is not None:
            module.dynamic_addr = base + dynamic.virtual_address
        module.entry_point = base + binary.header.entrypoint
        self.modules[name] = module
        soname = next((e.name for e in binary.dynamic_entries if e.tag == self._TAG.SONAME), None)
        if soname and soname != name:
            self.modules.setdefault(soname, module)

        self._register_exports(binary, base, module, expose=not scan_only)
        self._apply_relocations(binary, base, module)
        self._discover_init(binary, base, module)
        if not scan_only and (not is_dependency or self._is_app_shipped(resolved)):
            self.pending_init.append(module)

        self._log.library_load(name, base, span)
        return module

    def add_data_symbol(self, name: str, address: int) -> None:
        self._data_symbols[name] = address
        self._log.loader("add_data_symbol %s => %#x", name, address)

    def create_virtual_module(
        self, name: str, symbols: "dict[str, int] | None" = None
    ) -> "VirtualModule":
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
        return next((m for m in self.modules.values() if m.base == base), None)

    def module_at(self, addr: int) -> NativeModule | None:
        return next((m for m in self.modules.values() if m.contains(addr)), None)

    def _map_segments(self, name: str, loads: list, base: int) -> list[tuple[int, int, int]]:
        loads = sorted(loads, key=lambda s: s.virtual_address)
        page = MemoryLayout.PAGE_SIZE
        span_lo = MemoryLayout.page_align_down(base + loads[0].virtual_address)
        span_hi = MemoryLayout.page_align_up(
            base + max(s.virtual_address + s.virtual_size for s in loads)
        )
        page_perms = {addr: MemoryProtectionFlag.NONE for addr in range(span_lo, span_hi, page)}
        for seg in loads:
            lo = MemoryLayout.page_align_down(base + seg.virtual_address)
            hi = MemoryLayout.page_align_up(base + seg.virtual_address + seg.virtual_size)
            perms = self._seg_perms(int(seg.flags))
            for addr in range(lo, hi, page):
                page_perms[addr] |= perms
        segments: list[tuple[int, int, int]] = []
        for addr in range(span_lo, span_hi, page):
            perms = page_perms[addr]
            if segments and segments[-1][0] + segments[-1][1] == addr and segments[-1][2] == perms:
                base_, size_, _ = segments[-1]
                segments[-1] = (base_, size_ + page, perms)
            else:
                segments.append((addr, page, perms))
        for start, size, _ in segments:
            self._mem.map(start, size, RW, f"{name} LOAD")
        for seg in loads:
            self._mem.write(base + seg.virtual_address, bytes(seg.content))
        for start, size, perms in segments:
            self._mem.protect(start, size, perms)
        return segments

    def _register_exports(
        self, binary: "lief.Binary", base: int, module: NativeModule, expose: bool = True
    ) -> None:
        for sym in binary.dynamic_symbols:
            if not sym.name:
                continue
            undefined = bool(sym.imported)
            is_weak = sym.binding == lief.ELF.Symbol.BINDING.WEAK
            module.symbols.append(
                Symbol(
                    sym.name,
                    0 if undefined else base + sym.value,
                    size=int(sym.size),
                    sym_type=self._enum_name(sym.type),
                    binding=self._enum_name(sym.binding),
                    undefined=undefined,
                )
            )
            if sym.exported:
                addr = base + sym.value
                module.exports[sym.name] = addr
                if expose and (
                    sym.name not in self._exports or (self._weak[sym.name] and not is_weak)
                ):
                    self._exports[sym.name] = addr
                    self._weak[sym.name] = is_weak

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
            code = (
                struct.pack("<II", 0xE3A00000, 0xE12FFF1E)
                if self._arch.pointer_size == 4
                else struct.pack("<II", 0xD2800000, 0xD65F03C0)
            )  # arm: mov r0,#0;bx lr / arm64: mov x0,#0;ret
            page = self._mem.mmap(len(code), perms=RX, label="tlsdesc-resolver")
            self._mem.write(page, code)
            self._tlsdesc_stub = page
        return self._tlsdesc_stub

    def _apply_relocations(self, binary: "lief.Binary", base: int, module: NativeModule) -> None:
        dialect = self._RELOC[self._arch.name]
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
                addend = reloc.addend if dialect["rela"] else read_word(where)
            if reloc.type == dialect["relative"]:
                value = base + addend
            elif reloc.type in dialect["symbolic"]:
                symbol_name = reloc.symbol.name if reloc.symbol else None
                if symbol_name:
                    module.import_relocations.append((where, symbol_name))
                target = self._resolve(symbol_name) if symbol_name else None
                if target is None:
                    self.unresolved.append((module.name, symbol_name or "?"))
                    if symbol_name:
                        self.deferred_relocs.append(
                            (module, where, symbol_name, reloc.type, addend)
                        )
                    is_weak = (
                        reloc.symbol is not None
                        and reloc.symbol.binding == lief.ELF.Symbol.BINDING.WEAK
                    )
                    if is_weak or not symbol_name:
                        self._log.loader(
                            "unresolved WEAK %s in %s -> 0",
                            symbol_name,
                            module.name,
                            level=LogLevel.WARN,
                        )
                        value = 0
                    else:
                        value = self._mem.poison_pointer(f"{module.name}:{symbol_name}")
                        self._log.loader(
                            "unresolved STRONG %s in %s -> poison %#x (faults if used)",
                            symbol_name,
                            module.name,
                            value,
                            level=LogLevel.ERROR,
                        )
                else:
                    value = target if reloc.type == dialect["jump_slot"] else target + addend
            elif reloc.type == dialect["irelative"]:
                self.pending_irelative.append((where, base + addend))
                continue
            elif reloc.type == dialect["tls_desc"]:
                write_word(where, self._tlsdesc_resolver())
                write_word(where + pointer_size, 0)
                self._log.loader(
                    "TLSDESC @ %#x in %s -> benign resolver (per-module TLS not modelled)",
                    where,
                    module.name,
                    level=LogLevel.WARN,
                )
                continue
            elif reloc.type in dialect["tls_module"]:
                value = 1
            elif reloc.type in dialect["tls_offset"]:
                value = ((reloc.symbol.value if reloc.symbol else 0) + addend) & 0xFFFFFFFFFFFFFFFF
            elif reloc.type in self._IGNORED:
                continue
            else:
                raise EmuliteError(
                    f"unhandled relocation {reloc.type!r} @ {where:#x} in {module.name} — "
                    f"emulite refuses to silently skip it (implement this reloc type)"
                )
            write_word(where, value)

    def resolve_pending_symbols(self) -> None:
        if not self.deferred_relocs:
            return
        dialect = self._RELOC[self._arch.name]
        write_word = self._mem.write_u64 if self._arch.pointer_size == 8 else self._mem.write_u32
        still_missing = []
        for module, where, symbol_name, reloc_type, addend in self.deferred_relocs:
            target = self._resolve(symbol_name)
            if target is None:
                still_missing.append((module, where, symbol_name, reloc_type, addend))
                continue
            value = target if reloc_type == dialect["jump_slot"] else target + addend
            write_word(where, value)
            self.unresolved = [u for u in self.unresolved if u != (module.name, symbol_name)]
            self._log.loader("deferred %s in %s resolved -> %#x", symbol_name, module.name, value)
        self.deferred_relocs = still_missing

    def _discover_init(self, binary: "lief.Binary", base: int, module: LinuxModule) -> None:
        init = binary.get(self._TAG.INIT)
        if init is not None:
            module.init = base + init.value
        fini = binary.get(self._TAG.FINI)
        if fini is not None:
            module.fini = base + fini.value
        module.init_array = self._read_ptr_table(
            binary, base, self._TAG.INIT_ARRAY, self._TAG.INIT_ARRAYSZ
        )
        module.fini_array = self._read_ptr_table(
            binary, base, self._TAG.FINI_ARRAY, self._TAG.FINI_ARRAYSZ
        )
        module.preinit_array = self._read_ptr_table(
            binary, base, self._TAG.PREINIT_ARRAY, self._TAG.PREINIT_ARRAYSZ
        )
        if module.init or module.init_array or module.fini or module.fini_array:
            self._log.loader(
                "%s init=%#x init_array=%d fini=%#x fini_array=%d preinit=%d",
                module.name,
                module.init,
                len(module.init_array),
                module.fini,
                len(module.fini_array),
                len(module.preinit_array),
            )

    def _read_ptr_table(
        self, binary: "lief.Binary", base: int, array_tag: object, size_tag: object
    ) -> list[int]:
        array, size = binary.get(array_tag), binary.get(size_tag)
        if array is None or size is None:
            return []
        pointer_size = self._arch.pointer_size
        read_word = self._mem.read_u64 if pointer_size == 8 else self._mem.read_u32
        empty = 0xFFFFFFFFFFFFFFFF if pointer_size == 8 else 0xFFFFFFFF
        return [
            ptr
            for i in range(size.value // pointer_size)
            if (ptr := read_word(base + array.value + i * pointer_size)) not in (0, empty)
        ]

    def _is_app_shipped(self, resolved: str) -> bool:
        if not self._rootfs:
            return True
        root = os.path.normcase(os.path.abspath(self._rootfs))
        return not os.path.normcase(os.path.abspath(resolved)).startswith(root + os.sep)

    def _find_file(self, path_or_name: str) -> str:
        if os.path.isfile(path_or_name):
            return path_or_name
        name = os.path.basename(path_or_name)
        candidates = []
        if self._rootfs:
            subs = (
                ("system/lib", "vendor/lib", "lib", ".")
                if self._arch.cpu_arch is CpuArch.ARM
                else ("system/lib64", "vendor/lib64", "lib64", "system/lib", ".")
            )
            for sub in subs:
                candidates.append(os.path.join(self._rootfs, sub, name))
        candidates += [os.path.join(d, name) for d in self._search]
        for c in candidates:
            if os.path.isfile(c):
                return c
        raise FileNotFoundError(name)
