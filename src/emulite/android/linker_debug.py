from __future__ import annotations

import struct
from collections.abc import Callable
from functools import partial
from typing import TYPE_CHECKING

from emulite.android.linker_image import LinkerImage
from emulite.android.structs.link_map32 import LinkMap32
from emulite.android.structs.link_map64 import LinkMap64
from emulite.android.structs.r_debug32 import RDebug32
from emulite.android.structs.r_debug64 import RDebug64
from emulite.common.errors import EmulatorCrashed
from emulite.common.log import LogLevel
from emulite.cpu.backend import MemoryProtectionFlag
from emulite.loader.module.native_module import NativeModule

if TYPE_CHECKING:
    from emulite.android_emulator import AndroidEmulatorBase

_DT_NULL, _DT_HASH, _DT_STRTAB, _DT_SYMTAB, _DT_STRSZ, _DT_SYMENT, _DT_SONAME, _DT_DEBUG = (0, 4, 5, 6, 10, 11, 14, 21)
_PT_LOAD, _PT_DYNAMIC, _PT_PHDR, _ET_EXEC, _ET_DYN = 1, 2, 6, 2, 3
_PF_R, _PF_RW = 4, 6
_EM = {8: 183, 4: 40}  # EM_AARCH64 / EM_ARM
_ST_FUNC_GLOBAL = (1 << 4) | 2  # st_info: STB_GLOBAL | STT_FUNC

_R = MemoryProtectionFlag.READ
_RW = MemoryProtectionFlag.READ | MemoryProtectionFlag.WRITE
_RX = MemoryProtectionFlag.READ | MemoryProtectionFlag.EXEC

_LINKER_SYMBOLS = ("rtld_db_dlactivity", "__dl__ZL22rtld_db_dlactivityv")
_SYNTHETIC_LIBS = {
    "liblog.so": ("__android_log_write", "__android_log_print"),
    "libandroid.so": ("AAssetManager_open", "AAssetManager_openDir", "AAssetManager_fromJava", "AAssetDir_getNextFileName", "AAssetDir_close", "AAsset_close", "AAsset_getBuffer", "AAsset_getLength"),
}


class LinkerDebug:
    """Guest-visible ELF and link_map state used by bionic debugger interfaces."""

    _CAPACITY = 512  # link_map nodes preallocated (modules + main-exe + linker)

    def __init__(self, emu: AndroidEmulatorBase):
        self._emu = emu
        self._mem = emu.mem
        self._arch = emu.arch
        self._log = emu.log
        self._ptr = emu.arch.pointer_size
        self._RDebug = RDebug64 if self._ptr == 8 else RDebug32
        self._LinkMap = LinkMap64 if self._ptr == 8 else LinkMap32
        self._name_ptrs: dict[str, int] = {}  # module name -> l_name cstr (allocated once, reused)
        self._mask = (1 << (self._ptr * 8)) - 1  # pointer-width mask for a bias-relative st_value
        self.dep_images: list[LinkerImage] = []  # synthetic liblog.so/libandroid.so (built lazily post-libc)
        self._dep_built = False
        self.r_debug_addr = 0
        self.phdr_addr = self.phnum = self.phent = self.entry = 0
        self._pool = 0
        self._main_ld = 0  # main-exe _DYNAMIC (l_ld for the head node)
        self._linker_ld = 0  # linker _DYNAMIC (l_ld for the linker node)
        self._linker_base = 0  # linker load base (l_addr for its node, r_debug.r_ldbase)
        self._linker_phdr = self._linker_phnum = 0  # linker program headers (its dl_iterate_phdr entry)
        self._rtld_activity = 0
        self._main_name = 0
        self._linker_name = 0
        self.main_image: LinkerImage | None = None
        self.linker_image: LinkerImage | None = None

    def install(self) -> None:
        exe, linker = ("app_process64", "/system/bin/linker64") if self._ptr == 8 else ("app_process32", "/system/bin/linker")
        self._main_name = self._mem.alloc_cstr(f"/system/bin/{exe}")
        self._linker_name = self._mem.alloc_cstr(linker)
        self.r_debug_addr = self._mem.mmap(self._RDebug.SIZE, _RW, "r_debug")
        self._main_ld = self._install_main_exe()
        self._linker_ld = self._install_linker()
        self._RDebug(version=1, brk=self._rtld_activity, ldbase=self._linker_base).write_to(self._mem, self.r_debug_addr)
        self.main_image = LinkerImage(0, self.phdr_addr, self.phnum, f"/system/bin/{exe}", ld=self._main_ld, name_ptr=self._main_name)
        self.linker_image = LinkerImage(self._linker_base, self._linker_phdr, self._linker_phnum, linker, ld=self._linker_ld, name_ptr=self._linker_name)
        self._pool = self._mem.mmap(self._CAPACITY * self._LinkMap.SIZE, _RW, "link_map")

    def _install_main_exe(self) -> int:
        # A minimal ET_EXEC image (load bias 0, so every p_vaddr is already the absolute address): three
        # program headers (PT_PHDR, PT_LOAD, PT_DYNAMIC) and a _DYNAMIC carrying DT_DEBUG -> r_debug.
        phent, ehdr = self._phdr_size(), self._ehdr_size()
        phoff, phnum = ehdr, 3
        dyn_off = phoff + phnum * phent
        dyn = self._dyn_bytes([(_DT_DEBUG, self.r_debug_addr), (_DT_NULL, 0)])
        size = dyn_off + len(dyn)
        base = self._mem.mmap(size, _RW, "main-exe")
        phdrs = self._phdr(_PT_PHDR, _PF_R, phoff, base + phoff, phnum * phent) + self._phdr(_PT_LOAD, _PF_R, 0, base, size) + self._phdr(_PT_DYNAMIC, _PF_RW, dyn_off, base + dyn_off, len(dyn))
        self._mem.write(base, self._ehdr(_ET_EXEC, base, phoff, phent, phnum) + phdrs + dyn)
        self._mem.protect(base, size, _R)
        self.phdr_addr, self.phnum, self.phent, self.entry = base + phoff, phnum, phent, base
        self._log.loader("main-exe debug image @ %#x (phdr @ %#x, DT_DEBUG -> r_debug @ %#x)", base, self.phdr_addr, self.r_debug_addr)
        return base + dyn_off

    def _install_linker(self) -> int:
        label = "linker64" if self._ptr == 8 else "linker"
        ret = struct.pack("<I", self._arch.ret_instruction)
        base, ld, phdr, phnum, blob = self._emit_module(label, label, _LINKER_SYMBOLS, lambda name, base, code_off: code_off, code=ret, perms=_RX)
        self._linker_base, self._linker_phdr, self._linker_phnum, self._rtld_activity = (base, phdr, phnum, blob)
        self._log.loader("%s debug image @ %#x (rtld_db_dlactivity @ %#x)", label, base, blob)
        return ld

    def _emit_module(self, label: str, soname: str, symbols: tuple[str, ...], st_value: Callable[[str, int, int], int], code: bytes = b"", perms: MemoryProtectionFlag = _R) -> tuple[int, int, int, int, int]:
        strtab = bytearray(b"\x00")
        name_offs = []
        for name in symbols:
            name_offs.append(len(strtab))
            strtab += name.encode() + b"\x00"
        soname_off = len(strtab)
        strtab += soname.encode() + b"\x00"

        ehdr, phent, phnum = self._ehdr_size(), self._phdr_size(), 3
        phoff = ehdr
        sym_size = self._sym_size()
        code_off = (phoff + phnum * phent + 7) & ~7
        sym_off = (code_off + len(code) + 7) & ~7
        strtab_off = sym_off + (len(symbols) + 1) * sym_size
        hash_off = strtab_off + len(strtab)
        hash_words = self._sysv_hash(len(symbols))
        dyn_off = (hash_off + len(hash_words) * 4 + 7) & ~7
        dyn = self._dyn_bytes([(_DT_HASH, hash_off), (_DT_STRTAB, strtab_off), (_DT_SYMTAB, sym_off), (_DT_STRSZ, len(strtab)), (_DT_SYMENT, sym_size), (_DT_SONAME, soname_off), (_DT_NULL, 0)])
        size = dyn_off + len(dyn)

        base = self._mem.mmap(size, _RW, label)
        phdrs = self._phdr(_PT_PHDR, _PF_R, phoff, phoff, phnum * phent) + self._phdr(_PT_LOAD, _PF_R, 0, 0, size) + self._phdr(_PT_DYNAMIC, _PF_RW, dyn_off, dyn_off, len(dyn))
        image = bytearray(size)
        image[0:phoff] = self._ehdr(_ET_DYN, 0, phoff, phent, phnum)
        image[phoff : phoff + len(phdrs)] = phdrs
        image[code_off : code_off + len(code)] = code
        syms = self._sym(0, 0, 0, 0, 0)
        for name, off in zip(symbols, name_offs):
            syms += self._sym(off, st_value(name, base, code_off), len(code), _ST_FUNC_GLOBAL, 1)
        image[sym_off : sym_off + len(syms)] = syms
        image[strtab_off : strtab_off + len(strtab)] = strtab
        image[hash_off : hash_off + len(hash_words) * 4] = struct.pack(f"<{len(hash_words)}I", *hash_words)
        image[dyn_off:] = dyn
        self._mem.write(base, bytes(image))
        self._mem.protect(base, size, perms)
        return base, base + dyn_off, base + phoff, phnum, base + code_off

    def _ensure_dep_libs(self) -> None:
        if self._dep_built:
            return
        self._dep_built = True
        for soname, symbols in _SYNTHETIC_LIBS.items():
            addrs = {name: self._symbol_address(name) for name in symbols}
            device_path = f"/system/lib{'64' if self._ptr == 8 else ''}/{soname}"
            base, ld, phdr, phnum, _ = self._emit_module("syslib", soname, tuple(addrs), partial(self._relative_symbol_address, addrs))
            self.dep_images.append(LinkerImage(base, phdr, phnum, device_path, ld=ld, name_ptr=self._mem.alloc_cstr(device_path)))
            self._log.loader("%s debug image @ %#x (%d symbols)", soname, base, len(addrs))

    def _relative_symbol_address(self, addresses: dict[str, int], name: str, base: int, _code_offset: int) -> int:
        return (addresses[name] - base) & self._mask

    def _symbol_address(self, name: str) -> int:
        addr = self._emu.libc.resolve_override(name)
        if addr is not None:
            return addr
        return self._emu.trap.alloc_slot(lambda: self._unimplemented(name), f"unimpl:{name}")

    def _unimplemented(self, name: str) -> None:
        raise EmulatorCrashed(f"{name}: not implemented in emulite — the NDK AssetManager (libandroid.so) is not modelled. A target that reads assets needs a driver to provide them.")

    def rebuild(self) -> None:
        if self.main_image is None or self.linker_image is None or not self._pool:
            raise RuntimeError("LinkerDebug.install() must be called before rebuild()")
        self._ensure_dep_libs()
        module_nodes = []
        seen: set[int] = set()
        for module in self._emu.loader.loaded_modules:
            if module.base == 0 or id(module) in seen:
                continue
            seen.add(id(module))
            module_nodes.append((module.base, self._module_name(module), module.dynamic_addr))
        cap = self._CAPACITY - 2 - len(self.dep_images)
        if len(module_nodes) > cap:
            self._log.loader("link_map: %d modules exceeds capacity %d — truncating (raise _CAPACITY)", len(module_nodes), cap, level=LogLevel.WARN)
            module_nodes = module_nodes[:cap]
        node_of = lambda image: (image.base, image.name_ptr, image.ld)
        nodes = [node_of(self.main_image), *module_nodes, *map(node_of, self.dep_images), node_of(self.linker_image)]
        size, count = self._LinkMap.SIZE, len(nodes)
        for i, (l_addr, l_name, l_ld) in enumerate(nodes):
            addr = self._pool + i * size
            prev = self._pool + (i - 1) * size if i > 0 else 0
            nxt = self._pool + (i + 1) * size if i < count - 1 else 0
            self._LinkMap(addr=l_addr, name=l_name, ld=l_ld, next=nxt, prev=prev).write_to(self._mem, addr)
        self._RDebug(version=1, map=self._pool, state=0, brk=self._rtld_activity, ldbase=self._linker_base).write_to(self._mem, self.r_debug_addr)

    def _module_name(self, module: NativeModule) -> int:
        if module.name not in self._name_ptrs:
            self._name_ptrs[module.name] = self._mem.alloc_cstr(self._emu.vfs.device_path(module))
        return self._name_ptrs[module.name]

    def _ehdr_size(self) -> int:
        return 64 if self._ptr == 8 else 52

    def _phdr_size(self) -> int:
        return 56 if self._ptr == 8 else 32

    def _sym_size(self) -> int:
        return 24 if self._ptr == 8 else 16

    def _ehdr(self, e_type: int, entry: int, phoff: int, phent: int, phnum: int) -> bytes:
        ident = b"\x7fELF" + bytes([2 if self._ptr == 8 else 1, 1, 1, 0]) + b"\x00" * 8
        tail = (e_type, _EM[self._ptr], 1, entry, phoff, 0, 0, self._ehdr_size(), phent, phnum, 0, 0, 0)
        fmt = "<HHIQQQIHHHHHH" if self._ptr == 8 else "<HHIIIIIHHHHHH"
        return ident + struct.pack(fmt, *tail)

    def _phdr(self, p_type: int, flags: int, offset: int, vaddr: int, size: int) -> bytes:
        if self._ptr == 8:
            return struct.pack("<IIQQQQQQ", p_type, flags, offset, vaddr, vaddr, size, size, 0x1000)
        return struct.pack("<IIIIIIII", p_type, offset, vaddr, vaddr, size, size, flags, 0x1000)

    def _dyn_bytes(self, entries: list[tuple[int, int]]) -> bytes:
        fmt = "<qQ" if self._ptr == 8 else "<iI"
        return b"".join(struct.pack(fmt, tag, val) for tag, val in entries)

    def _sym(self, name: int, value: int, size: int, info: int, shndx: int) -> bytes:
        if self._ptr == 8:
            return struct.pack("<IBBHQQ", name, info, 0, shndx, value, size)
        return struct.pack("<IIIBBH", name, value, size, info, 0, shndx)

    @staticmethod
    def _sysv_hash(defined: int) -> list[int]:
        chain = [0] + [k + 1 for k in range(1, defined)] + [0]
        return [1, defined + 1, 1, *chain]
