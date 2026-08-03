from __future__ import annotations

import struct

from emulite.filesystem.types.ioctl_context import IoctlContext


class BinderDriver:
    """A minimal /dev/binder: answers BINDER_VERSION, and for BINDER_WRITE_READ parses BC_TRANSACTIONs
    and synthesizes BR_REPLY parcels. Enough to satisfy a ServiceManager.getService("package") lookup;
    PackageManager transactions are not modelled and throw (rather than fake an empty-OK reply)."""

    _PROTOCOL_VERSION = 8
    _VERSION_NR = 0x09  # request & 0xFF for the BINDER_VERSION ioctl (its size field varies)
    _BINDER_WRITE_READ = 0xC0306201

    _BC_TRANSACTION = 0x6300  # low 16 bits of the command word (BC_TRANSACTION nr 0)
    _BC_TRANSACTION_SG = 0x6311  # BC_TRANSACTION_SG (scatter-gather)

    _BR_TRANSACTION_COMPLETE = 0x00007206
    _BR_REPLY = 0x80407203
    _BR_NOOP = 0x0000720C

    _BINDER_TYPE_HANDLE = 0x73682A85  # flat_binder_object for a remote service handle
    _BINDER_TYPE_BINDER = 0x73622A85  # a local binder; null here => the service is absent

    _PACKAGE_MANAGER_HANDLE = 1
    _MAX_PARCEL = 4096  # cap on the transaction parcel we copy out of guest memory
    _REPLY_BUDGET = 0x60  # worst-case bytes a BR_TRANSACTION_COMPLETE + BR_REPLY occupies

    def __init__(self, context: IoctlContext) -> None:
        self._context = context
        self._replies: list[tuple[bytes, list[int]]] = []  # queued (reply_parcel, flat_object_offsets) FIFO

    def ioctl(self, request: int, arg: int) -> int:
        if request & 0xFF == self._VERSION_NR and arg:
            self._context.mem.write_u32(arg, self._PROTOCOL_VERSION)
            return 0
        if request == self._BINDER_WRITE_READ and arg:
            return self._write_read(arg)
        self._context.log.vfs("binder: unhandled ioctl %#x", request)  # visible, not silently swallowed
        return 0

    def _write_read(self, arg: int) -> int:
        mem = self._context.mem
        wsize, wbuf = mem.read_u64(arg), mem.read_u64(arg + 16)
        rsize, rbuf = mem.read_u64(arg + 24), mem.read_u64(arg + 40)
        self._consume_write(wbuf, wsize)
        mem.write_u64(arg + 8, wsize)  # write_consumed
        out = self._build_read(rsize)
        n = min(len(out), rsize)
        if n:
            mem.write(rbuf, out[:n])
        mem.write_u64(arg + 32, n)  # read_consumed
        return 0

    def _consume_write(self, wbuf: int, wsize: int) -> None:
        mem = self._context.mem
        p, end = wbuf, wbuf + wsize
        while p + 4 <= end:  # each command: u32 word + payload of (word>>16) bytes
            cmd = mem.read_u32(p)
            body = p + 4
            if (cmd & 0xFFFF) in (self._BC_TRANSACTION, self._BC_TRANSACTION_SG):
                handle, code = mem.read_u32(body), mem.read_u32(body + 16)
                dsize, dbuf = mem.read_u64(body + 32), mem.read_u64(body + 48)
                if dsize > self._MAX_PARCEL:
                    self._context.log.vfs("binder: parcel of %d bytes truncated to %d", dsize, self._MAX_PARCEL)
                parcel = bytes(mem.read(dbuf, min(dsize, self._MAX_PARCEL))) if dbuf and dsize else b""
                self._replies.append(self._service_reply(handle, code, parcel))
            p = body + ((cmd >> 16) & 0x3FFF)

    def _build_read(self, rsize: int) -> bytes:
        out = b""
        while self._replies and rsize - len(out) >= self._REPLY_BUDGET:
            data, offsets = self._replies.pop(0)
            out += struct.pack("<I", self._BR_TRANSACTION_COMPLETE)
            out += struct.pack("<I", self._BR_REPLY) + self._transaction_data(data, offsets)
        if not out and rsize >= 4:
            out = struct.pack("<I", self._BR_NOOP)  # nothing queued: keep the reader looping
        return out

    def _transaction_data(self, data: bytes, offsets: list[int]) -> bytes:
        mem = self._context.mem
        buf = mem.mmap(max(len(data), 16))
        mem.write(buf, data)
        offb = 0
        if offsets:
            offb = mem.mmap(len(offsets) * 8)
            mem.write(offb, b"".join(struct.pack("<Q", o) for o in offsets))
        # binder_transaction_data: target, cookie, code, flags, sender_pid, sender_euid, data_size, offsets_size, buffer, offsets
        return struct.pack("<qQIIIIQQQQ", 0, 0, 0, 0x01, 0, 0, len(data), len(offsets) * 8, buf, offb)

    def _service_reply(self, handle: int, code: int, parcel: bytes) -> tuple[bytes, list[int]]:
        if handle == 0:  # ServiceManager.getService / checkService
            service = parcel.decode("utf-16-le", "ignore").split("IServiceManager", 1)[-1]
            if "package" in service:  # PackageManager -> a real handle
                fbo = struct.pack("<IIQQ", self._BINDER_TYPE_HANDLE, 0x7F, self._PACKAGE_MANAGER_HANDLE, 0)
                return struct.pack("<i", 0) + fbo, [4]
            self._context.log.vfs("binder: ServiceManager -> null for unmodelled service %r", service)
            fbo = struct.pack("<IIQQ", self._BINDER_TYPE_BINDER, 0, 0, 0)  # null strong binder = service absent
            return struct.pack("<i", 0) + fbo, [4]
        return self._pm_reply(code, parcel), []

    def _pm_reply(self, code: int, parcel: bytes) -> bytes:
        raise NotImplementedError(
            f"binder: PackageManager transaction code={code} is not modelled (parcel={parcel[:64].hex()}...). "
            f"Implement its reply Parcel (e.g. getPackageInfo carrying profile.apk_signature) rather than faking one."
        )
