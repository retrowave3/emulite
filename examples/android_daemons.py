from __future__ import annotations

import struct


def logdw_handler(emu):
    def handle(data: bytes) -> bytes:
        try:
            log_id = data[0]
            priority = data[11]
            tag, msg = data[12:].split(b"\x00", 1)
            msg = msg.split(b"\x00", 1)[0]
            emu.log.vfs(
                "logd[%d] pri=%d %s: %s",
                log_id,
                priority,
                tag.decode("utf-8", "replace"),
                msg.decode("utf-8", "replace"),
            )
        except (IndexError, ValueError):
            emu.log.vfs("logd raw: %r", data)
        return b""

    return handle


def dnsproxyd_handler(_emu, answers: "dict[str, str] | None" = None):
    table = dict(answers or {})

    def handle(data: bytes) -> bytes:
        parts = data.split(b"\x00")
        host = next((p.decode("latin-1") for p in parts[1:] if p), "")
        ip = table.get(host, "127.0.0.1")
        return struct.pack(">I", 0) + ip.encode() + b"\x00"  # rv=0 (success) then the A record

    return handle


def install(emu, *, dns=None) -> None:
    emu.register_socket("/dev/socket/logdw", logdw_handler(emu))
    emu.register_socket("/dev/socket/dnsproxyd", dnsproxyd_handler(emu, dns))
