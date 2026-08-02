from __future__ import annotations


class Mutf8:
    @staticmethod
    def encode(text: str) -> bytes:
        out = bytearray()
        for ch in text:
            code = ord(ch)
            if code == 0:
                out += b"\xc0\x80"
            elif code < 0x80:
                out.append(code)
            elif code < 0x800:
                out += bytes((0xC0 | (code >> 6), 0x80 | (code & 0x3F)))
            elif code < 0x10000:
                out += bytes((0xE0 | (code >> 12), 0x80 | ((code >> 6) & 0x3F), 0x80 | (code & 0x3F)))
            else:
                code -= 0x10000
                for surrogate in (0xD800 | (code >> 10), 0xDC00 | (code & 0x3FF)):
                    out += bytes((0xE0 | (surrogate >> 12), 0x80 | ((surrogate >> 6) & 0x3F), 0x80 | (surrogate & 0x3F)))
        return bytes(out)

    @staticmethod
    def decode(data: bytes) -> str:
        out: list[str] = []
        i, n = 0, len(data)
        while i < n:
            b0 = data[i]
            if b0 == 0xC0 and i + 1 < n and data[i + 1] == 0x80:
                out.append("\x00")
                i += 2
            elif b0 < 0x80:
                out.append(chr(b0))
                i += 1
            elif b0 >> 5 == 0b110 and i + 1 < n:
                out.append(chr(((b0 & 0x1F) << 6) | (data[i + 1] & 0x3F)))
                i += 2
            elif b0 >> 4 == 0b1110 and i + 2 < n:
                cp = ((b0 & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F)
                if 0xD800 <= cp <= 0xDBFF and i + 5 < n:
                    lo = ((data[i + 3] & 0x0F) << 12) | ((data[i + 4] & 0x3F) << 6) | (data[i + 5] & 0x3F)
                    if 0xDC00 <= lo <= 0xDFFF:
                        out.append(chr(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)))
                        i += 6
                        continue
                out.append(chr(cp))
                i += 3
            else:
                i += 1
        return "".join(out)
