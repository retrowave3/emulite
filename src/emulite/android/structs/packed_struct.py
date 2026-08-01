from __future__ import annotations


class PackedStruct:
    def pack(self) -> bytes:
        raise NotImplementedError

    def write_to(self, mem: object, address: int) -> None:
        mem.write(address, self.pack())
