from __future__ import annotations


class JniMangler:
    @staticmethod
    def component(text: str) -> str:
        out: list[str] = []
        encoded = text.encode("utf-16-be", "surrogatepass")
        for offset in range(0, len(encoded), 2):
            char = chr(int.from_bytes(encoded[offset : offset + 2], "big"))
            if char.isascii() and char.isalnum():
                out.append(char)
            elif char in "/.":
                out.append("_")
            elif char == "_":
                out.append("_1")
            elif char == ";":
                out.append("_2")
            elif char == "[":
                out.append("_3")
            else:
                out.append(f"_0{ord(char):04x}")
        return "".join(out)

    @staticmethod
    def mangle(class_name: str, method_name: str) -> str:
        return "Java_" + JniMangler.component(class_name) + "_" + JniMangler.component(method_name)

    @staticmethod
    def overloaded(class_name: str, method_name: str, signature: str) -> str:
        if not signature.startswith("(") or ")" not in signature:
            raise ValueError(f"invalid JNI method signature: {signature!r}")
        args = signature[1 : signature.index(")")]
        return JniMangler.mangle(class_name, method_name) + "__" + JniMangler.component(args)
