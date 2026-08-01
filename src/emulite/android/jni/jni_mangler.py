from __future__ import annotations


class JniMangler:
    @staticmethod
    def component(text: str) -> str:
        out = []
        for char in text:
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
                out.append("_0%04x" % ord(char))
        return "".join(out)

    @staticmethod
    def mangle(class_name: str, method_name: str) -> str:
        return "Java_" + JniMangler.component(class_name) + "_" + JniMangler.component(method_name)

    @staticmethod
    def overloaded(class_name: str, method_name: str, signature: str) -> str:
        args = signature[1 : signature.index(")")] if ")" in signature else ""
        return JniMangler.mangle(class_name, method_name) + "__" + JniMangler.component(args)
