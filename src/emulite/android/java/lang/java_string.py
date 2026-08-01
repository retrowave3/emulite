"""
https://docs.oracle.com/javase/8/docs/api/java/lang/String.html
"""

from __future__ import annotations

import re
from typing import ClassVar

from emulite.android.java.jvalue import JChar
from emulite.android.java.lang.java_class import JavaClass
from emulite.android.java.lang.java_object import JavaObject


class JavaString(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/lang/String"
    _FORMAT_SPEC: ClassVar = re.compile(r"%(\d+\$)?([-#+ 0,(]*)(\d+)?(\.\d+)?([a-zA-Z%])")

    def __init__(self, value: str = ""):
        super().__init__(value=value)

    @staticmethod
    def valueOf(value: object) -> "JavaString":
        if value is None:
            return JavaString("null")
        if isinstance(value, bool):
            return JavaString("true" if value else "false")
        if isinstance(value, JChar):
            return JavaString(chr(int(value)))
        return JavaString(value.toString() if isinstance(value, JavaObject) else str(value))

    @staticmethod
    def format(fmt: object, *rest: object) -> "JavaString":
        template = fmt.value if isinstance(fmt, JavaObject) else str(fmt)
        if len(rest) == 1 and isinstance(rest[0], JavaObject) and isinstance(rest[0].value, list):
            args = list(rest[0].value)
        else:
            args = list(rest)
        return JavaString(JavaString._apply_format(template, args))

    @staticmethod
    def _apply_format(template: str, args: list) -> str:
        counter = [0]

        def render(match: object) -> str:
            conversion = match.group(5)
            if conversion == "%":
                return "%"
            if conversion == "n":
                return "\n"
            index = int(match.group(1)[:-1]) - 1 if match.group(1) else counter[0]
            if not match.group(1):
                counter[0] += 1
            arg = args[index] if 0 <= index < len(args) else None
            flags = (
                (match.group(2) or "").replace(",", "").replace("(", "")
            )  # grouping/parens: dropped
            spec = "%" + flags + (match.group(3) or "") + (match.group(4) or "")
            lower = conversion.lower()
            raw = (
                arg.value
                if isinstance(arg, JavaObject) and not isinstance(arg.value, list)
                else arg
            )
            if lower == "b":
                return (spec + "s") % ("false" if arg is None or raw is False else "true")
            if lower == "s":
                text = (
                    arg.toString()
                    if isinstance(arg, JavaObject)
                    else ("null" if arg is None else str(raw))
                )
                return (spec + "s") % text
            if lower in "dox":
                return (spec + conversion) % int(raw)
            if lower in "feg":
                return (spec + conversion) % float(raw)
            if lower == "c":
                return (spec + "c") % (chr(int(raw)) if isinstance(raw, int) else str(raw))
            return match.group(0)

        return JavaString._FORMAT_SPEC.sub(render, template)

    @classmethod
    def jni_construct(cls, args: list) -> "JavaString":
        if not args:
            return cls("")
        arg = args[0]
        if isinstance(arg, JavaObject):
            payload = arg.value
            if isinstance(payload, (bytes, bytearray)):
                descriptor = arg.java_class.name if arg.java_class else "[B"
                if descriptor == "[C":  # char[] is UTF-16LE
                    return cls(bytes(payload).decode("utf-16-le", errors="replace"))
                charset = (
                    args[1].value if len(args) > 1 and isinstance(args[1], JavaObject) else "utf-8"
                )
                return cls(bytes(payload).decode(cls._py_charset(charset), errors="replace"))
            if isinstance(payload, str):
                return cls(payload)
        return cls(str(arg))

    def _s(self) -> str:
        return self.value or ""

    @staticmethod
    def _text(obj: object) -> str:
        return obj.value if isinstance(obj, JavaObject) else str(obj)

    def length(self) -> int:
        return len(self._s())

    def isEmpty(self) -> bool:
        return not self._s()

    def charAt(self, index: int) -> int:
        return ord(self._s()[int(index)])

    def toString(self) -> str:
        return self._s()

    def equals(self, obj: "JavaObject | None") -> bool:
        return isinstance(obj, JavaString) and obj.value == self.value

    def equalsIgnoreCase(self, obj: "JavaObject | None") -> bool:
        return isinstance(obj, JavaObject) and self._s().lower() == self._text(obj).lower()

    def hashCode(self) -> int:
        h = 0
        for ch in self._s():
            h = (31 * h + ord(ch)) & 0xFFFFFFFF
        return h - 0x100000000 if h >= 0x80000000 else h

    def compareTo(self, other: object) -> int:
        a, b = self._s(), self._text(other)
        for ca, cb in zip(a, b):
            if ca != cb:
                return ord(ca) - ord(cb)
        return len(a) - len(b)

    def compareToIgnoreCase(self, other: object) -> int:
        a, b = self._s().lower(), self._text(other).lower()
        for ca, cb in zip(a, b):
            if ca != cb:
                return ord(ca) - ord(cb)
        return len(a) - len(b)

    def indexOf(self, target: object, from_index: int = 0) -> int:
        needle = chr(int(target)) if isinstance(target, int) else self._text(target)
        return self._s().find(needle, int(from_index))

    def lastIndexOf(self, target: object, from_index: "int | None" = None) -> int:
        needle = chr(int(target)) if isinstance(target, int) else self._text(target)
        s = self._s()
        return (
            s.rfind(needle)
            if from_index is None
            else s.rfind(needle, 0, int(from_index) + len(needle))
        )

    def startsWith(self, prefix: object, offset: int = 0) -> bool:
        return self._s().startswith(self._text(prefix), int(offset))

    def endsWith(self, suffix: object) -> bool:
        return self._s().endswith(self._text(suffix))

    def contains(self, part: object) -> bool:
        return self._text(part) in self._s()

    def matches(self, regex: object) -> bool:
        return (
            re.fullmatch(self._text(regex), self._s()) is not None
        )  # Java-ish regex (Python engine)

    def substring(self, begin: int, end: "int | None" = None) -> "JavaString":
        s = self._s()
        return JavaString(s[int(begin) :] if end is None else s[int(begin) : int(end)])

    def concat(self, other: object) -> "JavaString":
        return JavaString(self._s() + self._text(other))

    def replace(self, old: object, new: object) -> "JavaString":
        if isinstance(old, int):
            return JavaString(self._s().replace(chr(int(old)), chr(int(new))))
        return JavaString(self._s().replace(self._text(old), self._text(new)))

    def replaceAll(self, regex: object, replacement: object) -> "JavaString":
        return JavaString(re.sub(self._text(regex), self._text(replacement), self._s()))

    def trim(self) -> "JavaString":
        s = self._s()  # Java trims EVERY leading/trailing char <= U+0020
        i, j = 0, len(s)
        while i < j and ord(s[i]) <= 0x20:
            i += 1
        while j > i and ord(s[j - 1]) <= 0x20:
            j -= 1
        return JavaString(s[i:j])

    def toLowerCase(self, *_locale: object) -> "JavaString":
        return JavaString(self._s().lower())

    def toUpperCase(self, *_locale: object) -> "JavaString":
        return JavaString(self._s().upper())

    def getBytes(self, *charset: object) -> "JavaObject":
        name = self._text(charset[0]) if charset else "utf-8"
        if name.lower().replace("-", "") == "utf16":  # Java's UTF-16 is big-endian with a FE FF BOM
            return self._byte_array(
                b"\xfe\xff" + self._s().encode("utf-16-be")
            )  # (Python utf-16 is host-endian)
        return self._byte_array(self._s().encode(self._py_charset(name)))

    def toCharArray(self) -> "JavaObject":
        return JavaObject(
            JavaClass("[C"), bytearray(self._s().encode("utf-16-le"))
        )  # 2 bytes / jchar

    def split(self, regex: object, limit: int = 0) -> "JavaObject":
        parts = re.split(
            self._text(regex), self._s(), maxsplit=(int(limit) - 1 if int(limit) > 0 else 0)
        )
        if int(limit) == 0:
            while len(parts) > 1 and parts[-1] == "":  # Java drops trailing empty strings
                parts.pop()
        return JavaObject(JavaClass("[Ljava/lang/String;"), [JavaString(p) for p in parts])

    @staticmethod
    def _byte_array(data: bytes) -> "JavaObject":
        return JavaObject(JavaClass("[B"), bytearray(data))

    @staticmethod
    def _py_charset(name: str) -> str:
        # Map common Java charset names onto Python codec names.
        return name.lower().replace("utf8", "utf-8").replace("us-ascii", "ascii")
