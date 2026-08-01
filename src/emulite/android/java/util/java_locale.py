"""
https://docs.oracle.com/javase/8/docs/api/java/util/Locale.html
"""

from __future__ import annotations

from typing import ClassVar

from emulite.android.java.lang.java_object import JavaObject


class JavaLocale(JavaObject):
    JAVA_NAME: ClassVar[str] = "java/util/Locale"

    def __init__(self, language: object = "en", country: object = "", _variant: object = ""):
        super().__init__()
        self._language = language.value if isinstance(language, JavaObject) else str(language)
        self._country = country.value if isinstance(country, JavaObject) else str(country)

    @classmethod
    def jni_construct(cls, args: list) -> "JavaLocale":
        return cls(*args[:3])

    @staticmethod
    def getDefault(*_category: object) -> "JavaLocale":
        return JavaLocale("en", "US")  # pinned device locale

    def getLanguage(self) -> str:
        return self._language

    def getCountry(self) -> str:
        return self._country

    def getDisplayName(self, *_locale: object) -> str:
        return self.toString()

    def toString(self) -> str:
        return f"{self._language}_{self._country}" if self._country else self._language
