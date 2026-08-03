from typing import TypeAlias

from emulite.android.java.lang.java_object import JavaObject

JniValue: TypeAlias = int | float | str | JavaObject | list[object] | None
