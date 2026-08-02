from dataclasses import dataclass, field

from emulite.hooks._got_hook import _GotHook


@dataclass(slots=True)
class _GotHookChain:
    original: int
    hooks: list[_GotHook] = field(default_factory=list)
