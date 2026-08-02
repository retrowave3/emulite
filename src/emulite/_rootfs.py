from __future__ import annotations

import os
from pathlib import Path


def bundled_android_rootfs() -> Path:
    package_rootfs = Path(__file__).resolve().parent / "rootfs" / "android"
    source_rootfs = Path(__file__).resolve().parents[2] / "rootfs" / "android"

    for path in (package_rootfs, source_rootfs):
        if (path / "system" / "build.prop").is_file():
            return path

    raise FileNotFoundError("bundled Android rootfs is missing")


def resolve_android_rootfs(rootfs: str | os.PathLike[str] | None) -> str:
    return os.fspath(bundled_android_rootfs() if rootfs is None else rootfs)
