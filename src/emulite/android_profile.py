from __future__ import annotations

import os
import random
from dataclasses import dataclass, field


@dataclass
class AndroidProfile:
    package_name: str = "com.example.app"

    process_uid: int = 10198
    process_gid: int = 10198
    process_pid: int = 28839
    process_tid: int = 28839
    parent_process_pid: int = 743

    data_dir: str | None = None
    apk_path: str | None = None
    native_lib_dir: str | None = None
    external_files_dir: str | None = None
    external_storage_dir: str = "/sdcard"

    program_name: str | None = None
    application_flags: int = 0
    seed: int | None = None

    supplementary_groups: tuple[int, ...] = (3003, 9997, 20198, 50198)
    oom_score_adj: int = 200
    selinux_context: str = "u:r:untrusted_app:s0:c159,c256,c512,c768"
    stack_guard: int = field(default_factory=lambda: int.from_bytes(os.urandom(8), "little") & ~0xFF)
    environment_variables: dict[str, str] = field(default_factory=lambda: {"ANDROID_DATA": "/data", "ANDROID_ROOT": "/system", "PATH": "/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin"})

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)
        self.process_age_s: int = self._rng.randint(3, 3600)
        self.voluntary_ctxt_switches: int = self._rng.randint(200, 6000)
        self.nonvoluntary_ctxt_switches: int = self._rng.randint(40, 900)
        self.utime_ticks: int = self._rng.randint(2, max(3, self.process_age_s * 25))
        self.stime_ticks: int = self._rng.randint(1, max(2, self.process_age_s * 10))
        package = self.package_name
        if self.data_dir is None:
            self.data_dir = f"/data/user/0/{package}"
        if self.apk_path is None:
            self.apk_path = f"/data/app/{package}/base.apk"
        if self.native_lib_dir is None:
            self.native_lib_dir = f"/data/app/{package}/lib/arm64"
        if self.external_files_dir is None:
            self.external_files_dir = f"/sdcard/Android/data/{package}/files"
        if self.program_name is None:
            self.program_name = package

    @property
    def thread_name(self) -> str:
        return (self.program_name or self.package_name)[:15]
