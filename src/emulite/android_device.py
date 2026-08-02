from __future__ import annotations

import os
import random
import re

from emulite.android.bionic_property_area import AndroidPropertyArea
from emulite.android.virtual_clock import VirtualClock


class AndroidDevice:
    _UPTIME_RANGE_S = (20 * 60, 14 * 86400)
    _BUILD_PROP_PATH = os.path.join("system", "build.prop")
    _PROPERTY_ALIASES = {
        "ro.product.brand": "ro.product.system.brand",
        "ro.product.device": "ro.product.system.device",
        "ro.product.manufacturer": "ro.product.system.manufacturer",
        "ro.product.model": "ro.product.system.model",
        "ro.product.name": "ro.product.system.name",
        "ro.product.cpu.abilist": "ro.system.product.cpu.abilist",
        "ro.product.cpu.abilist32": "ro.system.product.cpu.abilist32",
        "ro.product.cpu.abilist64": "ro.system.product.cpu.abilist64",
        "ro.build.fingerprint": "ro.system.build.fingerprint",
    }
    _DUMP_LINE = re.compile(r"\[(?P<key>.*?)\]:\s*\[(?P<value>.*)\]\s*$")

    SDK = "ro.build.version.sdk"
    ABI = "ro.product.cpu.abi"
    ABILIST = "ro.product.cpu.abilist"
    ABILIST64 = "ro.product.cpu.abilist64"

    # AT_HWCAP uses different bit layouts for AArch64 and AArch32.
    HWCAP_ARM64 = 0x00100FFF
    HWCAP2_ARM64 = 0
    HWCAP_ARM32 = 0x3FB0D6
    HWCAP2_ARM32 = 0x1F

    def __init__(self, properties: dict[str, str], seed: int | None = None):
        self._properties = dict(properties)
        self._props: AndroidPropertyArea | None = None
        self._rng = random.Random(seed)

        lo, hi = self._UPTIME_RANGE_S
        self.clock = VirtualClock(self._rng.randint(lo, hi) * 1_000_000_000)
        self._reset_runtime_stats()

    def _reset_runtime_stats(self) -> None:
        cpus = self.cpu_count
        r = self._rng
        self._intr_rate = r.randint(400, 4000)
        self._ctxt_rate = r.randint(1000, 12000)
        self._fork_rate = r.uniform(0.3, 4.0)
        self._softirq_rate = r.randint(300, 3000)
        self._idle_frac = r.uniform(0.82, 0.95)
        self._cpu_jitter = [r.uniform(0.9, 1.1) for _ in range(cpus)]
        self._procs_total = r.randint(720, 1050)
        self._procs_running = r.randint(1, 4)
        self._loads = tuple(round(r.uniform(0.0, 1.2) * cpus, 2) for _ in range(3))

    def bind_memory(self, mem: object) -> None:
        self._props = AndroidPropertyArea(mem)

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._properties.get(key, default)

    def get_int(self, key: str, default: int) -> int:
        try:
            return int(self.get(key))
        except (TypeError, ValueError):
            return default

    def set(self, key: str, value: str) -> None:
        self._properties[key] = value
        if self._props is not None:
            self._props.invalidate(key)

    def merge(self, props: dict[str, str]) -> None:
        for key, value in props.items():
            self.set(key, value)
        if "ro.cpu.count" in props:
            self._reset_runtime_stats()

    @property
    def properties(self) -> dict[str, str]:
        return dict(self._properties)

    def get_sdk_int(self) -> int:
        return self.get_int(self.SDK, 33)

    @property
    def cpu_count(self) -> int:
        return max(1, self.get_int("ro.cpu.count", 8))

    def get_supported_abis(self) -> list[str]:
        value = self.get(self.ABILIST, "arm64-v8a") or ""
        return [abi for abi in value.split(",") if abi]

    def get_machine(self) -> str:
        abi = self.get(self.ABI, "arm64-v8a") or "arm64-v8a"
        return "aarch64" if abi.startswith("arm64") else "armv7l"

    def uname(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.get("ro.kernel.ostype", "Linux") or "Linux",
            self.get("ro.kernel.hostname", "localhost") or "localhost",
            self.get("ro.kernel.osrelease", "5.10.0") or "5.10.0",
            self.get("ro.kernel.version", "#1 SMP") or "#1 SMP",
            self.get_machine(),
            self.get("ro.kernel.domainname", "(none)") or "(none)",
        )

    def cpu_stat(self) -> list[tuple[int, int, int, int, int, int]]:
        up = self.clock.uptime_s()
        out = []
        for jitter in self._cpu_jitter:
            total = int(up * 100 * jitter)
            idle = int(total * self._idle_frac)
            iowait = int(total * 0.02)
            busy = max(0, total - idle - iowait)
            system = int(busy * 0.35)
            nice = int(busy * 0.03)
            softirq = int(busy * 0.05)
            user = busy - system - nice - softirq
            out.append((user, nice, system, idle, iowait, softirq))
        return out

    def stat_counters(self) -> dict[str, int]:
        up = self.clock.uptime_s()
        return {
            "intr": int(self._intr_rate * up),
            "ctxt": int(self._ctxt_rate * up),
            "processes": int(self._fork_rate * up) + 100,
            "softirq": int(self._softirq_rate * up),
            "procs_running": self._procs_running,
        }

    @property
    def total_procs(self) -> int:
        return self._procs_total

    @property
    def load_averages(self) -> tuple[float, float, float]:
        return self._loads

    @property
    def sigpending_limit(self) -> int:
        return self.get_int("ro.kernel.sigpending", 12704)

    @property
    def filesystem_bytes(self) -> int:
        return self.get_int("ro.fs.data_bytes", 55834574848)

    @property
    def file_mtime(self) -> int:
        return self.get_int("ro.bootimage.build.date.utc", 1677974400)

    @property
    def selinux_policyvers(self) -> str:
        return self.get("ro.selinux.policyvers", "33") or "33"

    def cpu_topology(self) -> list[tuple[str, str]]:
        part = self.get("ro.cpuinfo.part", "0xd0b") or "0xd0b"
        variant = self.get("ro.cpuinfo.variant", "0x1") or "0x1"
        encoded = self.get("ro.cpuinfo.topology", "") or ""
        topology = [tuple(core.split(":", 1)) for core in encoded.split(",") if ":" in core]
        if not topology:
            topology = [(part, variant)]
        return (topology + [topology[-1]] * self.cpu_count)[: self.cpu_count]

    def cpu_features(self, is_arm32: bool) -> str:
        key = "ro.cpuinfo.features.arm" if is_arm32 else "ro.cpuinfo.features"
        return self.get(key, "") or ""

    def midr_el1(self, cpu: int = 0) -> int:
        topology = self.cpu_topology()
        part, variant = topology[cpu] if cpu < len(topology) else topology[0]
        implementer = int(self.get("ro.cpuinfo.implementer", "0x41") or "0x41", 16)
        return (implementer << 24) | (int(variant, 16) << 20) | (0xF << 16) | (int(part, 16) << 4)

    def dump(self) -> str:
        return "\n".join(f"{key} = {value}" for key, value in sorted(self._properties.items()))

    def getprop(self, name: str) -> str:
        value = self.get(name)
        if value is not None:
            return value
        return self._computed(name) or ""

    def exists(self, name: str) -> bool:
        return self.get(name) is not None or self._computed(name) is not None

    def find(self, name: str) -> int:
        if not self.exists(name):
            return 0
        if self._props is None:
            raise RuntimeError("AndroidDevice.find requires guest memory; bind_memory() was never called")
        return self._props.intern(name, self.getprop(name))

    def name_value(self, info: int) -> tuple[str, str] | None:
        found = self.read_info(info)
        return (found[0], found[1]) if found is not None else None

    def read_info(self, info: int) -> tuple[str, str, int] | None:
        return self._props.read(info) if self._props is not None else None

    def _computed(self, name: str) -> str | None:
        if name.endswith("build.fingerprint"):
            return self._fingerprint()
        if name in ("ro.build.flavor", "ro.build.flavor.release"):
            return f"{self.getprop('ro.product.name')}-{self.getprop('ro.build.type')}"
        if name == "ro.build.display.id":
            return self.getprop("ro.build.id")
        if name == "ro.build.description":
            return (
                f"{self.getprop('ro.product.name')}-{self.getprop('ro.build.type')} "
                f"{self.getprop('ro.build.version.release')} {self.getprop('ro.build.id')} "
                f"{self.getprop('ro.build.version.incremental')} {self.getprop('ro.build.tags')}"
            )
        if name == "ro.product.first_api_level":
            return self.getprop("ro.build.version.sdk")
        if name == "ro.boot.serialno":
            return self.getprop("ro.serialno")
        if name == "ro.boot.hardware":
            return self.getprop("ro.hardware")
        if name == "ro.zygote":
            return "zygote64_32" if "arm64" in self.getprop(self.ABI) else "zygote32"
        return None

    def _fingerprint(self) -> str:
        keys = ("ro.product.brand", "ro.product.name", "ro.product.device", "ro.build.version.release", "ro.build.id", "ro.build.version.incremental", "ro.build.type", "ro.build.tags")
        brand, name, device, release, build_id, incremental, build_type, tags = (self.getprop(key) for key in keys)
        if not (brand and device and build_id):
            return ""
        return f"{brand}/{name}/{device}:{release}/{build_id}/{incremental}:{build_type}/{tags}"

    @staticmethod
    def _read_prop_file(path: str) -> dict[str, str]:
        props: dict[str, str] = {}
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                dump = AndroidDevice._DUMP_LINE.match(line)
                if dump:
                    props.setdefault(dump["key"], dump["value"])
                elif "=" in line:
                    key, _, value = line.partition("=")
                    props.setdefault(key.strip(), value.strip())
        return props

    @classmethod
    def from_build_prop(cls, path: str, seed: int | None = None) -> AndroidDevice:
        return cls(cls._normalize_properties(cls._read_prop_file(path)), seed=seed)

    @classmethod
    def from_rootfs(cls, rootfs: str, seed: int | None = None) -> AndroidDevice:
        return cls(cls.load_build_prop(rootfs), seed=seed)

    @staticmethod
    def load_build_prop(rootfs: str) -> dict[str, str]:
        if not os.path.isdir(rootfs):
            raise FileNotFoundError(f"Android rootfs directory not found: {rootfs}")
        path = os.path.join(rootfs, AndroidDevice._BUILD_PROP_PATH)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"required Android property file not found: {path}")
        props = AndroidDevice._read_prop_file(path)
        if not props:
            raise ValueError(f"Android property file is empty: {path}")
        return AndroidDevice._normalize_properties(props)

    @staticmethod
    def _normalize_properties(props: dict[str, str]) -> dict[str, str]:
        for name, scoped_name in AndroidDevice._PROPERTY_ALIASES.items():
            if name not in props and scoped_name in props:
                props[name] = props[scoped_name]
        return props
