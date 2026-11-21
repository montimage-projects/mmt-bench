"""System-under-test fingerprint collector (``mbench sut``, sut.json).

Plan §B4: every campaign and every run carries a full record of the host it ran
on. :func:`collect` builds that record from a :class:`~mbench.hostsrc.Source`,
read-only and without sudo. A field it cannot read is never dropped: it holds an
*unavailable marker* instead, ``{"unavailable": <kind>, "reason": <text>}``,
where ``kind`` is one of :data:`UNAVAILABLE_KINDS`.

Each data source has its own ``parse_*`` function, a pure function of the text
the source produced, so it is unit-tested against a fixture captured on
dgx-spark (``tests/fixtures/dgx-spark/``).

:func:`sut_hash` covers the hardware and OS parts only (:data:`HASHED_SECTIONS`),
so two runs are compared only when those match. See ``docs/sut-fingerprint.md``.
"""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import platform
import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeGuard

from mbench import __version__
from mbench.hostsrc import DMIDECODE_MEMORY_KEYS, CommandResult, LiveSource, Source

SCHEMA_VERSION = 1

#: Kinds of unavailable marker. ``needs_root``: readable by root only.
#: ``not_supported``: this host, kernel or driver does not expose it.
#: ``not_applicable``: the field has no meaning here (a host-scope record has no
#: tool under test). ``missing_tool``: the inspection command is not installed.
#: ``redacted``: readable, deliberately not recorded (a secret). ``error``: the
#: read failed for another reason, given in ``reason``.
UNAVAILABLE_KINDS = (
    "needs_root",
    "not_supported",
    "not_applicable",
    "missing_tool",
    "redacted",
    "error",
)

#: Sections covered by :func:`sut_hash`: the hardware and the OS.
HASHED_SECTIONS = ("host", "os", "nics")

#: Units recorded by default, to say whether vLLM was stopped for the run.
VLLM_UNITS = ("vllm-qwen.service", "vllm-health-watchdog.timer")

DEFAULT_SAMPLE_SECONDS = 1.0
DEFAULT_TOP_N = 10

Json = Any
Marker = dict[str, str]


def unavailable(kind: str, reason: str) -> Marker:
    """An explicit "could not record this field" value."""
    if kind not in UNAVAILABLE_KINDS:
        raise ValueError(f"unknown unavailable kind: {kind}")
    return {"unavailable": kind, "reason": reason}


def is_unavailable(value: Json) -> TypeGuard[Marker]:
    return isinstance(value, dict) and set(value) == {"unavailable", "reason"}


# --- Parsers: text from one source -> data -----------------------------------


def parse_cpulist(text: str) -> list[int]:
    """``"0-4,10-14"`` -> ``[0, 1, 2, 3, 4, 10, ...]``. Empty text -> ``[]``."""
    cpus: list[int] = []
    for part in text.strip().split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            cpus.extend(range(int(lo), int(hi) + 1))
        else:
            cpus.append(int(part))
    return sorted(set(cpus))


def format_cpulist(cpus: Iterable[int]) -> str:
    """``[0, 1, 2, 5]`` -> ``"0-2,5"``."""
    ordered = sorted(set(cpus))
    runs: list[str] = []
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        runs.append(str(ordered[i]) if i == j else f"{ordered[i]}-{ordered[j]}")
        i = j + 1
    return ",".join(runs)


def parse_lscpu_models(text: str) -> dict[int, str]:
    """``lscpu -p=CPU,MODELNAME`` -> ``{cpu: model name}``."""
    models: dict[int, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        cpu, _, name = line.partition(",")
        models[int(cpu)] = name.strip()
    return models


def parse_lscpu_caches(text: str) -> list[dict[str, Json]]:
    """``lscpu -J -C`` -> lscpu's own cache summary, one entry per cache name."""
    caches = json.loads(text)["caches"]
    return [
        {
            "name": c["name"],
            "one_size": c.get("one-size"),
            "all_size": c.get("all-size"),
            "ways": c.get("ways"),
            "level": c.get("level"),
            "type": c.get("type"),
        }
        for c in caches
    ]


def parse_cpuinfo(text: str) -> dict[int, dict[str, str]]:
    """``/proc/cpuinfo`` -> ``{cpu: {field: value}}`` (keys lower-cased)."""
    cpus: dict[int, dict[str, str]] = {}
    current: dict[str, str] = {}
    for line in [*text.splitlines(), ""]:
        if not line.strip():
            if "processor" in current and current["processor"].isdigit():
                cpus[int(current["processor"])] = current
            current = {}
            continue
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() != "serial":  # a board serial number: never kept
            current[key.strip().lower()] = value.strip()
    return cpus


_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KMG]?)i?B?\s*$", re.IGNORECASE)


def parse_size_kib(text: str) -> int:
    """A sysfs cache size (``"512K"``, ``"8192K"``, ``"2M"``) in KiB."""
    m = _SIZE.match(text)
    if m is None:
        raise ValueError(f"not a size: {text!r}")
    factor = {"": 1 / 1024, "K": 1, "M": 1024, "G": 1024 * 1024}[m.group(2).upper()]
    return round(float(m.group(1)) * factor)


def parse_meminfo(text: str) -> dict[str, int]:
    """``/proc/meminfo`` (or a node ``meminfo``) -> ``{key: value}``, kB or a count."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        line = re.sub(r"^Node \d+ ", "", line)
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        number = rest.split()
        if number and number[0].isdigit():
            values[key.strip()] = int(number[0])
    return values


def parse_swaps(text: str) -> list[dict[str, Json]]:
    """``/proc/swaps`` -> one entry per swap area (its name is not kept)."""
    areas: list[dict[str, Json]] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 5:
            areas.append(
                {
                    "type": fields[1],
                    "size_kib": int(fields[2]),
                    "used_kib": int(fields[3]),
                    "priority": int(fields[4]),
                }
            )
    return areas


def parse_os_release(text: str) -> dict[str, str]:
    """``/etc/os-release`` -> ``{KEY: value}``, quotes removed."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


_UUID = re.compile(
    r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"
)


#: Kernel parameters whose whole value can identify one host or its network:
#: the netboot address, NFS root and PXE boot interface, the netconsole target,
#: the iSCSI initiator name, any vendor ``*serialno=``, and any ``*hostname=``
#: (``hostname=``, ``systemd.hostname=`` ...): ``os.cmdline`` then never holds
#: the hostname, so it is hashed as recorded and ``--anonymise`` has nothing
#: left to rewrite there (#21).
_CMDLINE_REDACTED = re.compile(
    r"(?<!\S)(?P<key>ip|nfsroot|nfsaddrs|BOOTIF|netconsole|rd\.iscsi\.initiator"
    r"|iscsi_initiator|[\w.-]*serialno|[\w.-]*hostname)=\S*",
    re.IGNORECASE,
)
#: MAC addresses, colon- or dash-separated, and longer hex strings of that form.
_CMDLINE_MAC = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])"
)
_CMDLINE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def parse_cmdline(text: str) -> str:
    """``/proc/cmdline`` without the values that identify one host.

    Filesystem UUIDs (``root=UUID=...``) become ``<uuid>``; the values of the
    parameters in :data:`_CMDLINE_REDACTED` (``ip=``, ``nfsroot=``,
    ``BOOTIF=``, ``*serialno=``, ``*hostname=`` ...) become ``<redacted>``; any
    other MAC address becomes ``<mac>`` and any IPv4 address ``<ip>``. A
    hostname embedded in another value (the ``ubuntu`` of
    ``root=/dev/mapper/ubuntu--vg-ubuntu--lv``) is kept as is: it names the
    volume, not the host (#21).
    """
    text = _CMDLINE_REDACTED.sub(lambda m: f"{m.group('key')}=<redacted>", text.strip())
    text = _UUID.sub("<uuid>", text)
    text = _CMDLINE_MAC.sub("<mac>", text)
    return _CMDLINE_IPV4.sub("<ip>", text)


def parse_sysfs_cpumask_text(text: str) -> str:
    """``isolated`` / ``nohz_full``: a cpulist, where ``(null)`` means none."""
    value = text.strip()
    return "" if value in {"", "(null)"} else value


def parse_ethtool_i(text: str) -> dict[str, str]:
    """``ethtool -i IFACE`` -> ``{driver, version, firmware-version, bus-info, ...}``."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            values[key.strip()] = value.strip()
    return values


def parse_ethtool_k(text: str) -> dict[str, str]:
    """``ethtool -k IFACE`` -> ``{feature: "on" | "off" | "off [fixed]" | ...}``."""
    features: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("Features for") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        features[key.strip()] = value.strip()
    return features


def _ethtool_sections(text: str) -> dict[str, dict[str, int | None]]:
    """The ``Pre-set maximums`` / ``Current hardware settings`` blocks of -l / -g."""
    sections: dict[str, dict[str, int | None]] = {}
    current: dict[str, int | None] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Pre-set maximums"):
            current = sections.setdefault("max", {})
        elif stripped.startswith("Current hardware settings"):
            current = sections.setdefault("current", {})
        elif current is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            value = value.strip()
            name = key.strip().lower().replace(" ", "_")
            if value.isdigit():
                current[name] = int(value)
            elif value == "n/a":
                current[name] = None
    return sections


def parse_ethtool_l(text: str) -> dict[str, dict[str, int | None]]:
    """``ethtool -l IFACE`` -> ``{"max": {rx, tx, other, combined}, "current": ...}``.

    ``None`` is ethtool's ``n/a``: the NIC has no channel of that kind.
    """
    return _ethtool_sections(text)


_RING_KEYS = ("rx", "rx_mini", "rx_jumbo", "tx")


def parse_ethtool_g(text: str) -> dict[str, dict[str, int | None]]:
    """``ethtool -g IFACE`` -> ``{"max": {rx, rx_mini, rx_jumbo, tx}, "current": ...}``."""
    return {
        section: {k: v for k, v in values.items() if k in _RING_KEYS}
        for section, values in _ethtool_sections(text).items()
    }


def parse_ethtool_x(text: str) -> dict[str, Json]:
    """``ethtool -x IFACE`` -> ring count, table size and hash functions.

    The RSS hash key is deliberately not parsed: it is a secret.
    """
    rings: int | None = None
    entries = 0
    functions: dict[str, str] = {}
    in_functions = False
    for line in text.splitlines():
        m = re.search(r"with (\d+) RX ring", line)
        if m:
            rings = int(m.group(1))
        elif re.match(r"^\s*\d+:\s", line):
            entries += len(line.split(":", 1)[1].split())
        elif line.startswith("RSS hash function"):
            in_functions = True
        elif in_functions and ":" in line:
            name, _, state = line.partition(":")
            functions[name.strip()] = state.strip()
        elif line.startswith("RSS hash key"):
            in_functions = False
    return {"rx_rings": rings, "indirection_table_size": entries, "hash_functions": functions}


def parse_lspci_nn(text: str) -> str:
    """``lspci -s ADDR -nn`` -> the device description after the address."""
    line = text.strip().splitlines()[0] if text.strip() else ""
    _, _, description = line.partition(" ")
    return description.strip()


def parse_docker_version(text: str) -> dict[str, Json]:
    """``docker version --format '{{json .}}'`` -> client, server and component versions."""
    data = json.loads(text)
    client = data.get("Client") or {}
    server = data.get("Server") or {}
    components = {c.get("Name"): c.get("Version") for c in server.get("Components") or []}
    return {
        "client_version": client.get("Version"),
        "server_version": server.get("Version"),
        "api_version": server.get("ApiVersion"),
        "containerd_version": components.get("containerd"),
        "runc_version": components.get("runc"),
    }


def parse_docker_info(text: str) -> dict[str, Json]:
    """``docker info --format '{{json .}}'`` -> the runtime's configuration."""
    data = json.loads(text)
    return {
        "server_version": data.get("ServerVersion"),
        "storage_driver": data.get("Driver"),
        "cgroup_driver": data.get("CgroupDriver"),
        "cgroup_version": data.get("CgroupVersion"),
        "default_runtime": data.get("DefaultRuntime"),
        "runtimes": sorted(data.get("Runtimes") or {}),
        "ncpu": data.get("NCPU"),
        "mem_total_bytes": data.get("MemTotal"),
        "containers_running": data.get("ContainersRunning"),
        "limit_support": {
            "cpuset": bool(data.get("CPUSet")),
            "cpu_shares": bool(data.get("CPUShares")),
            "cfs_quota": bool(data.get("CpuCfsQuota")),
            "memory": bool(data.get("MemoryLimit")),
            "swap": bool(data.get("SwapLimit")),
        },
    }


def parse_proc_self_cgroup(text: str) -> str | None:
    """``/proc/self/cgroup`` -> the cgroup v2 path (the ``0::`` line), if any."""
    for line in text.splitlines():
        if line.startswith("0::"):
            return line[3:].strip()
    return None


def parse_systemctl_show(text: str) -> dict[str, str]:
    """``systemctl show UNIT --property=...`` -> ``{Property: value}``."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key] = value
    return values


def parse_loadavg(text: str) -> dict[str, float]:
    """``/proc/loadavg`` -> ``{"load1", "load5", "load15"}``."""
    one, five, fifteen = text.split()[:3]
    return {"load1": float(one), "load5": float(five), "load15": float(fifteen)}


@dataclass(frozen=True)
class PidStat:
    pid: int
    comm: str
    ticks: int  # utime + stime, in clock ticks
    rss_pages: int


def parse_pid_stat(text: str) -> PidStat:
    """``/proc/PID/stat`` -> pid, command name, CPU ticks and resident pages."""
    pid = int(text.split(" ", 1)[0])
    comm = text[text.index("(") + 1 : text.rindex(")")]
    rest = text[text.rindex(")") + 2 :].split()
    # rest[0] is field 3 (state); utime and stime are fields 14 and 15, rss is 24.
    return PidStat(pid, comm, int(rest[11]) + int(rest[12]), int(rest[21]))


def parse_dmidecode_memory(text: str) -> dict[str, Json]:
    """``dmidecode -t 17`` -> populated memory devices with their types and speeds."""
    devices: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        if line.strip() == "Memory Device":
            current = {}
            devices.append(current)
        elif current is not None and ":" in line and line.startswith("\t"):
            key, _, value = line.strip().partition(":")
            current[key.strip()] = value.strip()
    # Only DMIDECODE_MEMORY_KEYS are read; a recorded answer keeps only those.
    size, mtype, speed, configured = DMIDECODE_MEMORY_KEYS
    populated = [d for d in devices if d.get(size, "No Module Installed") != "No Module Installed"]
    return {
        "devices": len(populated),
        "types": sorted({d.get(mtype, "Unknown") for d in populated}),
        "speeds": sorted({d.get(speed, "Unknown") for d in populated}),
        "configured_speeds": sorted({d.get(configured, "Unknown") for d in populated}),
    }


# --- The harness's own identity ----------------------------------------------


@dataclass(frozen=True)
class HarnessInfo:
    """What ran the collection: mbench and its Python."""

    mbench_version: str
    mbench_commit: Json
    mbench_dirty: Json
    python_version: str
    python_implementation: str

    @classmethod
    def live(
        cls, source: Source | None = None, package_dir: str | Path | None = None
    ) -> HarnessInfo:
        """The running mbench. Git is asked through ``source`` (default: the host)."""
        pkg = Path(package_dir) if package_dir is not None else Path(__file__).resolve().parent
        commit, dirty = git_state(source if source is not None else LiveSource(), str(pkg))
        return cls(
            mbench_version=__version__,
            mbench_commit=commit,
            mbench_dirty=dirty,
            python_version=platform.python_version(),
            python_implementation=platform.python_implementation(),
        )


#: Every git call: never take ``.git/index.lock`` or rewrite the index.
GIT = ("git", "--no-optional-locks")


def git_state(src: Source, package_dir: str) -> tuple[Json, Json]:
    """``(commit, dirty)`` of the mbench checkout holding ``package_dir``.

    Recorded only when the git work tree around the package is mbench's own
    source tree (``<toplevel>/src/mbench`` is the package). An mbench installed
    in another repository (a project's ``.venv``, a ``$HOME`` kept in git) gets
    a marker, not that repository's HEAD. The reasons never name a path.
    """

    def both(kind: str, reason: str) -> tuple[Marker, Marker]:
        return unavailable(kind, reason), unavailable(kind, reason)

    try:
        top = src.run([*GIT, "-C", package_dir, "rev-parse", "--show-toplevel"])
        if top.returncode != 0:
            return both("not_applicable", "mbench is not running from a git checkout")
        toplevel = top.stdout.strip()
        try:
            own = bool(toplevel) and src.realpath(f"{toplevel}/src/mbench") == src.realpath(
                package_dir
            )
        except OSError:
            own = False
        if not own:
            return both(
                "not_applicable",
                "the git work tree around the mbench package is another repository, "
                "not mbench's source tree",
            )
        head = src.run([*GIT, "-C", toplevel, "rev-parse", "--verify", "HEAD"])
        status = src.run([*GIT, "-C", toplevel, "status", "--porcelain", "--untracked-files=no"])
    except FileNotFoundError:
        return both("missing_tool", "git is not installed")
    except OSError as exc:
        return both("error", f"git: {exc.strerror or exc}")
    if head.returncode != 0 or status.returncode != 0:
        return both("error", "git could not read the HEAD or status of the mbench checkout")
    return head.stdout.strip(), bool(status.stdout.strip())


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


# --- The collector -----------------------------------------------------------


@dataclass
class Options:
    """What to collect beyond the defaults."""

    alias: str | None = None  # --anonymise: replace the hostname with this alias
    extra_nics: Sequence[str] = ()  # --nic: the NICs under test (a virtual one: a veth)
    watch_units: Sequence[str] = VLLM_UNITS  # services whose state is recorded
    sample_seconds: float = DEFAULT_SAMPLE_SECONDS
    top_n: int = DEFAULT_TOP_N
    harness: HarnessInfo | None = None
    clock: Callable[[], datetime] = field(default=_now)


class Collector:
    """Builds one sut.json record from a :class:`Source`."""

    def __init__(self, source: Source, options: Options | None = None) -> None:
        self.src = source
        self.opts = options or Options()
        self.consts = source.constants()
        self._commands: dict[tuple[str, ...], CommandResult | Marker] = {}
        self._hostname: str | Marker | None = None

    # Reading helpers: each returns the value or an unavailable marker.

    def _oserror(self, exc: OSError, what: str) -> Marker:
        if isinstance(exc, PermissionError):
            if self.consts.get("euid") == 0:
                return unavailable("error", f"{what}: permission denied even as root")
            return unavailable("needs_root", f"{what} is readable by root only")
        if isinstance(exc, FileNotFoundError):
            return unavailable("not_supported", f"{what} does not exist on this host")
        if exc.errno == errno.EINVAL:
            return unavailable("not_supported", f"{what}: the driver does not report it (EINVAL)")
        return unavailable("error", f"{what}: {exc.strerror or exc}")

    def text(self, path: str) -> str | Marker:
        try:
            return self.src.read(path).strip()
        except OSError as exc:
            return self._oserror(exc, path)

    def listdir(self, path: str) -> list[str] | Marker:
        try:
            return self.src.listdir(path)
        except OSError as exc:
            return self._oserror(exc, path)

    def command(self, argv: Sequence[str]) -> CommandResult | Marker:
        """Run ``argv`` once per collection; a repeat call reuses the result."""
        key = tuple(argv)
        if key not in self._commands:
            self._commands[key] = self._command(argv)
        return self._commands[key]

    def _command(self, argv: Sequence[str]) -> CommandResult | Marker:
        try:
            result = self.src.run(argv)
        except FileNotFoundError:
            return unavailable("missing_tool", f"{argv[0]} is not installed")
        except OSError as exc:
            return unavailable("error", f"{' '.join(argv)}: {exc.strerror or exc}")
        if result.returncode != 0:
            err = (result.stderr or result.stdout).strip().splitlines()
            message = err[-1] if err else f"exit status {result.returncode}"
            kind = "not_supported" if "not supported" in message.lower() else "error"
            if "not permitted" in message.lower() or "permission denied" in message.lower():
                kind = "needs_root" if self.consts.get("euid") != 0 else "error"
            return unavailable(kind, f"{' '.join(argv)}: {message}")
        return result

    def parsed(self, argv: Sequence[str], parser: Callable[[str], Json]) -> Json:
        result = self.command(argv)
        if isinstance(result, dict):
            return result
        try:
            return parser(result.stdout)
        except (ValueError, KeyError, IndexError) as exc:
            return unavailable("error", f"{' '.join(argv)}: unparsable output ({exc})")

    def number(self, path: str, scale: float = 1.0) -> Json:
        value = self.text(path)
        if isinstance(value, dict):
            return value
        try:
            number = float(value) * scale
        except ValueError:
            return unavailable("error", f"{path}: not a number: {value!r}")
        return int(number) if number.is_integer() else round(number, 3)

    # Sections.

    def collect(self) -> dict[str, Json]:
        start = self.opts.clock()
        load_before = self.loadavg()
        first = self.process_sample()
        self.src.sleep(self.opts.sample_seconds)
        second = self.process_sample()

        cpus = self.online_cpus()
        record: dict[str, Json] = {
            "schema_version": SCHEMA_VERSION,
            "scope": "host",
            "collected_at": _iso(start),
            "sut_hash": "",
            "host": self.host(cpus),
            "os": self.os_section(),
            "nics": self.nics(),
            "container_runtime": self.container_runtime(),
            "tools": unavailable(
                "not_applicable",
                "host-scope record: the adapter fills the tools under test at run time (#5)",
            ),
            "noise": {},
            "harness": {},
        }
        noise = self.noise(record["host"]["cpu"]["core_types"], first, second)
        record["noise"] = {
            "load_average": {"before": load_before, "after": self.loadavg()},
            **noise,
        }
        end = self.opts.clock()
        record["harness"] = self.harness(start, end)
        record["sut_hash"] = sut_hash(record)
        return record

    def online_cpus(self) -> list[int]:
        online = self.text("/sys/devices/system/cpu/online")
        if isinstance(online, dict):
            entries = self.listdir("/sys/devices/system/cpu")
            if isinstance(entries, dict):
                return []
            return sorted(int(e[3:]) for e in entries if re.fullmatch(r"cpu\d+", e))
        return parse_cpulist(online)

    def real_hostname(self) -> str | Marker:
        if self._hostname is None:
            self._hostname = self.text("/proc/sys/kernel/hostname")
        return self._hostname

    def host(self, cpus: list[int]) -> dict[str, Json]:
        hostname = self.real_hostname()
        if self.opts.alias is not None:
            hostname = self.opts.alias
        arch = self.parsed(["uname", "-m"], lambda s: s.strip())
        return {
            "hostname": hostname,
            "hostname_anonymised": self.opts.alias is not None,
            "architecture": arch,
            "dmi": self.dmi(),
            "cpu": self.cpu(cpus),
            "numa": self.numa(),
            "memory": self.memory(),
        }

    DMI_FIELDS = (
        "sys_vendor",
        "product_name",
        "product_family",
        "product_version",
        "product_sku",
        "board_vendor",
        "board_name",
        "board_version",
        "bios_vendor",
        "bios_version",
        "bios_date",
        "bios_release",
        "chassis_vendor",
        "chassis_type",
    )

    def dmi(self) -> dict[str, Json]:
        # Serial numbers and the product UUID are not recorded at all: they
        # identify one machine and add nothing to a performance comparison.
        return {f: self.text(f"/sys/class/dmi/id/{f}") for f in self.DMI_FIELDS}

    def cpu(self, cpus: list[int]) -> dict[str, Json]:
        base = "/sys/devices/system/cpu"
        models = self.parsed(["lscpu", "-p=CPU,MODELNAME"], parse_lscpu_models)
        cpuinfo_text = self.text("/proc/cpuinfo")
        cpuinfo = {} if isinstance(cpuinfo_text, dict) else parse_cpuinfo(cpuinfo_text)

        per_cpu: dict[int, dict[str, Json]] = {}
        all_caches: dict[int, list[dict[str, Json]] | Marker] = {}
        for n in cpus:
            d = f"{base}/cpu{n}"
            info = cpuinfo.get(n, {})
            model: Json
            if isinstance(models, dict) and n in models and models[n] not in {"", "-"}:
                model = models[n]
            elif "model name" in info:
                model = info["model name"]
            elif "cpu part" in info:
                model = f"part {info['cpu part']}"
            else:
                model = unavailable("not_supported", "no model name from lscpu or /proc/cpuinfo")
            midr = self.text(f"{d}/regs/identification/midr_el1")
            if is_unavailable(midr) and midr["unavailable"] == "not_supported":
                midr = unavailable("not_applicable", "MIDR_EL1 exists on Arm CPUs only")
            per_cpu[n] = {
                "model_name": model,
                "midr": midr,
                "cpuinfo_max_mhz": self.number(f"{d}/cpufreq/cpuinfo_max_freq", 1e-3),
                "cpuinfo_min_mhz": self.number(f"{d}/cpufreq/cpuinfo_min_freq", 1e-3),
                "scaling_max_mhz": self.number(f"{d}/cpufreq/scaling_max_freq", 1e-3),
                "scaling_min_mhz": self.number(f"{d}/cpufreq/scaling_min_freq", 1e-3),
                "scaling_driver": self.text(f"{d}/cpufreq/scaling_driver"),
                "governor": self.text(f"{d}/cpufreq/scaling_governor"),
                "caches": self.per_core_caches(all_caches.setdefault(n, self.read_caches(d))),
                "package": self.number(f"{d}/topology/physical_package_id"),
            }

        groups: dict[str, list[int]] = {}
        for n, info in per_cpu.items():
            key = json.dumps([info["model_name"], info["midr"]], sort_keys=True)
            groups.setdefault(key, []).append(n)
        core_types = []
        for members in sorted(groups.values(), key=lambda m: m[0]):
            first = per_cpu[members[0]]
            fields = [k for k in first if k != "package"]
            nonuniform = sorted(
                k for k in fields if any(per_cpu[m][k] != first[k] for m in members)
            )
            entry = {k: first[k] for k in fields}
            # A field that differs between CPUs of one type (dgx-spark: the L3
            # is 8 MiB on CPUs 0-9 and 16 MiB on 10-19) keeps the first CPU's
            # value and lists every variant with the CPUs that have it.
            variants: dict[str, list[dict[str, Json]]] = {}
            for k in nonuniform:
                by_value: dict[str, list[int]] = {}
                for m in members:
                    by_value.setdefault(json.dumps(per_cpu[m][k], sort_keys=True), []).append(m)
                variants[k] = [
                    {"cpus": format_cpulist(ms), "value": json.loads(v)}
                    for v, ms in sorted(by_value.items(), key=lambda item: item[1][0])
                ]
            entry.update(
                count=len(members),
                cpus=format_cpulist(members),
                nonuniform_fields=nonuniform,
                variants=variants,
            )
            core_types.append(entry)

        packages = {
            info["package"] for info in per_cpu.values() if isinstance(info["package"], int)
        }
        smt_active = self.text(f"{base}/smt/active")
        return {
            "logical_cpus": len(cpus),
            "online": format_cpulist(cpus),
            "sockets": len(packages)
            if packages
            else unavailable("not_supported", "no physical_package_id in sysfs topology"),
            "smt": {
                "control": self.text(f"{base}/smt/control"),
                "active": smt_active if isinstance(smt_active, dict) else smt_active == "1",
            },
            "boost": self.boost(),
            "isolated": self._cpumask(f"{base}/isolated"),
            "nohz_full": self._cpumask(f"{base}/nohz_full"),
            "core_types": core_types,
            "cache_totals": self.cache_totals(all_caches),
            "lscpu_caches": self.parsed(["lscpu", "-J", "-C"], parse_lscpu_caches),
        }

    def _cpumask(self, path: str) -> Json:
        value = self.text(path)
        return value if isinstance(value, dict) else parse_sysfs_cpumask_text(value)

    def read_caches(self, cpu_dir: str) -> list[dict[str, Json]] | Marker:
        """The caches of one CPU; ``shared_list`` is the raw sharing cpulist."""
        entries = self.listdir(f"{cpu_dir}/cache")
        if isinstance(entries, dict):
            return entries
        caches = []
        for index in sorted(e for e in entries if e.startswith("index")):
            d = f"{cpu_dir}/cache/{index}"
            size = self.text(f"{d}/size")
            caches.append(
                {
                    "level": self.number(f"{d}/level"),
                    "type": self.text(f"{d}/type"),
                    "size_kib": size if isinstance(size, dict) else parse_size_kib(size),
                    "ways": self.number(f"{d}/ways_of_associativity"),
                    "line_bytes": self.number(f"{d}/coherency_line_size"),
                    "shared_list": self.text(f"{d}/shared_cpu_list"),
                }
            )
        return caches

    @staticmethod
    def per_core_caches(caches: list[dict[str, Json]] | Marker) -> Json:
        """One CPU's caches as recorded per core type: sharing as a CPU count."""
        if is_unavailable(caches):
            return caches
        assert isinstance(caches, list)
        out = []
        for c in caches:
            shared = c["shared_list"]
            entry = {k: v for k, v in c.items() if k != "shared_list"}
            entry["shared_cpus"] = shared if is_unavailable(shared) else len(parse_cpulist(shared))
            out.append(entry)
        return out

    @staticmethod
    def cache_totals(all_caches: dict[int, list[dict[str, Json]] | Marker]) -> Json:
        """Unique cache instances (by name and sharing CPUs) and their total size."""
        seen: set[tuple[str, str]] = set()
        totals: dict[str, dict[str, int]] = {}
        for caches in all_caches.values():
            if is_unavailable(caches):
                return caches
            assert isinstance(caches, list)
            for c in caches:
                if any(is_unavailable(c[k]) for k in ("level", "type", "size_kib", "shared_list")):
                    continue
                name = f"L{c['level']}" + {"Data": "d", "Instruction": "i"}.get(str(c["type"]), "")
                key = (name, str(c["shared_list"]))
                if key in seen:
                    continue
                seen.add(key)
                slot = totals.setdefault(name, {"instances": 0, "total_kib": 0})
                slot["instances"] += 1
                slot["total_kib"] += int(c["size_kib"])
        return totals

    def boost(self) -> Json:
        value = self.text("/sys/devices/system/cpu/cpufreq/boost")
        if not isinstance(value, dict):
            return value == "1"
        no_turbo = self.text("/sys/devices/system/cpu/intel_pstate/no_turbo")
        if not isinstance(no_turbo, dict):
            return no_turbo == "0"
        return unavailable("not_supported", "no cpufreq boost or intel_pstate no_turbo control")

    def numa(self) -> Json:
        base = "/sys/devices/system/node"
        entries = self.listdir(base)
        if isinstance(entries, dict):
            return entries
        nodes = []
        for name in sorted(
            (e for e in entries if re.fullmatch(r"node\d+", e)), key=lambda e: int(e[4:])
        ):
            cpus = self.text(f"{base}/{name}/cpulist")
            meminfo = self.text(f"{base}/{name}/meminfo")
            nodes.append(
                {
                    "node": int(name[4:]),
                    "cpus": cpus,
                    "mem_total_kib": (
                        meminfo
                        if isinstance(meminfo, dict)
                        else parse_meminfo(meminfo).get("MemTotal", 0)
                    ),
                }
            )
        return {"nodes": nodes}

    def memory(self) -> dict[str, Json]:
        meminfo_text = self.text("/proc/meminfo")
        meminfo = {} if isinstance(meminfo_text, dict) else parse_meminfo(meminfo_text)
        swaps = self.text("/proc/swaps")
        swap: Json
        if isinstance(swaps, dict):
            swap = swaps
        else:
            swap = {
                "total_kib": meminfo.get("SwapTotal", 0),
                "areas": [
                    {k: v for k, v in a.items() if k != "used_kib"} for a in parse_swaps(swaps)
                ],
            }
        dimms = self.dimms()
        return {
            "total_kib": meminfo.get("MemTotal")
            or unavailable("error", "/proc/meminfo has no MemTotal"),
            "speed": dimms if is_unavailable(dimms) else dimms["speeds"],
            "type": dimms if is_unavailable(dimms) else dimms["types"],
            "hugepages": self.hugepages(),
            "transparent_hugepage": {
                "enabled": self._bracketed("/sys/kernel/mm/transparent_hugepage/enabled"),
                "defrag": self._bracketed("/sys/kernel/mm/transparent_hugepage/defrag"),
            },
            "swap": swap,
        }

    def dimms(self) -> Json:
        probe = self.text("/sys/firmware/dmi/tables/smbios_entry_point")
        if is_unavailable(probe):
            if probe["unavailable"] == "needs_root":
                return unavailable(
                    "needs_root",
                    "memory speed and type come from the SMBIOS table "
                    "/sys/firmware/dmi/tables/DMI (dmidecode), readable by root only",
                )
            return unavailable("not_supported", "no SMBIOS table on this host")
        return self.parsed(["dmidecode", "-t", "17"], parse_dmidecode_memory)

    def _bracketed(self, path: str) -> Json:
        value = self.text(path)
        if isinstance(value, dict):
            return value
        m = re.search(r"\[([^\]]+)\]", value)
        return m.group(1) if m else value

    def hugepages(self) -> Json:
        base = "/sys/kernel/mm/hugepages"
        entries = self.listdir(base)
        if isinstance(entries, dict):
            return entries
        meminfo = self.text("/proc/meminfo")
        default = (
            meminfo if isinstance(meminfo, dict) else parse_meminfo(meminfo).get("Hugepagesize", 0)
        )
        pools = []
        for name in entries:
            m = re.fullmatch(r"hugepages-(\d+)kB", name)
            if m:
                pools.append(
                    {
                        "size_kib": int(m.group(1)),
                        "total": self.number(f"{base}/{name}/nr_hugepages"),
                    }
                )
        return {"default_size_kib": default, "pools": sorted(pools, key=lambda p: p["size_kib"])}

    def os_section(self) -> dict[str, Json]:
        release = self.text("/etc/os-release")
        if is_unavailable(release):
            release = self.text("/usr/lib/os-release")
        distro: Json
        if isinstance(release, dict):
            distro = release
        else:
            values = parse_os_release(release)
            distro = {
                "id": values.get("ID", ""),
                "version_id": values.get("VERSION_ID", ""),
                "pretty_name": values.get("PRETTY_NAME", ""),
            }
        cmdline = self.text("/proc/cmdline")
        if isinstance(cmdline, str):
            cmdline = parse_cmdline(cmdline)
        return {
            "distro": distro,
            "kernel": {
                "release": self.text("/proc/sys/kernel/osrelease"),
                "version": self.text("/proc/sys/kernel/version"),
            },
            "cmdline": cmdline,
            "mitigations": self.mitigations(),
            "sysctl_net_core": self.sysctl_net_core(),
        }

    def mitigations(self) -> Json:
        base = "/sys/devices/system/cpu/vulnerabilities"
        entries = self.listdir(base)
        if isinstance(entries, dict):
            return entries
        return {name: self.text(f"{base}/{name}") for name in entries}

    #: net.core keys holding secrets: readable, never recorded.
    SECRET_SYSCTLS = frozenset({"netdev_rss_key"})

    def sysctl_net_core(self) -> Json:
        base = "/proc/sys/net/core"
        entries = self.listdir(base)
        if isinstance(entries, dict):
            return entries
        values: dict[str, Json] = {}
        for name in entries:
            if name in self.SECRET_SYSCTLS:
                values[name] = unavailable("redacted", "RSS hash key: a secret, not recorded")
                continue
            value = self.text(f"{base}/{name}")
            values[name] = value if isinstance(value, dict) else " ".join(value.split())
        return values

    def nics(self) -> Json:
        """Every physical NIC, and the NICs under test (``--nic``).

        A host with neither (a container with only a veth) gets a
        ``not_supported`` marker that points to ``--nic``; an unreadable
        ``/sys/class/net`` gets the marker of the failed read. Never ``[]``.
        """
        names = self.listdir("/sys/class/net")
        if isinstance(names, dict):
            if self.opts.extra_nics:
                raise ValueError(
                    f"cannot find {', '.join(self.opts.extra_nics)}: {names['reason']}"
                )
            return names
        chosen = []
        for name in names:
            device = self._realpath(f"/sys/class/net/{name}/device")
            if device is not None or name in self.opts.extra_nics:
                chosen.append((name, device))
        missing = sorted(set(self.opts.extra_nics) - {n for n, _ in chosen})
        if missing:
            raise ValueError(f"no such network interface: {', '.join(missing)}")
        if not chosen:
            return unavailable(
                "not_supported",
                "no physical network interface on this host; "
                "name the interface under test with --nic IFACE",
            )
        return [self.nic(name, device) for name, device in chosen]

    def _realpath(self, path: str) -> str | None:
        try:
            return self.src.realpath(path)
        except OSError:
            return None

    def nic(self, name: str, device: str | None) -> dict[str, Json]:
        d = f"/sys/class/net/{name}"
        info = self.parsed(["ethtool", "-i", name], parse_ethtool_i)
        driver: Json
        if is_unavailable(info):
            driver = info
        else:
            firmware: Json = info.get("firmware-version", "")
            if firmware in {"", "N/A", "n/a"}:
                firmware = unavailable("not_supported", "the driver reports no firmware version")
            driver = {
                "name": info.get("driver", ""),
                "version": info.get("version", ""),
                "firmware": firmware,
            }
        offload_features = self.parsed(["ethtool", "-k", name], parse_ethtool_k)
        return {
            "name": name,
            "kind": "physical" if device is not None else "virtual",
            "under_test": name in self.opts.extra_nics,
            "pci": self.pci(d, device),
            "driver": driver,
            "link": self.link(d),
            "queues": self.queues(d),
            "channels": self.parsed(["ethtool", "-l", name], parse_ethtool_l),
            "rings": self.parsed(["ethtool", "-g", name], parse_ethtool_g),
            "offloads": self.offloads(offload_features),
            "rss": self.parsed(["ethtool", "-x", name], parse_ethtool_x),
            "irqs": self.irqs(d)
            if device is not None
            else unavailable("not_applicable", "virtual interface: no device interrupts"),
        }

    def pci(self, d: str, device: str | None) -> Json:
        if device is None:
            return unavailable("not_applicable", "virtual interface: no PCI device")
        bus = self._realpath(f"{d}/device/subsystem")
        if bus is None or bus.rsplit("/", 1)[-1] != "pci":
            name = "an unknown" if bus is None else f"the {bus.rsplit('/', 1)[-1]}"
            return unavailable("not_applicable", f"device is on {name} bus, not PCI")
        address = device.rsplit("/", 1)[-1]
        base = f"/sys/bus/pci/devices/{address}"
        return {
            "address": address,
            "vendor_id": self.text(f"{base}/vendor"),
            "device_id": self.text(f"{base}/device"),
            "subsystem_vendor_id": self.text(f"{base}/subsystem_vendor"),
            "subsystem_device_id": self.text(f"{base}/subsystem_device"),
            "description": self.parsed(["lspci", "-s", address, "-nn"], parse_lspci_nn),
        }

    def link(self, d: str) -> dict[str, Json]:
        operstate = self.text(f"{d}/operstate")
        speed = self.number(f"{d}/speed")
        # A link that is down reads -1, or fails with EINVAL, instead of a speed.
        negative = isinstance(speed, (int, float)) and speed < 0
        if negative or (is_unavailable(speed) and operstate != "up"):
            speed = unavailable("not_applicable", f"link is {operstate}: no negotiated speed")
        return {
            "operstate": operstate,
            "speed_mbps": speed,
            "duplex": self.text(f"{d}/duplex"),
            "mtu": self.number(f"{d}/mtu"),
        }

    def queues(self, d: str) -> Json:
        entries = self.listdir(f"{d}/queues")
        if isinstance(entries, dict):
            return entries
        rx = [e for e in entries if e.startswith("rx-")]
        rps_values = sorted(
            {v for q in rx if isinstance(v := self.text(f"{d}/queues/{q}/rps_cpus"), str)}
        )
        return {
            "rx": len(rx),
            "tx": sum(1 for e in entries if e.startswith("tx-")),
            "rps_cpus": rps_values,
        }

    def offloads(self, features: Json) -> Json:
        if is_unavailable(features):
            return features

        def on(name: str) -> Json:
            value = features.get(name)
            if value is None:
                return unavailable("not_supported", f"ethtool -k reports no {name}")
            return str(value).startswith("on")

        return {
            "gro": on("generic-receive-offload"),
            "lro": on("large-receive-offload"),
            "tso": on("tcp-segmentation-offload"),
            "gso": on("generic-segmentation-offload"),
            "rx_hashing": on("receive-hashing"),
            "features": features,
        }

    #: Entries of /proc/irq/N that are not action (handler) names.
    IRQ_FILES = frozenset(
        {
            "affinity_hint",
            "effective_affinity",
            "effective_affinity_list",
            "node",
            "smp_affinity",
            "smp_affinity_list",
            "spurious",
        }
    )

    def irqs(self, d: str) -> Json:
        entries = self.listdir(f"{d}/device/msi_irqs")
        if isinstance(entries, dict):
            if entries["unavailable"] == "not_supported":
                return unavailable("not_supported", f"{d}/device has no MSI interrupts")
            return entries
        irqs = []
        for irq in sorted(int(e) for e in entries if e.isdigit()):
            actions = self.listdir(f"/proc/irq/{irq}")
            names = (
                []
                if isinstance(actions, dict)
                else sorted(a for a in actions if a not in self.IRQ_FILES)
            )
            irqs.append(
                {
                    "irq": irq,
                    "names": names,
                    "affinity": self.text(f"/proc/irq/{irq}/smp_affinity_list"),
                    "effective_affinity": self.text(f"/proc/irq/{irq}/effective_affinity_list"),
                }
            )
        return irqs

    DOCKER_VERSION_KEYS = ("client_version", "api_version", "containerd_version", "runc_version")
    DOCKER_INFO_KEYS = (
        "server_version",
        "storage_driver",
        "cgroup_driver",
        "cgroup_version",
        "default_runtime",
        "runtimes",
        "ncpu",
        "mem_total_bytes",
        "limit_support",
    )

    def container_runtime(self) -> dict[str, Json]:
        version = self.parsed(["docker", "version", "--format", "{{json .}}"], parse_docker_version)
        info = self.parsed(["docker", "info", "--format", "{{json .}}"], parse_docker_info)
        docker: Json
        if is_unavailable(version) and is_unavailable(info):
            docker = version
        else:
            docker = {}
            for key in self.DOCKER_VERSION_KEYS:
                docker[key] = version if is_unavailable(version) else version[key]
            for key in self.DOCKER_INFO_KEYS:
                docker[key] = info if is_unavailable(info) else info[key]
            if docker["server_version"] is None or is_unavailable(docker["server_version"]):
                docker["server_version"] = (
                    version if is_unavailable(version) else version["server_version"]
                )
            docker = {
                k: unavailable("error", f"docker did not report {k}") if v is None else v
                for k, v in sorted(docker.items())
            }
        controllers = self.text("/sys/fs/cgroup/cgroup.controllers")
        cgroup: Json
        if isinstance(controllers, str):
            cgroup = {"version": 2, "controllers": controllers.split()}
        elif not is_unavailable(self.listdir("/sys/fs/cgroup/cpu")):
            cgroup = {"version": 1, "controllers": self.listdir("/sys/fs/cgroup")}
        else:
            cgroup = unavailable("not_supported", "no cgroup filesystem at /sys/fs/cgroup")
        return {
            "docker": docker,
            "cgroup": cgroup,
            "limits": {
                "harness": self.harness_cgroup_limits(),
                "per_run": unavailable(
                    "not_applicable",
                    "host-scope record: the runner records each run's container limits (#8)",
                ),
            },
        }

    def harness_cgroup_limits(self) -> Json:
        text = self.text("/proc/self/cgroup")
        if isinstance(text, dict):
            return text
        path = parse_proc_self_cgroup(text)
        if path is None:
            return unavailable("not_supported", "no cgroup v2 entry in /proc/self/cgroup")
        base = "/sys/fs/cgroup" + path.rstrip("/")
        limits: dict[str, Json] = {}
        for key, name, controller in (
            ("cpu_max", "cpu.max", "cpu"),
            ("memory_max", "memory.max", "memory"),
            ("cpuset_cpus", "cpuset.cpus.effective", "cpuset"),
        ):
            value = self.text(f"{base}/{name}")
            if is_unavailable(value) and value["unavailable"] == "not_supported":
                # The path names a per-session scope; it is not recorded.
                value = unavailable(
                    "not_supported",
                    f"the {controller} controller is not enabled for the harness's cgroup",
                )
            limits[key] = value
        return limits

    def loadavg(self) -> Json:
        text = self.text("/proc/loadavg")
        return text if isinstance(text, dict) else parse_loadavg(text)

    def process_sample(self) -> dict[int, PidStat] | Marker:
        entries = self.listdir("/proc")
        if isinstance(entries, dict):
            return entries
        sample: dict[int, PidStat] = {}
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                stat = parse_pid_stat(self.src.read(f"/proc/{entry}/stat"))
            except (OSError, ValueError, IndexError):
                continue  # the process exited between the listing and the read
            sample[stat.pid] = stat
        return sample

    def top_processes(
        self, first: dict[int, PidStat] | Marker, second: dict[int, PidStat] | Marker
    ) -> tuple[Json, Json]:
        """The processes using the most CPU over the sample window, and the most memory."""
        if is_unavailable(first):
            return first, first
        if is_unavailable(second):
            return second, second
        before_sample: dict[int, PidStat] = first  # type: ignore[assignment]
        after_sample: dict[int, PidStat] = second  # type: ignore[assignment]
        ticks = self.consts["clock_ticks"] * self.opts.sample_seconds
        page_kib = self.consts["page_size"] // 1024
        rows: list[dict[str, Any]] = []
        for pid, now in after_sample.items():
            before = before_sample.get(pid)
            if before is None or before.comm != now.comm or now.ticks < before.ticks:
                continue  # exited, or the pid was reused in the window
            rows.append(
                {
                    "pid": pid,
                    "comm": now.comm,
                    "cpu_percent": round(100.0 * (now.ticks - before.ticks) / ticks, 1),
                    "rss_kib": now.rss_pages * page_kib,
                }
            )
        n = self.opts.top_n
        by_cpu = sorted(rows, key=lambda r: (-r["cpu_percent"], r["pid"]))[:n]
        by_mem = sorted(rows, key=lambda r: (-r["rss_kib"], r["pid"]))[:n]
        return by_cpu, by_mem

    def services(self) -> list[dict[str, Json]]:
        props = "--property=Id,LoadState,ActiveState,SubState,UnitFileState"
        records = []
        for unit in self.opts.watch_units:
            found: dict[str, Json] | None = None
            errors = []
            for scope, argv in (
                ("system", ["systemctl", "show", unit, props, "--no-pager"]),
                ("user", ["systemctl", "--user", "show", unit, props, "--no-pager"]),
            ):
                result = self.parsed(argv, parse_systemctl_show)
                if is_unavailable(result):
                    errors.append(result)
                    continue
                if result.get("LoadState") == "loaded":
                    found = {"scope": scope, **result}
                    break
            if found is not None:
                records.append(
                    {
                        "unit": unit,
                        "scope": found["scope"],
                        "load_state": found.get("LoadState", ""),
                        "active_state": found.get("ActiveState", ""),
                        "sub_state": found.get("SubState", ""),
                        "unit_file_state": found.get("UnitFileState", ""),
                    }
                )
            elif errors:
                # A scope that could not be asked (no user bus under cron, sudo
                # or a service) is not a scope that lacks the unit: the state
                # is unknown, never "not found" or "stopped".
                records.append(
                    {
                        "unit": unit,
                        "scope": errors[0],
                        "load_state": errors[0],
                        "active_state": errors[0],
                        "sub_state": errors[0],
                        "unit_file_state": errors[0],
                    }
                )
            else:
                missing = unavailable("not_applicable", "unit not found in system or user scope")
                records.append(
                    {
                        "unit": unit,
                        "scope": missing,
                        "load_state": "not-found",
                        "active_state": "inactive",
                        "sub_state": "dead",
                        "unit_file_state": missing,
                    }
                )
        return records

    def noise(
        self,
        core_types: Json,
        first: dict[int, PidStat] | Marker,
        second: dict[int, PidStat] | Marker,
    ) -> dict[str, Json]:
        by_cpu, by_mem = self.top_processes(first, second)
        services = self.services()
        vllm = [s for s in services if s["unit"] in VLLM_UNITS]
        vllm_stopped: Json
        if any(is_unavailable(s["active_state"]) for s in vllm):
            vllm_stopped = unavailable("error", "the state of a vLLM unit could not be read")
        elif not vllm:
            vllm_stopped = unavailable("not_applicable", "no vLLM unit is watched")
        else:
            running = {"active", "activating", "reloading", "deactivating"}
            vllm_stopped = not any(s["active_state"] in running for s in vllm)
        meminfo_text = self.text("/proc/meminfo")
        meminfo = {} if isinstance(meminfo_text, dict) else parse_meminfo(meminfo_text)
        info = self.parsed(["docker", "info", "--format", "{{json .}}"], parse_docker_info)
        return {
            "top_cpu": by_cpu,
            "top_memory": by_mem,
            "sample_seconds": self.opts.sample_seconds,
            "services": services,
            "vllm_stopped": vllm_stopped,
            "containers_running": info if is_unavailable(info) else info["containers_running"],
            "memory": {
                "available_kib": meminfo.get("MemAvailable", 0),
                "swap_used_kib": meminfo.get("SwapTotal", 0) - meminfo.get("SwapFree", 0),
            },
            "thermal": self.thermal(),
            "cpu_frequency": self.cpu_frequency(core_types),
        }

    def thermal(self) -> Json:
        base = "/sys/class/thermal"
        entries = self.listdir(base)
        if isinstance(entries, dict):
            return entries
        zones = []
        cooling: dict[str, dict[str, int]] = {}
        for name in sorted(entries, key=lambda e: (re.sub(r"\d+$", "", e), _suffix(e))):
            if name.startswith("thermal_zone"):
                temp = self.number(f"{base}/{name}/temp", 1e-3)
                zones.append(
                    {"zone": name, "type": self.text(f"{base}/{name}/type"), "temp_c": temp}
                )
            elif name.startswith("cooling_device"):
                ctype = self.text(f"{base}/{name}/type")
                cur = self.number(f"{base}/{name}/cur_state")
                slot = cooling.setdefault(
                    str(ctype) if isinstance(ctype, str) else "unknown", {"devices": 0, "active": 0}
                )
                slot["devices"] += 1
                slot["active"] += 1 if isinstance(cur, int) and cur > 0 else 0
        if not zones:
            return unavailable("not_supported", "no thermal zones in /sys/class/thermal")
        return {"zones": zones, "cooling_devices": cooling}

    def cpu_frequency(self, core_types: Json) -> Json:
        """Frequency per core type at the end of the collection, and throttled CPUs."""
        if is_unavailable(core_types):
            return core_types
        out = []
        for core_type in core_types:
            cpus = parse_cpulist(core_type["cpus"])
            entry: dict[str, Json] = {
                "model_name": core_type["model_name"],
                "cpus": core_type["cpus"],
            }
            for key, name in (
                ("scaling_cur_mhz", "scaling_cur_freq"),
                ("cpuinfo_cur_mhz", "cpuinfo_cur_freq"),
            ):
                values = [
                    self.number(f"/sys/devices/system/cpu/cpu{n}/cpufreq/{name}", 1e-3)
                    for n in cpus
                ]
                markers = [v for v in values if is_unavailable(v)]
                entry[key] = (
                    markers[0]
                    if markers
                    else {
                        "min": min(values),
                        "max": max(values),
                        "mean": round(sum(values) / len(values), 1),
                    }
                )
            limited = {
                n: self.number(f"/sys/devices/system/cpu/cpu{n}/cpufreq/perf_limited") for n in cpus
            }
            markers = [v for v in limited.values() if is_unavailable(v)]
            entry["perf_limited_cpus"] = (
                markers[0] if markers else format_cpulist(n for n, v in limited.items() if v)
            )
            out.append(entry)
        return out

    def harness(self, start: datetime, end: datetime) -> dict[str, Json]:
        info = self.opts.harness or HarnessInfo.live(self.src)
        return {
            "mbench_version": info.mbench_version,
            "mbench_commit": info.mbench_commit,
            "mbench_dirty": info.mbench_dirty,
            "python_version": info.python_version,
            "python_implementation": info.python_implementation,
            "collection": {"start": _iso(start), "end": _iso(end)},
            "run": unavailable(
                "not_applicable", "host-scope record: the runner records the run's times (#8)"
            ),
            "pcaps": unavailable(
                "not_applicable", "host-scope record: the runner records the pcap sha256s (#8)"
            ),
        }


def _suffix(name: str) -> int:
    m = re.search(r"(\d+)$", name)
    return int(m.group(1)) if m else -1


def collect(source: Source, options: Options | None = None) -> dict[str, Json]:
    """The sut.json record of the host behind ``source``."""
    return Collector(source, options).collect()


# --- sut_hash ----------------------------------------------------------------

#: Fields inside the hashed sections that change at run time without any
#: hardware or configuration change, left out of the hash. irqbalance rewrites
#: ``affinity``; ``effective_affinity`` is wherever the kernel last placed the
#: interrupt; a thermal or power limit lowers ``scaling_max_mhz`` (the hardware
#: maximum, ``cpuinfo_max_mhz``, is hashed instead).
_HASH_EXCLUDED_NIC_IRQ_FIELDS = ("affinity", "effective_affinity")
_HASH_EXCLUDED_CPU_FIELDS = ("scaling_max_mhz",)
#: Link state, hashed only for the NICs under test (``--nic``): an unused
#: port or the Wi-Fi card coming up does not change the system under test.
_HASH_LINK_STATE_FIELDS = ("operstate", "speed_mbps", "duplex")


def hash_input(record: dict[str, Json]) -> dict[str, Json]:
    """The part of ``record`` that :func:`sut_hash` covers."""
    host = copy.deepcopy(record["host"])
    if isinstance(host, dict):
        host.pop("hostname", None)
        host.pop("hostname_anonymised", None)
        cpu = host.get("cpu")
        core_types = cpu.get("core_types") if isinstance(cpu, dict) else None
        for core_type in core_types if isinstance(core_types, list) else []:
            if not isinstance(core_type, dict):
                continue
            for key in _HASH_EXCLUDED_CPU_FIELDS:
                core_type.pop(key, None)
                if isinstance(core_type.get("nonuniform_fields"), list):
                    core_type["nonuniform_fields"] = [
                        f for f in core_type["nonuniform_fields"] if f != key
                    ]
                if isinstance(core_type.get("variants"), dict):
                    core_type["variants"].pop(key, None)
    # The command line is hashed as recorded: its *hostname= values are
    # already <redacted>, and nothing else in it is rewritten. The hash then
    # depends on the recorded line only, never on the hostname (#21).
    os_section = copy.deepcopy(record["os"])
    nics: Json
    raw_nics = record.get("nics")
    if is_unavailable(raw_nics):
        nics = copy.deepcopy(raw_nics)
    else:
        nics = []
        for nic in raw_nics if isinstance(raw_nics, list) else []:
            if not isinstance(nic, dict) or nic.get("kind") != "physical":
                continue
            nic = copy.deepcopy(nic)
            under_test = nic.pop("under_test", False) is True
            if not under_test and isinstance(nic.get("link"), dict):
                for key in _HASH_LINK_STATE_FIELDS:
                    nic["link"].pop(key, None)
            if isinstance(nic.get("irqs"), list):
                for irq in nic["irqs"]:
                    if isinstance(irq, dict):
                        for key in _HASH_EXCLUDED_NIC_IRQ_FIELDS:
                            irq.pop(key, None)
            nics.append(nic)
    return {
        "schema_version": record.get("schema_version"),
        "host": host,
        "os": os_section,
        "nics": nics,
    }


def sut_hash(record: dict[str, Json]) -> str:
    """sha256 over the hardware and OS parts of ``record``, as ``sha256:<hex>``."""
    canonical = json.dumps(hash_input(record), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --- Walking a record --------------------------------------------------------


def iter_leaves(value: Json, path: str = "") -> Iterator[tuple[str, Json]]:
    """Every recorded field as ``(dotted path, value)``. A marker is one leaf."""
    if isinstance(value, dict) and not is_unavailable(value):
        for key, child in value.items():
            yield from iter_leaves(child, f"{path}.{key}" if path else str(key))
    elif (
        isinstance(value, list)
        and value
        and not all(isinstance(v, (str, int, float, bool)) for v in value)
    ):
        for i, child in enumerate(value):
            yield from iter_leaves(child, f"{path}[{i}]")
    else:
        yield path, value


def unavailable_fields(record: dict[str, Json]) -> list[tuple[str, str, str]]:
    """``(path, kind, reason)`` of every field recorded as unavailable."""
    return [
        (path, value["unavailable"], value["reason"])
        for path, value in iter_leaves(record)
        if is_unavailable(value)
    ]


def field_count(record: dict[str, Json]) -> int:
    return sum(1 for _ in iter_leaves(record))
