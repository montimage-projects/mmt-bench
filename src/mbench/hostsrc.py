"""Where the SUT collector reads the host from: live, recorded, or replayed.

:mod:`mbench.sut` never touches the filesystem or runs a command directly. It
goes through a :class:`Source`, so the same collector code runs

* live on the host (:class:`LiveSource`),
* live while recording every read and command (:class:`RecordingSource`), which
  is how the parser fixtures under ``tests/fixtures/`` are captured, and
* replayed from such a recording (:class:`SnapshotSource`), which is how the
  tests run on a CI runner that has never seen the benchmark host.

Every access is read-only. The only commands run are the inspection commands
listed in ``docs/sut-fingerprint.md`` (``lscpu``, ``ethtool -i/-k/-l/-g/-x``,
``lspci -s``, ``docker version``/``docker info``, ``systemctl show``,
``uname -m``, ``dmidecode`` only when already root, and, for the harness's own
commit, ``git --no-optional-locks rev-parse`` and
``git --no-optional-locks status --porcelain --untracked-files=no``); none of
them changes host state. ``--no-optional-locks`` (and ``GIT_OPTIONAL_LOCKS=0``
in every command's environment) stops ``git status`` from refreshing the index,
which would otherwise take ``.git/index.lock`` and rewrite ``.git/index``.
"""

from __future__ import annotations

import copy
import errno as errno_mod
import json
import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

#: Seconds a single inspection command may take before it is abandoned.
COMMAND_TIMEOUT = 10.0

SNAPSHOT_VERSION = 1


@dataclass(frozen=True)
class CommandResult:
    """What an inspection command returned."""

    returncode: int
    stdout: str
    stderr: str


class Source(Protocol):
    """Read-only access to a host: files, directories, links and commands."""

    def read(self, path: str) -> str:
        """The text of ``path``. Raises :class:`OSError` (errno set) on failure."""
        ...

    def listdir(self, path: str) -> list[str]:
        """The sorted entries of directory ``path``. Raises :class:`OSError`."""
        ...

    def realpath(self, path: str) -> str:
        """``path`` with every symlink resolved. Raises :class:`OSError`."""
        ...

    def run(self, argv: Sequence[str]) -> CommandResult:
        """Run an inspection command. Raises :class:`FileNotFoundError` if absent."""
        ...

    def sleep(self, seconds: float) -> None:
        """Wait (the replay source does not)."""
        ...

    def constants(self) -> dict[str, int]:
        """Host constants: ``euid``, ``page_size`` and ``clock_ticks``."""
        ...


class LiveSource:
    """The host this process runs on."""

    def read(self, path: str) -> str:
        return Path(path).read_text(encoding="utf-8", errors="replace")

    def listdir(self, path: str) -> list[str]:
        return sorted(os.listdir(path))

    def realpath(self, path: str) -> str:
        if not os.path.lexists(path):
            raise FileNotFoundError(errno_mod.ENOENT, os.strerror(errno_mod.ENOENT), path)
        return os.path.realpath(path)

    def run(self, argv: Sequence[str]) -> CommandResult:
        exe = shutil.which(argv[0])
        if exe is None:
            raise FileNotFoundError(errno_mod.ENOENT, f"command not found: {argv[0]}", argv[0])
        # GIT_OPTIONAL_LOCKS=0: git never writes the index of the checkout it
        # inspects (see the module docstring).
        env = {**os.environ, "LC_ALL": "C", "LANG": "C", "GIT_OPTIONAL_LOCKS": "0"}
        try:
            proc = subprocess.run(
                [exe, *argv[1:]],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=COMMAND_TIMEOUT,
                check=False,
                env=env,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", f"timed out after {COMMAND_TIMEOUT:g} s")
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def constants(self) -> dict[str, int]:
        return {
            "euid": os.geteuid(),
            "page_size": os.sysconf("SC_PAGE_SIZE"),
            "clock_ticks": os.sysconf("SC_CLK_TCK"),
        }


def _error_entry(exc: OSError) -> dict[str, Any]:
    return {"errno": exc.errno or errno_mod.EIO, "error": exc.strerror or str(exc)}


def _raise_entry(entry: dict[str, Any], path: str) -> None:
    code = int(entry["errno"])
    message = str(entry.get("error", os.strerror(code)))
    if code == errno_mod.ENOENT:
        raise FileNotFoundError(code, message, path)
    if code in {errno_mod.EACCES, errno_mod.EPERM}:
        raise PermissionError(code, message, path)
    raise OSError(code, message, path)


class RecordingSource:
    """A :class:`LiveSource` that remembers every answer, for fixture capture.

    A path read twice (``/proc/loadavg`` before and after, a process ``stat``
    file in each sample) keeps every answer in order, so a replay gives the
    collector the same sequence.
    """

    def __init__(self, inner: Source | None = None) -> None:
        self.inner: Source = inner if inner is not None else LiveSource()
        self.files: dict[str, list[Any]] = {}
        self.dirs: dict[str, list[Any]] = {}
        self.links: dict[str, Any] = {}
        self.commands: dict[str, list[Any]] = {}
        self._constants: dict[str, int] | None = None

    def read(self, path: str) -> str:
        try:
            text = self.inner.read(path)
        except OSError as exc:
            self.files.setdefault(path, []).append(_error_entry(exc))
            raise
        self.files.setdefault(path, []).append(text)
        return text

    def listdir(self, path: str) -> list[str]:
        try:
            entries = self.inner.listdir(path)
        except OSError as exc:
            self.dirs.setdefault(path, []).append(_error_entry(exc))
            raise
        self.dirs.setdefault(path, []).append(list(entries))
        return entries

    def realpath(self, path: str) -> str:
        try:
            target = self.inner.realpath(path)
        except OSError as exc:
            self.links[path] = _error_entry(exc)
            raise
        self.links[path] = target
        return target

    def run(self, argv: Sequence[str]) -> CommandResult:
        key = command_key(argv)
        try:
            result = self.inner.run(argv)
        except OSError as exc:
            self.commands.setdefault(key, []).append(_error_entry(exc))
            raise
        self.commands.setdefault(key, []).append(
            {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        )
        return result

    def sleep(self, seconds: float) -> None:
        self.inner.sleep(seconds)

    def constants(self) -> dict[str, int]:
        if self._constants is None:
            self._constants = self.inner.constants()
        return dict(self._constants)

    def snapshot(self) -> dict[str, Any]:
        """Everything recorded so far, in the :class:`SnapshotSource` format."""
        return {
            "snapshot_version": SNAPSHOT_VERSION,
            "constants": self.constants(),
            "files": copy.deepcopy(self.files),
            "dirs": copy.deepcopy(self.dirs),
            "links": copy.deepcopy(self.links),
            "commands": copy.deepcopy(self.commands),
        }


def command_key(argv: Sequence[str]) -> str:
    """The snapshot key of a command: its arguments, JSON-encoded."""
    return json.dumps(list(argv))


class SnapshotSource:
    """Replays a recorded snapshot. Anything not recorded does not exist."""

    def __init__(self, data: dict[str, Any]) -> None:
        if data.get("snapshot_version") != SNAPSHOT_VERSION:
            raise ValueError(f"unsupported snapshot version: {data.get('snapshot_version')!r}")
        self._data = data
        self._cursor: dict[tuple[str, str], int] = {}

    @classmethod
    def load(cls, path: str | Path) -> SnapshotSource:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def _next(self, kind: str, key: str) -> Any:
        answers = self._data.get(kind, {}).get(key)
        if answers is None:
            return None
        i = self._cursor.get((kind, key), 0)
        self._cursor[(kind, key)] = i + 1
        return answers[min(i, len(answers) - 1)]

    def read(self, path: str) -> str:
        entry = self._next("files", path)
        if entry is None:
            raise FileNotFoundError(errno_mod.ENOENT, "not in snapshot", path)
        if isinstance(entry, dict):
            _raise_entry(entry, path)
        return str(entry)

    def listdir(self, path: str) -> list[str]:
        entry = self._next("dirs", path)
        if entry is None:
            raise FileNotFoundError(errno_mod.ENOENT, "not in snapshot", path)
        if isinstance(entry, dict):
            _raise_entry(entry, path)
        return [str(e) for e in entry]

    def realpath(self, path: str) -> str:
        entry = self._data.get("links", {}).get(path)
        if entry is None:
            raise FileNotFoundError(errno_mod.ENOENT, "not in snapshot", path)
        if isinstance(entry, dict):
            _raise_entry(entry, path)
        return str(entry)

    def run(self, argv: Sequence[str]) -> CommandResult:
        key = command_key(argv)
        entry = self._next("commands", key)
        if entry is None:
            raise FileNotFoundError(errno_mod.ENOENT, f"command not found: {argv[0]}", argv[0])
        if "errno" in entry:
            _raise_entry(entry, argv[0])
        return CommandResult(int(entry["returncode"]), entry["stdout"], entry["stderr"])

    def sleep(self, seconds: float) -> None:
        return None

    def constants(self) -> dict[str, int]:
        return {k: int(v) for k, v in self._data["constants"].items()}


# --- Sanitising a snapshot before it is committed -----------------------------

_MAC = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
_LONG_HEX = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){6,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
#: Dash-separated MACs (``aa-bb-cc-dd-ee-ff``), with or without the ``01-``
#: hardware-type prefix of a PXE ``BOOTIF=`` value.
_DASH_MAC = re.compile(r"(?<![0-9A-Fa-f-])(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f-])")
_DASH_LONG_HEX = re.compile(
    r"(?<![0-9A-Fa-f-])(?:[0-9A-Fa-f]{2}-){6,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f-])"
)
_UUID = re.compile(
    r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"
)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_H = "[0-9A-Fa-f]{1,4}"
#: Full and ``::``-compressed IPv6 addresses. A compressed one needs a group
#: after the ``::``, so the cgroup ``0::/path`` line and PCI addresses
#: (``0000:01:00.0``) are left alone.
_IPV6 = re.compile(
    rf"(?<![0-9A-Fa-f:\w])(?:(?:{_H}:){{7}}{_H}"
    rf"|(?:{_H}:){{0,6}}:{_H}(?::{_H}){{0,5}})(?![0-9A-Fa-f:.\w])"
)

#: Documentation values: a locally administered MAC, and the RFC 5737 and
#: RFC 3849 documentation prefixes.
DOC_MAC = "02:00:00:00:00:01"
DOC_DASH_MAC = DOC_MAC.replace(":", "-")
DOC_IPV4 = "192.0.2.1"
DOC_IPV6 = "2001:db8::1"
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def sanitise_text(text: str, hostname: str | None, alias: str) -> str:
    """Strip host identity from captured text.

    Replaces the hostname with ``alias``, case-insensitively (RFC 1123
    hostnames are case-insensitive), where it appears as a whole label —
    a ``hostname=`` or ``ip=`` value, a bare token, or one label of a
    dotted name — and swallows a following dotted tail, so
    ``myhost.example.lan`` becomes the alias (the domain is hidden too)
    and ``iqn.2003-01.org.myhost:`` becomes ``iqn.2003-01.org.<alias>:``.
    A trailing dot is not part of the name and does not shield it:
    ``myhost.example.lan.`` becomes ``<alias>.``. A dash- or word-joined
    occurrence is kept as captured: a device path like
    ``ubuntu--vg-ubuntu--lv`` or a version string like ``6.8.0-ubuntu``
    cannot be told from the hostname (#21). When the recorded hostname is
    an FQDN, its first label is rewritten too, so a bare ``myhost`` in
    ``ip=::::myhost:eth0`` does not survive — except when the first
    label is all digits (an IPv4 hostname included): ``10.0.0.9`` must
    not also eat every standalone ``10``. MAC
    addresses (colon- or dash-separated) become a documentation MAC,
    longer colon- or dash-hex strings (RSS hash keys, ``BOOTIF=01-...``)
    become zeros, UUIDs (filesystem, daemon and cgroup scope ids) become
    the nil UUID, IPv4 addresses a documentation address, and IPv6
    addresses a documentation address.
    """
    if hostname:
        short = hostname.partition(".")[0]
        names = {hostname}
        if short and short != hostname and not short.isdigit():
            names.add(short)
        pattern = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
        text = re.sub(
            rf"(?<![\w-])(?:{pattern})(?:\.[\w-]+)*(?![\w-])(?!\.[\w-])",
            lambda m: alias,
            text,
            flags=re.IGNORECASE,
        )
    text = _LONG_HEX.sub(lambda m: ":".join("00" for _ in m.group(0).split(":")), text)
    text = _MAC.sub(DOC_MAC, text)
    text = _DASH_LONG_HEX.sub(lambda m: "-".join("00" for _ in m.group(0).split("-")), text)
    text = _DASH_MAC.sub(DOC_DASH_MAC, text)
    text = _UUID.sub(ZERO_UUID, text)
    text = _IPV6.sub(DOC_IPV6, text)
    return _IPV4.sub(DOC_IPV4, text)


def _map_strings(value: Any, fn: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, list):
        return [_map_strings(v, fn) for v in value]
    if isinstance(value, dict):
        return {fn(k): _map_strings(v, fn) for k, v in value.items()}
    return value


#: ``docker info`` fields the collector reads. Everything else (daemon id,
#: proxies, registry CIDRs, labels) is dropped from a recorded snapshot.
DOCKER_INFO_KEYS = (
    "ServerVersion",
    "CgroupVersion",
    "CgroupDriver",
    "Driver",
    "DefaultRuntime",
    "Runtimes",
    "NCPU",
    "MemTotal",
    "ContainersRunning",
    "CPUSet",
    "CPUShares",
    "CpuCfsPeriod",
    "CpuCfsQuota",
    "MemoryLimit",
    "SwapLimit",
    "SecurityOptions",
    "Isolation",
)


def _trim_docker_info(stdout: str) -> str:
    try:
        info = json.loads(stdout)
    except ValueError:
        return stdout
    if not isinstance(info, dict):
        return stdout
    kept = {k: info[k] for k in DOCKER_INFO_KEYS if k in info}
    if isinstance(kept.get("Runtimes"), dict):
        kept["Runtimes"] = {name: {} for name in kept["Runtimes"]}
    return json.dumps(kept, sort_keys=True)


#: ``dmidecode -t 17`` fields :func:`mbench.sut.parse_dmidecode_memory` reads.
#: A recorded answer keeps only these and the ``Memory Device`` headers: the
#: serial number, asset tag, part number and locator of each DIMM are dropped.
DMIDECODE_MEMORY_KEYS = ("Size", "Type", "Speed", "Configured Memory Speed")

#: ``/proc/cpuinfo`` fields dropped from a recorded snapshot: the board serial
#: number some Arm kernels print (``Serial : 00000000abcdef01``).
CPUINFO_DROPPED_KEYS = frozenset({"serial"})


def reduce_dmidecode_memory(stdout: str) -> str:
    """``dmidecode -t 17`` output cut to what the parser reads."""
    kept: list[str] = []
    for line in stdout.splitlines():
        if line.strip() == "Memory Device":
            kept.append("Memory Device")
        elif line.startswith("\t") and line.strip().partition(":")[0] in DMIDECODE_MEMORY_KEYS:
            kept.append("\t" + line.strip())
    return "".join(f"{line}\n" for line in kept)


def strip_cpuinfo(text: str) -> str:
    """``/proc/cpuinfo`` without :data:`CPUINFO_DROPPED_KEYS` lines."""
    return "".join(
        line
        for line in text.splitlines(keepends=True)
        if line.partition(":")[0].strip().lower() not in CPUINFO_DROPPED_KEYS
    )


_PID_PATH = re.compile(r"^/proc/(\d+)(/|$)")


_NET_PATH = re.compile(r"^/sys/class/net/([^/]+)(/|$)")

#: The trees the collector reads. A recorded path anywhere else (the mbench
#: checkout, resolved for its git commit) names a user's directory: dropped.
_SYSTEM_TREES = ("/proc", "/sys", "/etc", "/usr/lib")


def _system_path(path: str) -> bool:
    return any(path == tree or path.startswith(f"{tree}/") for tree in _SYSTEM_TREES)


def sanitise_snapshot(
    data: dict[str, Any],
    hostname: str | None,
    alias: str,
    keep_pids: set[int],
    keep_nics: set[str],
) -> dict[str, Any]:
    """A copy of ``data`` that is safe to commit as a test fixture.

    Process files are kept only for ``keep_pids`` (the processes the record
    lists) and interface files only for ``keep_nics`` (the NICs it records);
    the ``/proc`` and ``/sys/class/net`` listings are cut down to match, so a
    replay gives the same record without naming other processes, bridges or
    tunnels. ``docker info`` is cut to :data:`DOCKER_INFO_KEYS`, ``dmidecode``
    to :data:`DMIDECODE_MEMORY_KEYS`, and ``/proc/cpuinfo`` loses its
    ``Serial`` line. ``git`` answers, and every path outside
    :data:`_SYSTEM_TREES`, are dropped: they hold the path of the mbench
    checkout, and the replay takes the harness from its options.
    """
    data = copy.deepcopy(data)

    def keep(path: str) -> bool:
        if not _system_path(path):
            return False
        pid = _PID_PATH.match(path)
        if pid is not None:
            return int(pid.group(1)) in keep_pids
        nic = _NET_PATH.match(path)
        return nic is None or nic.group(1) in keep_nics

    def cut(listing: list[Any], wanted: Callable[[str], bool]) -> list[Any]:
        return [e if isinstance(e, dict) else [x for x in e if wanted(x)] for e in listing]

    data["files"] = {p: v for p, v in data["files"].items() if keep(p)}
    data["dirs"] = {p: v for p, v in data["dirs"].items() if keep(p)}
    data["links"] = {p: v for p, v in data["links"].items() if keep(p)}
    if "/proc" in data["dirs"]:
        data["dirs"]["/proc"] = cut(
            data["dirs"]["/proc"], lambda x: not x.isdigit() or int(x) in keep_pids
        )
    if "/sys/class/net" in data["dirs"]:
        data["dirs"]["/sys/class/net"] = cut(data["dirs"]["/sys/class/net"], keep_nics.__contains__)
    if "/proc/cpuinfo" in data["files"]:
        data["files"]["/proc/cpuinfo"] = [
            strip_cpuinfo(a) if isinstance(a, str) else a for a in data["files"]["/proc/cpuinfo"]
        ]

    def kept_command(argv: list[str]) -> bool:
        if argv[0] == "git":
            return False
        return not (argv[0] == "ethtool" and argv[-1] not in keep_nics)

    data["commands"] = {k: v for k, v in data["commands"].items() if kept_command(json.loads(k))}
    for key, answers in data["commands"].items():
        argv = json.loads(key)
        trim: Callable[[str], str] | None = None
        if argv[:2] == ["docker", "info"]:
            trim = _trim_docker_info
        elif argv[0] == "dmidecode":
            trim = reduce_dmidecode_memory
        if trim is None:
            continue
        for answer in answers:
            if "stdout" in answer:
                answer["stdout"] = trim(answer["stdout"])
    return {
        k: _map_strings(v, lambda s: sanitise_text(s, hostname, alias)) for k, v in data.items()
    }
