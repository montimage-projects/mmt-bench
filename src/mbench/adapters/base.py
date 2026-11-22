"""The Adapter interface (plan §B3), the normalised alert model and the tools record.

Every tool under test (mmt-probe, Suricata, Snort 3) is driven through one
:class:`Adapter`. Its members are those of plan §B3:

- :attr:`Adapter.name`, :meth:`Adapter.version` and :attr:`Adapter.image`
  (the image reference and digest);
- :meth:`Adapter.prepare` writes the tool's config files for a rule set and a
  config profile;
- :meth:`Adapter.run_offline` and :meth:`Adapter.run_online` start the tool and
  return a :class:`ProcessHandle`;
- :meth:`Adapter.counters` reads the tool's own stats (:class:`Counters`);
- :meth:`Adapter.alerts` returns its alerts as normalised :class:`Alert`\\ s, so
  ``truth.py`` scores every tool the same way;
- :meth:`Adapter.rule_inventory` lists the rules of a rule set
  (:class:`RuleInfo`);

plus :meth:`Adapter.tools_record`, the "tools under test" record (plan §B4)
that the runner (#8) embeds in each run's sut.json. :func:`tools_record_errors`
checks it against the ``tools`` section of the committed sut.json schema (#4).
"""

from __future__ import annotations

import abc
import hashlib
import ipaddress
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Protocol, runtime_checkable

from jsonschema import Draft202012Validator

from mbench import sut

Json = Any

#: A protocol name: lowercase, as the tools and ``/etc/protocols`` spell it
#: (``tcp``, ``udp``, ``icmp``, ``sctp``, ``http``, ``ngap``...).
PROTO_PATTERN = re.compile(r"^[a-z][a-z0-9_.+-]*$")

#: The config profiles of the fair-comparison rule (docs/methodology.md).
CONFIG_PROFILES = ("recommended", "tuned")

#: An image digest, as the sut.json schema spells it.
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class InvalidValue(ValueError):
    """A value that does not fit the normalised model, naming the field."""


def _text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise InvalidValue(f"{name}: must be a non-empty string without surrounding spaces")
    return value


def _number(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InvalidValue(f"{name}: must be a number, not {type(value).__name__}")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise InvalidValue(f"{name}: must be a finite number >= 0, not {value!r}")
    return number


def _count(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidValue(f"{name}: must be an integer >= 0, not {value!r}")
    return value


def normalise_address(name: str, value: object) -> str:
    """An IPv4 or IPv6 address in its canonical text form."""
    if not isinstance(value, str):
        raise InvalidValue(f"{name}: must be an IP address string, not {type(value).__name__}")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise InvalidValue(f"{name}: not an IP address: {value!r}") from None


def normalise_proto(name: str, value: object) -> str:
    """A protocol name, lowercased."""
    if not isinstance(value, str) or not PROTO_PATTERN.match(value.lower()):
        raise InvalidValue(f"{name}: not a protocol name: {value!r}")
    return value.lower()


# --- The normalised alert ----------------------------------------------------


@dataclass(frozen=True)
class Alert:
    """One alert, in the form every adapter normalises its tool's alerts to.

    - ``ts``: when the attack was seen, in seconds since the epoch, in the
      packets' time (the pcap's timestamps offline), not the wall clock;
    - ``rule_id``: the tool's own id of the rule that fired;
    - ``category``: the tool's category for the rule (free text, kept as given);
    - ``src`` and ``dst``: the IP addresses of the packet or flow the alert is
      about, canonicalised (``2001:DB8::1`` becomes ``2001:db8::1``);
    - ``proto``: the protocol the rule matched on, lowercased.

    Construction rejects an invalid value with :class:`InvalidValue`.
    """

    ts: float
    rule_id: str
    category: str
    src: str
    dst: str
    proto: str

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "ts", _number("ts", self.ts))
        set_(self, "rule_id", _text("rule_id", self.rule_id))
        set_(self, "category", _text("category", self.category))
        set_(self, "src", normalise_address("src", self.src))
        set_(self, "dst", normalise_address("dst", self.dst))
        set_(self, "proto", normalise_proto("proto", self.proto))

    FIELDS: ClassVar[tuple[str, ...]] = ("ts", "rule_id", "category", "src", "dst", "proto")

    @classmethod
    def from_dict(cls, data: Mapping[str, Json]) -> Alert:
        """An alert from its JSON form; unknown or missing fields are rejected."""
        if not isinstance(data, Mapping):
            raise InvalidValue(f"alert: must be an object, not {type(data).__name__}")
        missing = [f for f in cls.FIELDS if f not in data]
        extra = sorted(set(data) - set(cls.FIELDS))
        if missing:
            raise InvalidValue(f"alert: missing field: {', '.join(missing)}")
        if extra:
            raise InvalidValue(f"alert: unknown field: {', '.join(extra)}")
        return cls(**{f: data[f] for f in cls.FIELDS})

    def to_dict(self) -> dict[str, Json]:
        return {f: getattr(self, f) for f in self.FIELDS}


# --- Counters, rules, rule sets ------------------------------------------------


@dataclass(frozen=True)
class Counters:
    """What the tool says it processed, from its own stats output.

    ``drops`` are the packets the tool itself dropped; the kernel's drops
    (``rx_dropped``, ``rx_missed``) are read by the online mode (#13), not here.
    ``extra`` holds any other counter the tool reports, by its own name.
    """

    packets: int
    bytes: int
    drops: int
    extra: Mapping[str, int | float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("packets", "bytes", "drops"):
            _count(name, getattr(self, name))
        for key, value in self.extra.items():
            _text("extra key", key)
            if key in {"packets", "bytes", "drops"}:
                raise InvalidValue(f"extra.{key}: shadows a main counter")
            _number(f"extra.{key}", value)
        object.__setattr__(self, "extra", dict(self.extra))

    def to_dict(self) -> dict[str, Json]:
        return {"packets": self.packets, "bytes": self.bytes, "drops": self.drops, **self.extra}


@dataclass(frozen=True)
class RuleInfo:
    """One rule of a rule set, as :meth:`Adapter.rule_inventory` lists it.

    ``layer`` is the layer table of plan P2 (``L2/3``, ``L4``, ``L7-web``...),
    ``protocols`` the protocols the rule reads, and ``stateful`` whether it
    correlates several events (a temporal rule) rather than one packet.
    """

    id: str
    category: str
    layer: str
    protocols: tuple[str, ...]
    stateful: bool

    def __post_init__(self) -> None:
        _text("id", self.id)
        _text("category", self.category)
        _text("layer", self.layer)
        if isinstance(self.protocols, str) or not isinstance(self.protocols, Sequence):
            raise InvalidValue("protocols: must be a list of protocol names")
        protocols = tuple(normalise_proto("protocols", p) for p in self.protocols)
        object.__setattr__(self, "protocols", protocols)
        if not isinstance(self.stateful, bool):
            raise InvalidValue("stateful: must be true or false")

    def to_dict(self) -> dict[str, Json]:
        return {
            "id": self.id,
            "category": self.category,
            "layer": self.layer,
            "protocols": list(self.protocols),
            "stateful": self.stateful,
        }


@dataclass(frozen=True)
class Ruleset:
    """A rule set under ``rulesets/``: its id and the file or directory holding it.

    ``security`` is the tool's own meaning of "the engine is on" — for
    mmt-probe it is the ``security.enable`` the generated config writes (R0
    is a run with the engine off, R0b a run with the engine on and no rules
    to match). ``allow_empty`` marks a rule set that legitimately holds zero
    ``.so`` files, so the adapter's "no rule staged" guard still catches a
    silently missing extraction everywhere else.
    """

    id: str
    path: Path
    security: bool = True
    allow_empty: bool = False

    def __post_init__(self) -> None:
        _text("id", self.id)

    def sha256(self) -> str:
        """The rule set's hash, as :func:`tree_sha256` computes it."""
        return tree_sha256(self.path)


@dataclass(frozen=True)
class ImageRef:
    """A container image, by reference and by ``sha256:`` digest (plan §B1)."""

    ref: str
    digest: str

    def __post_init__(self) -> None:
        _text("ref", self.ref)
        if not isinstance(self.digest, str) or not DIGEST_PATTERN.match(self.digest):
            raise InvalidValue(f"digest: not a sha256:<64 hex> digest: {self.digest!r}")

    def to_dict(self) -> dict[str, Json]:
        return {"ref": self.ref, "digest": self.digest}


# --- Hashes for the tools record ----------------------------------------------


def tree_sha256(path: Path) -> str:
    """The sha256 of a file, or of a directory's files.

    For a directory it is the sha256 of one line per regular file, sorted by
    relative path: ``<sha256 of the file>  <relative path>\\n``, the output of
    ``find . -type f | sort | xargs sha256sum`` with the ``./`` removed. So a
    renamed, added or changed rule file changes the hash.
    """
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if not path.is_dir():
        raise FileNotFoundError(f"no such file or directory: {path}")
    lines = []
    for item in sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = item.relative_to(path).as_posix()
        lines.append(f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {rel}\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def config_record(files: Sequence[Path], root: Path) -> dict[str, Json]:
    """The ``config`` part of a tools record: the full config and its hash.

    ``content`` is every config file in order, each after a
    ``# mbench-config-file: <path relative to root>`` line, so a tool with
    several config files is recorded whole; ``sha256`` is the sha256 of
    ``content`` (UTF-8), so anyone can check it from the record alone. The
    files are named relative to ``root`` (the run's workdir), so no host path
    gets into the record.
    """
    if not files:
        raise ValueError("config_record: no config file")
    parts = []
    for f in files:
        path = f if f.is_absolute() else root / f
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        parts.append(f"# mbench-config-file: {rel}\n{text}")
        if not text.endswith("\n"):
            parts.append("\n")
    content = "".join(parts)
    return {"sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(), "content": content}


# --- The process handle -------------------------------------------------------


@runtime_checkable
class ProcessHandle(Protocol):
    """A started tool. :class:`subprocess.Popen` is one.

    ``wait`` raises :class:`subprocess.TimeoutExpired` when ``timeout`` passes,
    so the runner (#8) can kill a run that exceeds its cap.
    """

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


# --- The adapter --------------------------------------------------------------


class Adapter(abc.ABC):
    """One tool under test, behind the members of plan §B3.

    Every member is abstract: a subclass that misses one cannot be
    instantiated. A member that does not apply yet still has to be written,
    and raises :class:`NotImplementedError` naming the issue or phase that
    adds it (``run_online`` of the mmt-probe adapter until P4).

    The calls of one run come in order: :meth:`prepare`, then
    :meth:`run_offline` or :meth:`run_online`, and once the process has
    exited :meth:`counters` and :meth:`alerts`, which read that run's output.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The tool's name, as results and reports show it (``mmt-probe``)."""

    @abc.abstractmethod
    def version(self) -> str | sut.Marker:
        """The tool's version string, or an unavailable marker with the reason."""

    @property
    @abc.abstractmethod
    def image(self) -> ImageRef | sut.Marker:
        """The image the tool runs from, pinned by digest, or a marker."""

    @abc.abstractmethod
    def prepare(self, ruleset: Ruleset, config_profile: str, workdir: Path) -> list[Path]:
        """Write the tool's config for ``ruleset`` and ``config_profile`` under ``workdir``.

        Returns the config files written, in the order the tool reads them.
        ``config_profile`` is one of :data:`CONFIG_PROFILES`.
        """

    @abc.abstractmethod
    def run_offline(self, pcap: Path, threads: int, cpuset: Sequence[int]) -> ProcessHandle:
        """Start the tool on ``pcap`` with ``threads`` threads, pinned to ``cpuset``."""

    @abc.abstractmethod
    def run_online(self, iface: str, threads: int, cpuset: Sequence[int]) -> ProcessHandle:
        """Start the tool on the live interface ``iface`` (a veth end, P4)."""

    @abc.abstractmethod
    def container_limits(self, cpuset: Sequence[int]) -> dict[str, Json]:
        """The cgroup limits a run pinned to ``cpuset`` is started with.

        The ``{cpu_max, memory_max, cpuset_cpus}`` record (the cgroup v2
        ``cpu.max``, ``memory.max`` and ``cpuset.cpus.effective`` contents) of
        the run's container, as the runner (#8) embeds it in the run's
        sut.json at ``container_runtime.limits.per_run``. A containerised
        adapter reads them inside a scratch container, so the record shows
        what the tool actually got, not what was requested.
        """

    @abc.abstractmethod
    def counters(self) -> Counters:
        """The last run's counters, from the tool's own stats output."""

    @abc.abstractmethod
    def alerts(self) -> list[Alert]:
        """The last run's alerts, normalised."""

    @abc.abstractmethod
    def rule_inventory(self, ruleset: Ruleset) -> list[RuleInfo]:
        """The rules of ``ruleset``: id, category, layer, protocols, stateful."""

    @abc.abstractmethod
    def tools_record(self) -> dict[str, Json]:
        """The tools-under-test record of the prepared run (plan §B4).

        One item of sut.json's ``tools`` array: ``name``, ``version``,
        ``image``, ``version_strings``, ``build_flags``, ``ruleset`` (id and
        sha256) and ``config`` (see :func:`config_record`). It must pass
        :func:`tools_record_errors`.
        """


# --- Validation of the tools record against the sut.json schema ---------------


def _tools_item_schema() -> dict[str, Json]:
    from mbench import validate

    root = validate.schema()
    # The tools item schema (identical in the base ``properties`` and the
    # run-scope ``allOf → then`` branch).
    tools = root["properties"]["tools"]["anyOf"][0]
    return {
        "$schema": root["$schema"],
        "$defs": root["$defs"],
        **tools["items"],
    }


def tools_record_errors(record: Json) -> list[str]:
    """Every reason ``record`` is not a valid item of sut.json's ``tools``; empty if valid.

    The check is the committed sut.json schema's own (#4), so a record that
    passes here passes ``mbench validate`` once embedded in a run.
    """
    from mbench import validate

    validator = Draft202012Validator(_tools_item_schema())
    return sorted(
        {
            validate.describe(leaf)
            for error in validator.iter_errors(record)
            for leaf in validate._leaf_errors(error)
        }
    )
