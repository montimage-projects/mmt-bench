"""The mmt-probe adapter (plan §B3), offline mode (#6).

The tool under test is mmt-probe with mmt-dpi and mmt-security, running in
the image built by ``tools/docker/mmt-probe/`` (all sources pinned, see its
README). The image is referenced by digest: ``name@sha256:...``, or the image
id the daemon reports for a built tag.

- :meth:`MmtProbeAdapter.prepare` writes ``mmt-probe.conf`` for a config
  profile and stages the ruleset's ``.so`` files under the run's workdir;
- :meth:`MmtProbeAdapter.run_offline` starts ``docker run --rm`` with an
  ``mbench-`` prefixed name, ``--network none``, the workdir, the pcap and
  the staged rules mounted read-only where they are inputs;
- :meth:`MmtProbeAdapter.counters` sums the session (100) and protocol (99)
  reports — the volumes the tool itself reports — and reads the probe's
  status line for processed/dropped packets;
- :meth:`MmtProbeAdapter.alerts` turns the STIX bundles (and legacy ``[10]``
  reports of a non-STIX build) into normalised :class:`Alert`\\ s;
- :meth:`MmtProbeAdapter.run_online` waits for P4.

The adapter starts, stops and mounts only its own ``mbench-`` containers and
its own workdir; it never touches other containers or data dirs.
"""

from __future__ import annotations

import json
import secrets
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Protocol, runtime_checkable

from mbench import sut
from mbench.adapters.base import (
    CONFIG_PROFILES,
    DIGEST_PATTERN,
    Adapter,
    Alert,
    Counters,
    ImageRef,
    InvalidValue,
    Json,
    ProcessHandle,
    RuleInfo,
    Ruleset,
    config_record,
)

#: Every container this adapter starts is named with this prefix, so a bench
#: run can never touch the production ``mmt-*`` containers.
CONTAINER_PREFIX = "mbench-"

#: The image the adapter uses by default; built by tools/docker/mmt-probe/.
DEFAULT_IMAGE = "mmt-bench/mmt-probe:local"

#: The build context of the probe image, relative to the repo root
#: (src/mbench/adapters/mmt_probe.py -> parents[3] is the repo root).
BUILD_CONTEXT = Path(__file__).resolve().parents[3] / "tools" / "docker" / "mmt-probe"

#: Inside the image: mmt-security's check captures and expected alerts,
#: copied at build time for the integration test.
IMAGE_CHECK_DIR = "/opt/mmt/check"

#: Inside the container: where the workdir, the pcap and the staged rules go.
WORKDIR_MOUNT = "/data"
PCAP_MOUNT = "/pcap"
RULES_MOUNT = "/opt/mmt/security/rules"

#: The probe's own stats reports, by report id (docs/data-format.md).
_REPORT_STATUS = 200
_REPORT_PROTO_NO_SESSION = 99
_REPORT_SESSION = 100
_REPORT_SECURITY = 10

#: Index of the volume fields inside a report's JSON array (0-based).
_SESSION_DATA_VOLUME = 9
_SESSION_PACKET_COUNT = 11
_PROTO_DATA_VOLUME = 8
_PROTO_PACKET_COUNT = 10

#: The probe's end-of-run status line: "MMT processed N packets, dropped D
#: packets (x%), generated A alerts". In offline mode the periodic status
#: report (200) rarely fires, so this line is the drop counter's source.
_STATUS_LINE = "MMT processed "

#: The protocols a rule's variables may use, most specific first. A STIX
#: bundle does not carry the trace attribute names, so an alert's ``proto``
#: is derived from the rule's protocol list: the first of these present.
#: (``tcp`` before ``http``: an alert about a TCP flow is normalised as tcp.)
_PROTO_PREFERENCE = ("tcp", "udp", "sctp", "icmp", "icmpv6", "arp", "gre")

#: Protocol names -> the layer of the plan's layer table (§B7).
_LAYER_5G = frozenset({"ngap", "nas", "s1ap", "gtp", "gtpv2", "diameter", "sgap"})
_LAYER_DICOM = frozenset({"dicom"})
_LAYER_WEB = frozenset(
    {
        "http",
        "https",
        "ssl",
        "tls",
        "ftp",
        "tftp",
        "smtp",
        "imap",
        "pop3",
        "dns",
        "ssh",
        "telnet",
        "rtsp",
        "rtp",
        "sip",
        "ldap",
        "radius",
        "dnp3",
        "ocpp",
        "mqtt",
        "modbus",
        "iec104",
        "smb",
        "rdp",
        "snmp",
        "dhcp",
        "ntp",
        "ssdp",
        "mdns",
        "websocket",
        "quic",
    }
)
_LAYER_L4 = frozenset({"tcp", "udp", "sctp", "icmp", "icmpv6"})


@runtime_checkable
class Docker(Protocol):
    """The docker calls the adapter needs; a test substitutes a fake.

    ``run`` executes a one-shot command and returns the completed process;
    ``spawn`` starts a long-running ``docker run`` and returns its handle.
    Every ``docker run`` the adapter issues carries ``--rm`` and an
    ``mbench-`` prefixed ``--name``.
    """

    def run(
        self, argv: Sequence[str], timeout: float | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        """Run ``docker argv`` to completion; returns the completed process."""

    def spawn(self, argv: Sequence[str], stdout: BinaryIO) -> subprocess.Popen[bytes]:
        """Start ``docker argv`` without waiting; returns the client process."""


class CliDocker:
    """The real :class:`Docker`, shelling out to the ``docker`` CLI."""

    def __init__(self, exe: str = "docker") -> None:
        self.exe = exe

    def run(
        self, argv: Sequence[str], timeout: float | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [self.exe, *argv],
            capture_output=True,
            timeout=timeout if timeout is not None else 300,
            check=False,
        )

    def spawn(self, argv: Sequence[str], stdout: BinaryIO) -> subprocess.Popen[bytes]:
        return subprocess.Popen([self.exe, *argv], stdout=stdout, stderr=subprocess.STDOUT)


def parse_image_ref(ref: str, docker: Docker | None = None) -> ImageRef:
    """An image reference pinned by digest (plan §B1).

    ``name[@tag]@sha256:<digest>`` gives the digest directly; a tag-only
    reference (``name:tag``) resolves to the daemon's image id — that needs a
    running daemon, and without one the reference is refused: a tag is
    mutable, so a tools record that only says ``name:tag`` cannot prove what
    ran. The returned :class:`ImageRef` keeps the full reference, so
    ``docker run`` starts exactly the pinned image.
    """
    if "@" in ref:
        name, _, digest = ref.rpartition("@")
        return ImageRef(f"{name}@{digest}", digest)
    if docker is None:
        raise InvalidValue(
            f"image: {ref!r} is a tag-only reference; pin it by digest (name@sha256:...) "
            "or let the daemon resolve it"
        )
    found = docker.run(["image", "inspect", "-f", "{{.Id}}", ref], timeout=60)
    digest = found.stdout.decode("utf-8", "replace").strip()
    if found.returncode != 0 or not DIGEST_PATTERN.match(digest):
        raise InvalidValue(
            f"image: {ref!r} is a tag-only reference and the daemon did not return "
            f"a sha256 digest for it (rc={found.returncode}); build it with "
            "tools/docker/mmt-probe first"
        )
    return ImageRef(ref, digest)


@dataclass
class _Container:
    """A ``docker run --rm`` process, as a :class:`ProcessHandle`.

    ``kill`` kills the *container* by name (``docker kill`` — always an
    ``mbench-`` name, never another container), since killing the client
    leaves the container running.
    """

    proc: subprocess.Popen[bytes]
    docker: Docker
    name: str
    _log: BinaryIO | None = field(default=None, repr=False)

    def poll(self) -> int | None:
        return self.proc.poll()

    def wait(self, timeout: float | None = None) -> int:
        try:
            return self.proc.wait(timeout)
        finally:
            if self.proc.poll() is not None and self._log is not None:
                self._log.close()
                self._log = None

    def kill(self) -> None:
        self.docker.run(["kill", self.name], timeout=30)
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        if self._log is not None:
            self._log.close()
            self._log = None


def _container_name(purpose: str) -> str:
    return f"{CONTAINER_PREFIX}mmt-probe-{purpose}-{secrets.token_hex(4)}"


def _iso_seconds(text: str) -> float:
    """A STIX ISO-8601 timestamp (``2017-02-01T15:37:10.640075Z``) as epoch seconds."""
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC).timestamp()


def _report_values(path: Path) -> Iterator[Json]:
    """Every JSON value of one report file.

    The probe writes one JSON array per line for the numeric reports and one
    ``[{...}]`` multi-line bundle per alert; a stray non-JSON line is skipped
    rather than aborting the whole file.
    """
    decoder = json.JSONDecoder()
    buf = path.read_text(encoding="utf-8", errors="replace")
    i = 0
    while i < len(buf):
        while i < len(buf) and buf[i] in " \t\r\n":
            i += 1
        if i >= len(buf):
            break
        try:
            value, i = decoder.raw_decode(buf, i)
        except json.JSONDecodeError:
            nl = buf.find("\n", i)
            i = len(buf) if nl < 0 else nl + 1
            continue
        yield value


def _pick_protocol(protocols: Sequence[str]) -> str:
    """The ``proto`` of an alert on a rule using ``protocols`` (plan §B7 order)."""
    lowered = [p.lower() for p in protocols]
    for proto in _PROTO_PREFERENCE:
        if proto in lowered:
            return proto
    return lowered[0] if lowered else "ip"


def _layer(protocols: Sequence[str]) -> str:
    """The plan's layer (L2/3, L4, L7-web, L7-dicom, L7-5g) from a rule's protocols."""
    protos = {p.lower() for p in protocols}
    if protos & _LAYER_5G:
        return "L7-5g"
    if protos & _LAYER_DICOM:
        return "L7-dicom"
    if protos & _LAYER_WEB:
        return "L7-web"
    if protos & _LAYER_L4:
        return "L4"
    return "L2/3"


def _stix_alert(
    bundle: Mapping[str, Json], protocol_of: Mapping[str, Sequence[str]]
) -> Alert | None:
    """One STIX ``bundle`` as an :class:`Alert`; ``None`` when it is not an alert.

    The rule id is the ``x-attack-type``'s external id, the category its
    ``rule_type`` (attack/evasion/security), the timestamp the observation's
    ``first_observed``. ``src``/``dst`` are the first two IP SCOs — in bundle
    order (``ip.src``/``ip.dst``, or the trace's ARP addresses); a single-IP
    alert (an ARP conflict names one address) repeats it on both ends.
    ``proto`` comes from the rule's protocol list: the bundle does not carry
    the trace's attribute names.
    """
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        return None
    attack = next(
        (o for o in objects if isinstance(o, dict) and o.get("type") == "x-attack-type"), None
    )
    observed = next(
        (o for o in objects if isinstance(o, dict) and o.get("type") == "observed-data"), None
    )
    if attack is None or observed is None:
        return None
    refs = attack.get("external_references")
    if not isinstance(refs, list) or not refs:
        return None
    rule_id = str(refs[0].get("external_id", ""))
    if not rule_id:
        return None
    ext = attack.get("extensions", {})
    category = ext.get("x-attack-type-ext", {}).get("rule_type")
    if not isinstance(category, str) or not category:
        category = "unknown"
    ips = [
        o["value"]
        for o in objects
        if isinstance(o, dict)
        and o.get("type") in ("ipv4-addr", "ipv6-addr")
        and isinstance(o.get("value"), str)
    ]
    if not ips:
        return None
    src = ips[0]
    dst = ips[1] if len(ips) > 1 else ips[0]
    try:
        ts = _iso_seconds(str(observed["first_observed"]))
    except (KeyError, ValueError):
        return None
    return Alert(
        ts=ts,
        rule_id=rule_id,
        category=category,
        src=src,
        dst=dst,
        proto=_pick_protocol(protocol_of.get(rule_id, ())),
    )


def _trace_alert(value: Sequence[Json], protocol_of: Mapping[str, Sequence[str]]) -> Alert | None:
    """A legacy ``[10,...]`` security report (a non-STIX build) as an :class:`Alert`.

    Untested legacy: the pinned image is STIX-only, so no recorded output
    exercises this path; it is kept for a build without ``STIX_FORMAT``.

    The report's last field is the trace: ``{"event_N": {"timestamp": t,
    "attributes": [["proto.att", v], ...]}, ...}``; the proto is the first
    attribute's protocol, the endpoints the first ``ip.src``/``ip.dst`` (or
    ``arp.ar_sip``/``arp.ar_tip``) values, in trace order.
    """
    if len(value) < 9 or not isinstance(value[8], Mapping):
        return None
    rule_id = str(value[4])
    category = str(value[6]) if isinstance(value[6], str) else "unknown"
    try:
        ts = float(value[3])
    except (TypeError, ValueError):
        return None
    first_att: str | None = None
    src = dst = None
    for event in value[8].values():
        if not isinstance(event, Mapping):
            continue
        for att in event.get("attributes", ()):
            if not (isinstance(att, Sequence) and not isinstance(att, str) and len(att) == 2):
                continue
            key, val = att
            if not isinstance(key, str):
                continue
            if first_att is None:
                first_att = key
            if key in ("ip.src", "arp.ar_sip") and src is None and isinstance(val, str):
                src = val
            elif key in ("ip.dst", "arp.ar_tip") and dst is None and isinstance(val, str):
                dst = val
    proto = (
        first_att.split(".", 1)[0] if first_att else _pick_protocol(protocol_of.get(rule_id, ()))
    )
    if src is None or dst is None:
        return None
    return Alert(ts=ts, rule_id=rule_id, category=category, src=src, dst=dst, proto=proto)


def _parse_rule_info(text: str) -> list[RuleInfo]:
    """The rules of a ``rule_info`` run: id, category, layer, protocols, stateful.

    ``rule_info`` prints one block per rule::

        1 - Rule id: 13
        \t- type            : evasion
        \t- events_count    : 2
        \t- variables_count : 4
        \t- variables       : ip.dst (178.14), tcp.flags (354.6), ...
        \t- description     : Data in SYN packet.
    """
    rules: list[RuleInfo] = []
    fields: dict[str, Json] | None = None

    def flush() -> None:
        if fields is not None:
            protos = fields["protos"]
            rules.append(
                RuleInfo(
                    id=fields["id"],
                    category=fields["type"] or "unknown",
                    layer=_layer(protos),
                    protocols=tuple(dict.fromkeys(protos)),
                    stateful=fields["events"] > 1,
                )
            )

    for line in [*text.splitlines(), "x - Rule id:"]:
        line = line.strip()
        if "Rule id:" in line:
            flush()
            rid = line.rsplit("Rule id:", 1)[1].strip()
            fields = {"id": rid, "type": "", "events": 1, "protos": []} if rid else None
        elif fields is not None and line.startswith("- type"):
            fields["type"] = line.split(":", 1)[1].strip()
        elif fields is not None and line.startswith("- events_count"):
            try:
                fields["events"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                fields["events"] = 1
        elif fields is not None and line.startswith("- variables"):
            for var in line.split(":", 1)[1].split(","):
                var = var.strip()
                if "." in var:
                    fields["protos"].append(var.split(".", 1)[0].strip())
    return rules


def _parse_versions(text: str) -> dict[str, str]:
    """The ``versions`` command output: the VERSIONS pins plus ``probe -v``.

    VERSIONS holds ``key=value`` lines (``dpi=``, ``security=``,
    ``probe=``...); ``probe -v`` prints ``- MMT-Probe <v>``, ``- MMT-DPI
    <v>``, ``- MMT-Security <v>`` and ``- Modules: <list>``.
    """
    info: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("- "):
            line = line[2:]
        if line.startswith("MMT-Probe "):
            info["mmt-probe"] = line.removeprefix("MMT-Probe ").strip()
        elif line.startswith("MMT-DPI "):
            info["mmt-dpi"] = line.removeprefix("MMT-DPI ").strip()
        elif line.startswith("MMT-Security "):
            info["mmt-security"] = line.removeprefix("MMT-Security ").strip()
        elif line.startswith("Modules:"):
            info["mmt-probe-modules"] = line.split(":", 1)[1].strip()
        elif "=" in line and " " not in line.split("=", 1)[0]:
            key, _, value = line.partition("=")
            info.setdefault(f"pin-{key.strip()}", value.strip())
    return info


#: The generated mmt-probe.conf. ``{probe_id}``, ``{buffer_size}``,
#: ``{thread_queue}`` and ``{cache_max}`` are the profile's parameters; the
#: rest is the proven mmt-stack configuration (config/probe/mmt-probe.conf).
_CONF_TEMPLATE = """\
# mmt-probe configuration generated by mmt-bench ({profile} profile).
# Base values are mmt-stack's proven probe config; the profile tunes the
# buffering knobs. Offline input comes from `-t <pcap>` on the command line.

probe-id   = {probe_id}
stack-type = 1          # Ethernet
stats-period = 10

enable-proto-without-session-report = true   # report 99: protocol/application statistics
enable-ip-fragmentation-report      = false
enable-ip-defragmentation           = false
enable-tcp-reassembly               = false
enable-report-version-info          = true    # report 1 at start-up: versions in use

thread-nb    = 0   # overridden by -X thread-nb=<threads> at run time
# packets queued per worker thread, only with thread-nb >= 1
thread-queue = {thread_queue}

input {{
    mode        = ONLINE
    source      = "offline"    # overridden by `-t <pcap>`
    snap-len    = 0
    buffer-size = {buffer_size}   # bytes (pcap_set_buffer_size)
    timeout     = 1000
    pcap-filter = ""
}}

output {{
    format       = JSON      # each report is one JSON array per line
    cache-max    = {cache_max}
    cache-period = 60
}}

file-output {{
    enable       = true
    output-dir   = "{workdir_mount}/reports/"
    output-file  = "mmt-report.json"
    sample-file  = true
    retain-files = 0
}}

security {{
    enable                  = {security_enable}
    # 0 = rules are verified in the probe thread
    thread-nb               = 0
    exclude-rules           = ""
    rules-mask              = ""
    output-channel          = {{file}}   # STIX 2.1 bundles (STIX_FORMAT build)
    report-rule-description = true
    # false reports every verdict (the detection-fair default); true caps a
    # flow at its first verdict — mmt-stack's throughput setting, which
    # under-measures detection on scan and flood pcaps.
    ignore-remain-flow      = {ignore_remain_flow}
    stix-priority           = ""
    input.max-message-size  = 131072
    security.max-instances  = 16384
    security.smp.ring-size  = 1000
    ip-encapsulation-index  = LAST
}}

system-report {{
    enable         = false   # report 201 (cpu/mem), realtime; the bench measures itself
    period         = 5
    output-channel = {{file}}
}}

session-report {{           # report 100: one line per active session per period
    enable         = true
    output-channel = {{file}}
    ftp  = false
    http = true
    rtp  = false
    ssl  = true
    gtp  = false
    rtt-base = CAPTOR
}}

session-timeout {{
    default-session-timeout = 60
    short-session-timeout   = 15
    long-session-timeout    = 6000
    live-session-timeout    = 1500
}}

# The parser requires these blocks to exist, even disabled.
reconstruct-data ftp  {{ enable = false }}
"""

#: The two fair-comparison profiles (docs/methodology.md): the mmt-stack
#: proven values, and the same config with the buffers tuned for throughput.
#: ``ignore_remain_flow`` is a profile value so the recorded config shows
#: what a run used; both profiles set false — with true the probe reports
#: only a flow's first verdict, which under-measures detection (review F1).
_CONFIG_PROFILE_PARAMS = {
    "recommended": {
        "buffer_size": 67108864,
        "thread_queue": 4096,
        "cache_max": 100000,
        "ignore_remain_flow": "false",
    },
    "tuned": {
        "buffer_size": 268435456,
        "thread_queue": 16384,
        "cache_max": 500000,
        "ignore_remain_flow": "false",
    },
}


def render_config(profile: str, probe_id: int = 1, *, security: bool = True) -> str:
    """The ``mmt-probe.conf`` text of a config profile.

    ``security`` is the ruleset's switch (``Ruleset.security``): ``false``
    writes ``security.enable = false`` — the R0 cell, engine off; ``true``
    with an empty ruleset is R0b, the engine on with no rules to match.
    """
    if profile not in _CONFIG_PROFILE_PARAMS:
        raise ValueError(f"unknown config profile: {profile!r} (expected one of {CONFIG_PROFILES})")
    return _CONF_TEMPLATE.format(
        profile=profile,
        probe_id=probe_id,
        workdir_mount=WORKDIR_MOUNT,
        security_enable="true" if security else "false",
        **_CONFIG_PROFILE_PARAMS[profile],
    )


@dataclass
class _Run:
    """The last ``run_offline``: where its outputs land."""

    workdir: Path
    reports_dir: Path
    log_path: Path
    container_name: str


class MmtProbeAdapter(Adapter):
    """mmt-probe (with mmt-dpi and mmt-security) in a container, offline (#6).

    ``image`` is an :class:`ImageRef` or a reference string; a string must be
    digest-pinned (``name@sha256:...``) or resolvable by the daemon to the
    image's sha256 id — a bare tag with no daemon behind is refused, so the
    tools record always proves which image ran. ``docker`` is the docker CLI;
    tests inject a fake.
    """

    def __init__(
        self, image: ImageRef | str = DEFAULT_IMAGE, *, docker: Docker | None = None
    ) -> None:
        self.docker: Docker = docker if docker is not None else CliDocker()
        self._image = image if isinstance(image, ImageRef) else parse_image_ref(image, self.docker)
        self._prepared: dict[str, Json] | None = None
        self._run: _Run | None = None
        self._rule_protos: dict[str, tuple[str, ...]] = {}
        self._versions: dict[str, str] | sut.Marker | None = None

    # -- construction helpers --------------------------------------------------

    @classmethod
    def build(
        cls,
        tag: str = DEFAULT_IMAGE,
        *,
        context: Path = BUILD_CONTEXT,
        docker: Docker | None = None,
    ) -> MmtProbeAdapter:
        """Build the probe image and return an adapter on it, pinned by its sha256 id."""
        docker = docker if docker is not None else CliDocker()
        built = docker.run(["build", "-t", tag, str(context)], timeout=3600)
        if built.returncode != 0:
            raise RuntimeError(
                "docker build of the mmt-probe image failed:\n"
                + built.stdout.decode("utf-8", "replace")[-2000:]
            )
        return cls(parse_image_ref(tag, docker), docker=docker)

    @property
    def name(self) -> str:
        return "mmt-probe"

    def _run_image(self) -> str:
        """The reference ``docker run`` must start.

        A ``name@sha256:`` ref already pins the image. A tag the daemon
        resolved to an image id runs by that id instead, so a retag
        between the resolve and the run cannot start a different image
        than the one the record pins.
        """
        return self._image.ref if "@" in self._image.ref else self._image.digest

    # -- lifecycle --------------------------------------------------------------

    def prepare(self, ruleset: Ruleset, config_profile: str, workdir: Path) -> list[Path]:
        """Write ``mmt-probe.conf`` and stage the ruleset's ``.so`` files.

        The rules are staged under ``workdir/mmt-rules/`` (never a dir named
        ``rules``: the probe prefers ``./rules`` over its install dir, and a
        stray ``rules`` dir would silently shadow the mounted ruleset).
        """
        workdir.mkdir(parents=True, exist_ok=True)
        conf = workdir / "mmt-probe.conf"
        conf.write_text(render_config(config_profile, security=ruleset.security), encoding="utf-8")
        rules_dir = workdir / "mmt-rules"
        rules_dir.mkdir(exist_ok=True)
        staged = self._stage_rules(ruleset, rules_dir)
        if not staged and not ruleset.allow_empty:
            raise FileNotFoundError(f"ruleset {ruleset.id}: no .so rule found under {ruleset.path}")
        self._prepared = {
            "ruleset": ruleset,
            "profile": config_profile,
            "workdir": workdir,
            "conf": conf,
            "rules_dir": rules_dir,
        }
        # rule_inventory fills _rule_protos, which alerts() needs for `proto`.
        self._rule_protos = {r.id: r.protocols for r in self.rule_inventory(ruleset)}
        return [conf]

    @staticmethod
    def _stage_rules(ruleset: Ruleset, rules_dir: Path) -> list[Path]:
        """Copy the ruleset's ``.so`` files into ``rules_dir``; returns the copies."""
        if ruleset.path.is_file():
            if ruleset.path.suffix != ".so":
                raise InvalidValue(
                    f"ruleset {ruleset.id}: {ruleset.path.name} is not a .so rule file"
                )
            sources = [ruleset.path]
        elif ruleset.path.is_dir():
            sources = sorted(ruleset.path.glob("*.so"))
        else:
            raise FileNotFoundError(
                f"ruleset {ruleset.id}: no such file or directory: {ruleset.path}"
            )
        staged = []
        for src in sources:
            dst = rules_dir / src.name
            dst.write_bytes(src.read_bytes())
            staged.append(dst)
        return staged

    def _require_prepared(self) -> dict[str, Json]:
        if self._prepared is None:
            raise RuntimeError("prepare() first")
        return self._prepared

    def run_offline(self, pcap: Path, threads: int, cpuset: Sequence[int]) -> ProcessHandle:
        """Run the probe on ``pcap``; reports land in ``<workdir>/reports/``.

        ``threads`` is the probe's ``thread-nb`` (0 = capture and process on
        one thread); ``cpuset`` pins the container's cores
        (``--cpuset-cpus``). The pcap and the staged rules are mounted
        read-only; the workdir is the only read-write mount.
        """
        prepared = self._require_prepared()
        workdir = prepared["workdir"]
        pcap = Path(pcap)
        if not pcap.is_file():
            raise FileNotFoundError(f"pcap: no such file: {pcap}")
        reports_dir = workdir / "reports"
        reports_dir.mkdir(exist_ok=True)
        name = _container_name("run")
        argv = [
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "none",
            "-w",
            "/",
        ]
        if cpuset:
            argv += ["--cpuset-cpus", sut.format_cpulist(cpuset)]
        argv += [
            "-v",
            f"{workdir.resolve()}:{WORKDIR_MOUNT}",
            "-v",
            f"{pcap.resolve()}:{PCAP_MOUNT}/{pcap.name}:ro",
            "-v",
            f"{Path(prepared['rules_dir']).resolve()}:{RULES_MOUNT}:ro",
            self._run_image(),
            "probe",
            "-c",
            f"{WORKDIR_MOUNT}/mmt-probe.conf",
            "-t",
            f"{PCAP_MOUNT}/{pcap.name}",
            "-X",
            f"thread-nb={threads}",
        ]
        log_path = workdir / "probe.log"
        log = log_path.open("wb")
        try:
            proc = self.docker.spawn(argv, log)
        except Exception:
            log.close()
            raise
        self._run = _Run(workdir, reports_dir, log_path, name)
        return _Container(proc, self.docker, name, log)

    def run_online(self, iface: str, threads: int, cpuset: Sequence[int]) -> ProcessHandle:
        raise NotImplementedError("mmt-probe online mode is not implemented yet (P4)")

    def container_limits(self, cpuset: Sequence[int]) -> dict[str, Json]:
        """The run container's cgroup limits, read inside a scratch container.

        ``docker run`` gives the container a private cgroup namespace on
        cgroup v2 hosts, so ``/sys/fs/cgroup/*`` inside it is the run's own
        cgroup: this records what the run actually gets (the daemon's
        effective cpuset, not only the requested one). The scratch container
        is ``mbench-``-named and ``--rm``, like every container the adapter
        starts.
        """
        argv = [
            "run",
            "--rm",
            "--name",
            _container_name("limits"),
            "--network",
            "none",
            "-w",
            "/",
        ]
        if cpuset:
            argv += ["--cpuset-cpus", sut.format_cpulist(cpuset)]
        argv += [
            self._run_image(),
            "sh",
            "-c",
            "cat /sys/fs/cgroup/cpu.max; cat /sys/fs/cgroup/memory.max; "
            "cat /sys/fs/cgroup/cpuset.cpus.effective",
        ]
        proc = self.docker.run(argv, timeout=120)

        def missing(reason: str) -> sut.Marker:
            return sut.unavailable("error", f"the run container's cgroup limits: {reason}")

        if proc.returncode != 0:
            marker = missing(f"the limits probe exited with status {proc.returncode}")
            return {"cpu_max": marker, "memory_max": marker, "cpuset_cpus": marker}
        lines = proc.stdout.decode("utf-8", "replace").splitlines()
        keys = ("cpu_max", "memory_max", "cpuset_cpus")
        return {
            key: lines[i].strip() if i < len(lines) else missing(f"no {key} in the output")
            for i, key in enumerate(keys)
        }

    # -- outputs ----------------------------------------------------------------

    def _require_run(self) -> _Run:
        if self._run is None:
            raise RuntimeError("run_offline() first")
        return self._run

    def _values(self) -> Iterator[Json]:
        run = self._require_run()
        for report in sorted(run.reports_dir.glob("*.json")):
            yield from _report_values(report)

    def counters(self) -> Counters:
        """Packets, bytes and drops from the tool's own stats.

        ``bytes`` is the sum of the session (100) and protocol (99) reports'
        data volumes — wire bytes including L2 headers, equal to the pcap's
        total packet length. ``packets`` is the probe's own "MMT processed N
        packets" count (the status line), or the reports' packet sum when the
        status line is absent. ``drops`` is the same line's dropped count, or
        the last status report's ``mmt-lost``.
        """
        report_packets = report_bytes = 0
        status_lost = status_mmt_pkts = None
        stix = legacy = rows_99 = rows_100 = rows_200 = 0
        for value in self._values():
            if isinstance(value, list) and value:
                if value[0] == _REPORT_PROTO_NO_SESSION:
                    report_packets += int(value[_PROTO_PACKET_COUNT])
                    report_bytes += int(value[_PROTO_DATA_VOLUME])
                    rows_99 += 1
                elif value[0] == _REPORT_SESSION:
                    report_packets += int(value[_SESSION_PACKET_COUNT])
                    report_bytes += int(value[_SESSION_DATA_VOLUME])
                    rows_100 += 1
                elif value[0] == _REPORT_STATUS:
                    status_mmt_pkts = int(value[6])
                    status_lost = int(value[7])
                    rows_200 += 1
                elif isinstance(value[0], dict):
                    stix += 1
                elif value[0] == _REPORT_SECURITY:
                    legacy += 1
        if rows_99 + rows_100 + rows_200 + stix + legacy == 0:
            run = self._require_run()
            raise RuntimeError(
                f"the probe wrote no report under {run.reports_dir}: the run "
                f"produced nothing (the probe's own log is {run.log_path})"
            )
        processed, dropped = self._status_counts()
        packets = processed if processed is not None else report_packets
        drops = dropped if dropped is not None else (status_lost if status_lost is not None else 0)
        return Counters(
            packets=packets,
            bytes=report_bytes,
            drops=drops,
            extra={
                "report_packets": report_packets,
                "report_bytes": report_bytes,
                "status_packets": status_mmt_pkts if status_mmt_pkts is not None else 0,
                "status_lost": status_lost if status_lost is not None else 0,
                "processed_packets": processed if processed is not None else 0,
                "stix_alerts": stix,
                "legacy_alerts": legacy,
                "proto_reports": rows_99,
                "session_reports": rows_100,
            },
        )

    def _status_counts(self) -> tuple[int | None, int | None]:
        """``(processed, dropped)`` from the probe's end-of-run status line."""
        run = self._require_run()
        try:
            for line in run.log_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if _STATUS_LINE in line:
                    after = line.split(_STATUS_LINE, 1)[1]
                    processed = int(after.split(" ", 1)[0])
                    dropped = int(after.split("dropped ", 1)[1].split(" ", 1)[0])
                    return processed, dropped
        except OSError:
            pass
        return None, None

    def alerts(self) -> list[Alert]:
        """The run's STIX (and legacy ``[10]``) alerts, normalised."""
        out: list[Alert] = []
        for value in self._values():
            alert = None
            if (
                isinstance(value, list)
                and value
                and isinstance(value[0], Mapping)
                and value[0].get("type") == "bundle"
            ):
                alert = _stix_alert(value[0], self._rule_protos)
            elif isinstance(value, list) and value and value[0] == _REPORT_SECURITY:
                alert = _trace_alert(value, self._rule_protos)
            if alert is not None:
                out.append(alert)
        return out

    # -- rules ------------------------------------------------------------------

    def rule_inventory(self, ruleset: Ruleset) -> list[RuleInfo]:
        """The rules of ``ruleset``, via the image's ``rule_info``.

        The ruleset is staged into a temp dir and mounted read-only over the
        image's rules dir; ``rule_info`` with no argument loads every ``.so``
        there (cwd ``/`` so no ``./rules`` shadows it).
        """
        import tempfile

        with tempfile.TemporaryDirectory(prefix="mbench-rules-") as stage:
            staged = Path(stage)
            self._stage_rules(ruleset, staged)
            argv = [
                "run",
                "--rm",
                "--name",
                _container_name("rules"),
                "--network",
                "none",
                "-w",
                "/",
                "-v",
                f"{staged.resolve()}:{RULES_MOUNT}:ro",
                self._run_image(),
                "rule_info",
            ]
            proc = self.docker.run(argv, timeout=300)
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", "replace")[:500]
            raise RuntimeError(f"rule_info failed (rc={proc.returncode}): {tail}")
        rules = _parse_rule_info(proc.stdout.decode("utf-8", "replace"))
        self._rule_protos.update({r.id: r.protocols for r in rules})
        return rules

    # -- the tools record ---------------------------------------------------------

    def version(self) -> str | sut.Marker:
        info = self._versions_info()
        if isinstance(info, dict) and "mmt-probe" in info:
            return info["mmt-probe"].split(" ", 1)[0]
        return (
            info
            if not isinstance(info, dict)
            else sut.unavailable("error", "no MMT-Probe version in probe -v")
        )

    @property
    def image(self) -> ImageRef | sut.Marker:
        return self._image

    def _versions_info(self) -> dict[str, str] | sut.Marker:
        """The ``versions`` output, cached: VERSIONS pins and ``probe -v``."""
        if self._versions is not None:
            return self._versions
        proc = self.docker.run(
            [
                "run",
                "--rm",
                "--name",
                _container_name("versions"),
                "--network",
                "none",
                self._run_image(),
                "versions",
            ],
            timeout=120,
        )
        if proc.returncode != 0:
            self._versions = sut.unavailable(
                "error", f"`versions` in the probe image failed (rc={proc.returncode})"
            )
            return self._versions
        self._versions = _parse_versions(proc.stdout.decode("utf-8", "replace"))
        return self._versions

    def tools_record(self) -> dict[str, Json]:
        """The tools-under-test record of the prepared run (plan §B4).

        Take it while the run's workdir still exists: ``config_record``
        re-reads the generated ``mmt-probe.conf``.
        """
        prepared = self._require_prepared()
        ruleset = prepared["ruleset"]
        info = self._versions_info()
        strings: dict[str, Json] = dict(info) if isinstance(info, dict) else {}
        modules = {
            f"module_{m.strip().lower()}": True
            for m in strings.get("mmt-probe-modules", "").split(",")
            if m.strip()
        }
        flags = {
            f.strip().lower(): True
            for f in strings.get("pin-probe_modules", "").split()
            if f.strip()
        }
        return {
            "name": self.name,
            "version": self.version(),
            "image": self._image.to_dict() if isinstance(self._image, ImageRef) else self._image,
            "version_strings": strings if strings else info,
            "build_flags": {**modules, **flags}
            if (modules or flags)
            else sut.unavailable("error", "no build flags in the probe image"),
            "ruleset": {"id": ruleset.id, "sha256": ruleset.sha256()},
            "config": config_record([prepared["conf"]], prepared["workdir"]),
        }
