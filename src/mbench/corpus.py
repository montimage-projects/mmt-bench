"""The pcap corpus: ``corpus/manifest.yaml`` and the synthetic sets (#7).

The manifest lists every capture by sha256, with its source, licence, size,
packet count, average packet size and ground-truth file (plan §B6). Its schema
is committed as ``src/mbench/schemas/corpus-manifest.schema.json`` and checked
by ``mbench validate corpus/manifest.yaml``.

Captures are never committed: an entry's ``path`` is relative to the
manifest's directory and always under its ``data/`` directory, which git
ignores. An entry marked ``local_only`` (the anonymised dgx-spark capture) is
shown everywhere else, in results and reports included, only by its label and
sha256: :func:`result_ref` is the one place that decides what may be shown.

``mbench corpus gen`` writes C-small (64 B frames) and C-large (1500 B frames)
in pure Python (:mod:`mbench.pcap`). The bytes depend only on the set, the
seed, the packet count and the flow count, never on the host, the time or the
Python version: the pseudo-random bytes come from SHA-256 in counter mode, not
from :mod:`random`, whose streams Python does not promise to keep.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mbench import pcap

#: The manifest, relative to the repository root.
DEFAULT_MANIFEST = Path("corpus/manifest.yaml")
#: Where captures live, relative to the manifest's directory (git-ignored).
DATA_DIR = "data"
SCHEMA_VERSION = 1

#: Bumped whenever the bytes :func:`generate` writes change for the same
#: parameters, so an old manifest entry is never matched to new bytes.
GENERATOR_VERSION = 1
#: The licence recorded for generated sets: synthetic bytes with no
#: third-party content.
GENERATED_LICENCE = "CC0-1.0"

#: The schema's ``label`` pattern, checked before a file is ever written.
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

#: Field order of a manifest entry, as it is written.
ENTRY_FIELDS = (
    "label",
    "path",
    "sha256",
    "size_bytes",
    "packets",
    "avg_packet_bytes",
    "source",
    "licence",
    "ground_truth",
    "local_only",
    "description",
    "generator",
)

MANIFEST_HEADER = """\
# The pcap corpus (plan §B6), checked by `mbench validate corpus/manifest.yaml`
# against src/mbench/schemas/corpus-manifest.schema.json.
#
# Captures are never committed: each `path` is under corpus/data/, which git
# ignores. `mbench corpus gen` regenerates the synthetic sets byte for byte,
# `mbench corpus add` registers a local capture, and `mbench corpus check`
# compares every file present with its sha256. A `local_only` entry is shown
# in results and reports only by label and sha256.
#
# `mbench corpus gen` and `mbench corpus add` rewrite this file: comments other
# than this header are not kept.
"""

# --- synthetic sets ----------------------------------------------------------

#: Ethernet II + IPv4 (no options) + UDP.
HEADER_BYTES = 14 + 20 + 8
#: The payload starts with the packet's 8-byte sequence number.
MIN_FRAME_BYTES = HEADER_BYTES + 8
#: The first timestamp, 2026-01-01T00:00:00Z, and the gap between packets.
BASE_TIME = 1_767_225_600
GAP_USEC = 1
#: UDP discard (RFC 863): no DPI engine parses its payload as an L7 protocol.
DST_PORT = 9
#: At most this much memory for the flow table: one flow holds about
#: ``frame_bytes`` of precomputed bytes, so the cap scales with the frame size.
FLOW_BUDGET_BYTES = 256 << 20


@dataclass(frozen=True)
class SetSpec:
    """A synthetic set ``mbench corpus gen`` can write."""

    name: str
    frame_bytes: int
    packets: int
    flows: int
    description: str


SETS: dict[str, SetSpec] = {
    s.name: s
    for s in (
        SetSpec(
            "c-small",
            64,
            1_000_000,
            1024,
            "synthetic 64 B Ethernet/IPv4/UDP frames (packet-rate bound)",
        ),
        SetSpec(
            "c-large",
            1500,
            100_000,
            1024,
            "synthetic 1500 B Ethernet/IPv4/UDP frames (byte-rate bound)",
        ),
    )
}


class _Stream:
    """Deterministic pseudo-random bytes: SHA-256 of a key and a counter."""

    def __init__(self, key: bytes) -> None:
        self._key = key
        self._counter = 0
        self._buf = b""

    def take(self, n: int) -> bytes:
        parts = [self._buf]
        have = len(self._buf)
        while have < n:
            block = hashlib.sha256(self._key + self._counter.to_bytes(8, "big")).digest()
            self._counter += 1
            parts.append(block)
            have += len(block)
        data = b"".join(parts)
        self._buf = data[n:]
        return data[:n]

    def uint(self, nbytes: int) -> int:
        return int.from_bytes(self.take(nbytes), "big")


def _sum16(data: bytes) -> int:
    """The 16-bit one's-complement sum of ``data``, not folded."""
    if len(data) % 2:
        data += b"\0"
    return sum(struct.unpack(f">{len(data) // 2}H", data))


def _fold(total: int) -> int:
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


@dataclass(frozen=True)
class _Flow:
    prefix: bytes  # Ethernet + IPv4 + UDP ports and length
    filler: bytes  # the payload after the sequence number
    partial: int  # checksum sum of the pseudo-header, UDP header and filler


def _flows(spec: SetSpec, seed: int, flows: int) -> list[_Flow]:
    stream = _Stream(f"mbench corpus gen v{GENERATOR_VERSION} {spec.name} {seed}".encode())
    # Locally administered unicast MACs, and addresses from 198.18.0.0/15, the
    # range RFC 2544 reserves for benchmarks.
    src_mac = bytes([0x02]) + stream.take(5)
    dst_mac = bytes([0x02]) + stream.take(5)
    if dst_mac == src_mac:  # pragma: no cover - a 2^-40 chance
        dst_mac = bytes([0x02]) + bytes(5)
    ip_len = spec.frame_bytes - 14
    udp_len = ip_len - 20
    filler_len = udp_len - 16
    seen: set[tuple[int, int, int]] = set()
    out: list[_Flow] = []
    while len(out) < flows:
        src_ip = 0xC6120000 | stream.uint(2)  # 198.18.0.0/16
        dst_ip = 0xC6130000 | stream.uint(2)  # 198.19.0.0/16
        sport = 49152 + (stream.uint(2) & 0x3FFF)  # the dynamic port range
        key = (src_ip, dst_ip, sport)
        if key in seen:
            continue
        seen.add(key)
        ip = struct.pack(">BBHHHBBHII", 0x45, 0, ip_len, 0, 0x4000, 64, 17, 0, src_ip, dst_ip)
        ip = ip[:10] + struct.pack(">H", 0xFFFF - _fold(_sum16(ip))) + ip[12:]
        udp = struct.pack(">HHH", sport, DST_PORT, udp_len)
        filler = stream.take(filler_len)
        pseudo = struct.pack(">IIBBH", src_ip, dst_ip, 0, 17, udp_len)
        partial = _sum16(pseudo) + _sum16(udp) + _sum16(filler)
        out.append(_Flow(dst_mac + src_mac + b"\x08\x00" + ip + udp, filler, partial))
    return out


def max_flows(spec: SetSpec, packets: int) -> int:
    """The largest flow count allowed, bounded by packets and the flow budget."""
    return min(packets, 1 << 20, max(1, FLOW_BUDGET_BYTES // spec.frame_bytes))


def _checked_flows(spec: SetSpec, seed: int, packets: int, flows: int) -> list[_Flow]:
    """Check the parameters and build the flows; see :func:`generate`."""
    if seed < 0:
        raise ValueError("the seed must be >= 0")
    if packets < 1:
        raise ValueError("the packet count must be >= 1")
    if not 1 <= flows <= max_flows(spec, packets):
        raise ValueError(f"the flow count must be between 1 and {max_flows(spec, packets)}")
    if spec.frame_bytes < MIN_FRAME_BYTES:  # pragma: no cover - the sets are fixed
        raise ValueError(f"frames must be at least {MIN_FRAME_BYTES} B")
    return _flows(spec, seed, flows)


def generate(spec: SetSpec, seed: int, packets: int, flows: int, out: Path) -> None:
    """Write ``packets`` frames of ``spec.frame_bytes`` bytes to ``out``.

    Each frame is Ethernet II, IPv4 and UDP to the discard port, with valid
    checksums. The packets go round-robin over ``flows`` distinct 5-tuples, and
    each payload starts with the packet's sequence number. Timestamps start at
    :data:`BASE_TIME` and are :data:`GAP_USEC` apart. The file is written next
    to ``out`` first and renamed, so a failed run never leaves a partial file
    under the final name.
    """
    flow_list = _checked_flows(spec, seed, packets, flows)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    record = struct.Struct("<IIII")
    seq = struct.Struct(">Q")
    words = struct.Struct(">HHHH")
    length = spec.frame_bytes
    nflows = len(flow_list)
    try:
        with open(tmp, "wb") as f:
            pcap.Writer(f)
            for i in range(packets):
                flow = flow_list[i % nflows]
                seq_bytes = seq.pack(i)
                checksum = 0xFFFF - _fold(flow.partial + sum(words.unpack(seq_bytes)))
                usec = i * GAP_USEC
                f.write(
                    record.pack(BASE_TIME + usec // 1_000_000, usec % 1_000_000, length, length)
                    + flow.prefix
                    + struct.pack(">H", checksum or 0xFFFF)
                    + seq_bytes
                    + flow.filler
                )
        os.replace(tmp, out)
    finally:
        tmp.unlink(missing_ok=True)


# --- the manifest ------------------------------------------------------------


class ManifestError(ValueError):
    """The manifest cannot be read, or does not validate."""

    def __init__(self, message: str, problems: list[str] | None = None) -> None:
        super().__init__(message)
        self.problems = problems or []


def load(path: Path) -> dict[str, Any]:
    """Read and validate the manifest. A missing file is an empty manifest.

    Raises :class:`ManifestError` and :class:`OSError`.
    """
    from mbench import validate

    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "entries": []}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise ManifestError(f"{path}: not valid YAML: {exc}") from None
    problems = validate.manifest_errors(data)
    if problems:
        raise ManifestError(f"{path}: INVALID ({len(problems)} problems)", problems)
    assert isinstance(data, dict)
    return data


def dump(manifest: dict[str, Any]) -> str:
    return MANIFEST_HEADER + "\n" + yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True)


def save(path: Path, manifest: dict[str, Any]) -> None:
    """Write the manifest, replacing the file only once it is complete."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    try:
        tmp.write_text(dump(manifest), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def checked_save(path: Path, manifest: dict[str, Any]) -> None:
    """Save ``manifest`` only when it validates; leave ``path`` untouched.

    Raises :class:`ManifestError` naming every problem otherwise. The guard
    every write that merges caller-supplied fields goes through: fields the
    schema constrains but :func:`entry_from_file` does not check
    (``--source``, ``--licence``, ``--ground-truth``, ``--description``) or a
    duplicate path must never leave a manifest :func:`load` would refuse.
    """
    from mbench import validate

    problems = validate.manifest_errors(manifest)
    if problems:
        raise ManifestError(
            f"{path}: refusing to write an INVALID manifest ({len(problems)} problems)",
            problems,
        )
    save(path, manifest)


def ordered(entry: dict[str, Any]) -> dict[str, Any]:
    """``entry`` with its fields in :data:`ENTRY_FIELDS` order."""
    return {k: entry[k] for k in ENTRY_FIELDS if k in entry}


def find_entry(manifest: dict[str, Any], label: str) -> dict[str, Any] | None:
    """The entry named ``label``, or None."""
    entries: list[dict[str, Any]] = manifest.get("entries", [])
    return next((e for e in entries if e.get("label") == label), None)


def upsert(manifest: dict[str, Any], entry: dict[str, Any]) -> str:
    """Add ``entry``, or replace the one with its label: ``added``, ``replaced``
    or ``unchanged``."""
    entries: list[dict[str, Any]] = manifest.setdefault("entries", [])
    entry = ordered(entry)
    for i, old in enumerate(entries):
        if old.get("label") == entry["label"]:
            if old == entry:
                return "unchanged"
            entries[i] = entry
            return "replaced"
    entries.append(entry)
    return "added"


def entry_from_file(
    manifest_path: Path,
    file: Path,
    *,
    label: str,
    source: str,
    licence: str,
    ground_truth: str | None,
    local_only: bool,
    description: str | None = None,
    generator: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A manifest entry whose computed fields all come from ``file``'s bytes.

    ``file`` must be under the manifest's ``data/`` directory. Raises
    :class:`ValueError` (and :class:`mbench.pcap.CaptureError`) and
    :class:`OSError`.
    """
    if not LABEL_RE.fullmatch(label):
        raise ValueError(f"{label!r}: labels must match {LABEL_RE.pattern}")
    data_dir = (manifest_path.parent / DATA_DIR).resolve()
    resolved = file.resolve()
    if not resolved.is_relative_to(data_dir):
        raise ValueError(
            f"{file}: captures must be under {manifest_path.parent / DATA_DIR}/, which git ignores"
        )
    st = pcap.stats(resolved)
    entry: dict[str, Any] = {
        "label": label,
        "path": f"{DATA_DIR}/{resolved.relative_to(data_dir).as_posix()}",
        "sha256": st.sha256,
        "size_bytes": st.size_bytes,
        "packets": st.packets,
        "avg_packet_bytes": st.avg_packet_bytes,
        "source": source,
        "licence": licence,
        "ground_truth": ground_truth,
        "local_only": local_only,
    }
    if description is not None:
        entry["description"] = description
    if generator is not None:
        entry["generator"] = generator
    return ordered(entry)


def generator_params(spec: SetSpec, seed: int, packets: int, flows: int) -> dict[str, Any]:
    """The ``generator`` block a generated entry carries."""
    return {
        "set": spec.name,
        "version": GENERATOR_VERSION,
        "seed": seed,
        "packets": packets,
        "flows": flows,
        "frame_bytes": spec.frame_bytes,
    }


def gen_entry(
    manifest_path: Path,
    spec: SetSpec,
    seed: int,
    packets: int,
    flows: int,
    label: str,
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Generate ``spec`` under the manifest's data directory and upsert it.

    Returns the entry and ``generated`` or ``unchanged``. When the manifest
    already holds the same entry and the file still matches it, nothing is
    written. A ``label`` already used by an entry with no ``generator`` block
    is refused: ``gen`` never overwrites a capture it does not own.
    """
    out = manifest_path.parent / DATA_DIR / f"{label}.pcap"
    command = f"mbench corpus gen {spec.name} --seed {seed} --packets {packets} --flows {flows}"
    if not LABEL_RE.fullmatch(label):
        raise ValueError(f"{label!r}: labels must match {LABEL_RE.pattern}")
    existing = find_entry(manifest, label)
    if existing is not None and existing.get("generator") is None:
        raise ValueError(
            f"{label}: the manifest uses this label for an entry that was not generated"
        )
    if out.is_file():
        try:
            candidate = entry_from_file(
                manifest_path,
                out,
                label=label,
                source=f"synthetic: {command}",
                licence=GENERATED_LICENCE,
                ground_truth=None,
                local_only=False,
                description=spec.description,
                generator=generator_params(spec, seed, packets, flows),
            )
        except (OSError, pcap.CaptureError):
            candidate = None  # an unreadable file is regenerated below
        if candidate is not None and existing == candidate:
            return candidate, "unchanged"
    generate(spec, seed, packets, flows, out)
    entry = entry_from_file(
        manifest_path,
        out,
        label=label,
        source=f"synthetic: {command}",
        licence=GENERATED_LICENCE,
        ground_truth=None,
        local_only=False,
        description=spec.description,
        generator=generator_params(spec, seed, packets, flows),
    )
    upsert(manifest, entry)
    checked_save(manifest_path, manifest)
    return entry, "generated"


def result_ref(entry: dict[str, Any]) -> dict[str, Any]:
    """What results and reports may show of an entry.

    A ``local_only`` entry is its label and sha256 and nothing else: not its
    path, source, size or packet count. Results (#8) must name a capture
    through this function.
    """
    if entry.get("local_only", True):
        return {"label": entry["label"], "sha256": entry["sha256"], "local_only": True}
    return {
        k: entry[k]
        for k in (
            "label",
            "sha256",
            "size_bytes",
            "packets",
            "avg_packet_bytes",
            "source",
            "licence",
            "ground_truth",
        )
    } | {"local_only": False}


# --- the sha256 check --------------------------------------------------------


@dataclass(frozen=True)
class Check:
    """The outcome of checking one entry against its file."""

    label: str
    status: str  # ok | mismatch | missing | unreadable
    problems: tuple[str, ...] = ()


def check_entry(manifest_path: Path, entry: dict[str, Any]) -> Check:
    """Compare a file with its entry: sha256 first, then the computed fields.

    A ``local_only`` file is only hashed, and its problems name only its sha256.
    """
    label = str(entry["label"])
    file = manifest_path.parent / str(entry["path"])
    if not file.is_file():
        return Check(label, "missing", ("the file is not present",))
    st: pcap.Stats | None
    if entry["local_only"]:
        try:
            sha = pcap.sha256_file(file)
        except OSError as exc:
            return Check(label, "unreadable", (str(exc),))
        st = None
    else:
        try:
            st = pcap.stats(file)
        except (OSError, pcap.CaptureError) as exc:
            return Check(label, "unreadable", (str(exc),))
        sha = st.sha256
    if sha != entry["sha256"]:
        return Check(label, "mismatch", (f"sha256 is {sha}, manifest says {entry['sha256']}",))
    if st is None:
        return Check(label, "ok")
    problems = tuple(
        f"{name} is {actual}, manifest says {entry[name]}"
        for name, actual in (
            ("size_bytes", st.size_bytes),
            ("packets", st.packets),
            ("avg_packet_bytes", st.avg_packet_bytes),
        )
        if actual != entry[name]
    )
    return Check(label, "mismatch" if problems else "ok", problems)
