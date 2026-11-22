"""Campaign YAML to the list of runs it expands into (#8, plan §B1).

A campaign file under ``campaigns/`` asks one question and lists the
dimensions of its matrix: tools, rule sets, config profiles, corpus entries,
thread counts and cpusets. :func:`load` reads and resolves one (schema plus
references: every ruleset, corpus file and ground truth must exist and match
its pin) and expands the cartesian product of :class:`Cell`\\ s — one run
each — that ``runner.py`` executes and ``report/render.py`` compares.
Relative paths in the file resolve against its *anchor*: the directory that
holds ``campaigns/`` when there is one (the repo root), else the file's own
directory.
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mbench import cores, corpus, pcap, sut, truth
from mbench.adapters.base import Ruleset


class CampaignError(ValueError):
    """The campaign file cannot be read, validated or resolved."""

    def __init__(self, message: str, problems: Sequence[str] = ()) -> None:
        self.problems = list(problems)
        super().__init__(message)


@dataclass(frozen=True)
class CorpusRef:
    """A corpus entry resolved to its file, hash and display name.

    ``ref`` is what results and reports may show, through
    :func:`mbench.corpus.result_ref` semantics: label and sha256, plus the
    public fields for a non-local entry.
    """

    label: str
    path: Path
    sha256: str
    truth: truth.GroundTruth | None
    ref: dict[str, Any]


@dataclass(frozen=True)
class Cell:
    """One run of the matrix: the full assignment of every dimension."""

    index: int
    tool: str
    ruleset: Ruleset
    config_profile: str
    corpus: CorpusRef
    threads: int
    cpuset: tuple[int, ...]
    cpuset_str: str


@dataclass(frozen=True)
class Campaign:
    """A campaign file, resolved: every reference points at a real object."""

    name: str
    question: str
    description: str
    mode: str
    quiet_host: bool
    repeats: int
    timeout_s: float
    path: Path
    cells: tuple[Cell, ...]
    # ``perf`` trails so existing positional constructions keep working.
    perf: bool = False

    def meta(self) -> dict[str, Any]:
        """The campaign fields a run record and REPORT.md embed."""
        return {
            "name": self.name,
            "question": self.question,
            "description": self.description or None,
            "mode": self.mode,
            "quiet_host": self.quiet_host,
            "perf": self.perf,
            "repeats": self.repeats,
            "timeout_s": self.timeout_s,
        }


def _resolve_def(ident: str, path: Path, base: Path) -> Ruleset:
    """A ``rulesets/<id>.yaml`` definition: a rule set described, not stored.

    The def points at where the ``.so`` files live (for r-all, the pinned
    image's rules extracted into ``local/``) and says what the tool does
    with them (``security.enable``, ``allow_empty``); the rules themselves
    are never committed.
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CampaignError(f"ruleset {ident!r}: {path} cannot be read: {exc}") from None
    if not isinstance(data, dict) or data.get("kind") != "ruleset":
        raise CampaignError(f"ruleset {ident!r}: {path} is not a ruleset definition")
    from mbench import validate

    problems = validate.ruleset_errors(data)
    if problems:
        raise CampaignError(f"ruleset {ident!r}: INVALID", problems)
    rules = Path(data["rules"])
    if not rules.is_absolute():
        rules = base / rules
    if not rules.exists():
        provenance = data.get("provenance") or {}
        hint = f" — {provenance['extract']}" if provenance.get("extract") else ""
        raise CampaignError(f"ruleset {ident!r}: no such file or directory: {rules}{hint}")
    expected = (data.get("provenance") or {}).get("expect_rules")
    if expected is not None and rules.is_dir():
        found = len(list(rules.glob("*.so")))
        if found != expected:
            raise CampaignError(
                f"ruleset {ident!r}: {found} .so rules under {rules}, "
                f"expected {expected} (the definition's provenance)"
            )
    security = data.get("security") or {}
    return Ruleset(
        ident,
        rules,
        security=bool(security.get("enable", True)),
        allow_empty=bool(data.get("allow_empty", False)),
    )


def _resolve_ruleset(item: str | dict[str, Any], base: Path) -> Ruleset:
    """A ruleset entry: an id under ``rulesets/``, or ``{id, path}``."""
    if isinstance(item, str):
        ident, path = item, base / "rulesets" / item
        definition = path.with_suffix(".yaml")
        if definition.exists():
            return _resolve_def(ident, definition, base)
        if not path.exists():
            alt = path.with_suffix(".so")
            if alt.exists():
                path = alt
    else:
        ident, path = item["id"], Path(item["path"])
        if not path.is_absolute():
            path = base / path
    if not path.exists():
        raise CampaignError(f"ruleset {ident!r}: no such file or directory: {path}")
    return Ruleset(ident, path)


def _resolve_label(
    item: dict[str, Any], manifest_path: Path, manifest: dict[str, Any]
) -> CorpusRef:
    """A ``{label}`` corpus entry, resolved through the manifest."""
    label = item["label"]
    entry = corpus.find_entry(manifest, label)
    if entry is None:
        raise CampaignError(
            f"corpus: no manifest entry for {label!r} in {manifest_path}",
            [f"{label!r} is not a label of {manifest_path}"],
        )
    check = corpus.check_entry(manifest_path, entry)
    if check.status != "ok":
        raise CampaignError(
            f"corpus {label!r}: {check.status}",
            [f"corpus {label!r}: {p}" for p in check.problems],
        )
    gt = None
    if entry.get("ground_truth"):
        gt = _load_truth(manifest_path.parent / str(entry["ground_truth"]), entry["sha256"])
    return CorpusRef(
        label,
        manifest_path.parent / str(entry["path"]),
        entry["sha256"],
        gt,
        corpus.result_ref(entry),
    )


def _load_truth(path: Path, pcap_sha256: str) -> truth.GroundTruth:
    try:
        gt = truth.load(path)
    except (truth.TruthError, OSError) as exc:
        raise CampaignError(str(exc)) from None
    if gt.pcap_sha256 != pcap_sha256:
        raise CampaignError(
            f"{path}: the ground truth is for pcap {gt.pcap_sha256}, not {pcap_sha256}"
        )
    return gt


def _resolve_pcap(item: dict[str, Any], base: Path) -> CorpusRef:
    """A ``{path, sha256, truth?, name?}`` corpus entry, checked against its pin."""
    path = Path(item["path"])
    if not path.is_absolute():
        path = base / path
    if not path.is_file():
        raise CampaignError(f"corpus {item['path']!r}: no such file: {path}")
    try:
        st = pcap.stats(path)
    except (OSError, pcap.CaptureError) as exc:
        raise CampaignError(str(exc)) from None
    if st.sha256 != item["sha256"]:
        raise CampaignError(
            f"corpus {item['path']!r}: sha256 {st.sha256} "
            f"does not match the campaign's {item['sha256']}"
        )
    label = item.get("name") or path.stem
    gt = _load_truth(base / item["truth"], st.sha256) if item.get("truth") else None
    entry = {
        "label": label,
        "sha256": st.sha256,
        "size_bytes": st.size_bytes,
        "packets": st.packets,
        "avg_packet_bytes": st.avg_packet_bytes,
        # The path is never recorded, and the entry is local-only: a
        # path-pinned capture is the private-capture case — results name it
        # by its label and sha256 only (AGENTS.md).
        "source": "a path pinned in the campaign file",
        "licence": "unspecified (campaign-local capture)",
        "ground_truth": Path(item["truth"]).name if item.get("truth") else None,
        "local_only": True,
    }
    return CorpusRef(label, path, st.sha256, gt, corpus.result_ref(entry))


def _resolve_cpusets(
    items: Sequence[str], topology: dict[str, tuple[int, ...]] | None
) -> list[tuple[tuple[int, ...], str]]:
    """Each ``cpusets`` item as ``(cpus, canonical cpulist)``.

    A ``core:<fragment>`` item resolves against the host's topology
    (``topology``, live-derived when not given): the run then records the
    resolved cpulist, and the campaign file never hard-codes host CPU
    numbers.
    """
    resolved = []
    for item in items:
        if cores.selector(item) is not None:
            if topology is None:
                topology = cores.live()
            try:
                cpus = cores.resolve(item, topology)
            except LookupError as exc:
                raise CampaignError(str(exc)) from None
            resolved.append((cpus, sut.format_cpulist(cpus)))
        else:
            resolved.append((tuple(sut.parse_cpulist(item)), item))
    return resolved


def load(
    path: str | Path,
    *,
    manifest_path: Path = corpus.DEFAULT_MANIFEST,
    topology: dict[str, tuple[int, ...]] | None = None,
) -> Campaign:
    """Read, validate and resolve a campaign file.

    Raises :class:`CampaignError` with every problem found.
    """
    from mbench import validate

    p = Path(path)
    resolved = p.resolve()
    # The anchor every relative path in the file resolves against: the
    # directory holding campaigns/ when there is one (the repo root, so
    # `rulesets/<id>` names the committed rule sets), else the file's parent.
    base = resolved.parent.parent if resolved.parent.name == "campaigns" else resolved.parent
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CampaignError(f"{p}: cannot be read as YAML: {exc}") from None
    problems = validate.campaign_errors(data, manifest_path=manifest_path)
    if problems:
        raise CampaignError(f"{p}: INVALID ({len(problems)} problems)", problems)
    assert isinstance(data, dict)
    manifest: dict[str, Any] = {"entries": []}
    if any("label" in item for item in data["corpus"]):
        try:
            manifest = corpus.load(manifest_path)
        except (OSError, corpus.ManifestError) as exc:
            raise CampaignError(f"{manifest_path}: {exc}") from None
    rulesets = [_resolve_ruleset(item, base) for item in data["rulesets"]]
    corpus_refs = [
        _resolve_label(item, manifest_path, manifest)
        if "label" in item
        else _resolve_pcap(item, base)
        for item in data["corpus"]
    ]
    cpusets = _resolve_cpusets(data["cpusets"], topology)
    cells = [
        Cell(
            index=i,
            tool=tool,
            ruleset=ruleset,
            config_profile=profile,
            corpus=ref,
            threads=threads,
            cpuset=cpuset,
            cpuset_str=cpuset_str,
        )
        for i, (tool, ruleset, profile, ref, threads, (cpuset, cpuset_str)) in enumerate(
            itertools.product(
                data["tools"],
                rulesets,
                data.get("config_profiles") or ["recommended"],
                corpus_refs,
                data["threads"],
                cpusets,
            )
        )
    ]
    return Campaign(
        name=data.get("name") or p.stem,
        question=data["question"],
        description=data.get("description") or "",
        mode=data.get("mode") or "offline",
        quiet_host=bool(data.get("quiet_host", False)),
        perf=bool(data.get("perf", False)),
        repeats=data["repeats"],
        timeout_s=float(data["timeout_s"]),
        path=p,
        cells=tuple(cells),
    )
