"""``mbench validate``: check a record for completeness.

It checks sut.json records (#4) against the committed JSON Schema
(``src/mbench/schemas/sut.schema.json``) and re-computes their ``sut_hash``,
the corpus manifest (#7, ``corpus/manifest.yaml``) against
``src/mbench/schemas/corpus-manifest.schema.json``, a pcap's ground-truth
file (#26, ``<pcap>.truth.json``) against
``src/mbench/schemas/truth.schema.json`` plus the checks of
:func:`mbench.truth.parse`, a campaign file (#8,
``campaigns/<name>.yaml``) against ``src/mbench/schemas/campaign.schema.json``
plus checks a schema cannot express (known tools, resolved corpus labels),
and a results directory's ``REPORT.md`` or ``REPORT-<batch>.md`` (#9) against
a fresh render over its own batch's run files. A ``SWEEP.json`` summary of
``mbench sweep`` (#17) is checked against ``src/mbench/schemas/sweep.schema.json``,
and ``SWEEP.md`` against a fresh render of its sibling ``SWEEP*.json``.

Every problem is reported by the dotted path of the field, for example
``missing field: host.cpu.core_types[0].governor``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from mbench import sut

SUT_SCHEMA = "sut.schema.json"
MANIFEST_SCHEMA = "corpus-manifest.schema.json"
CAMPAIGN_SCHEMA = "campaign.schema.json"
RULESET_SCHEMA = "ruleset.schema.json"
SWEEP_SCHEMA = "sweep.schema.json"


@cache
def schema(name: str = SUT_SCHEMA) -> dict[str, Any]:
    """A committed JSON Schema, from the installed package."""
    text = files("mbench").joinpath("schemas", name).read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


def format_path(parts: Iterator[str | int] | list[str | int]) -> str:
    out = ""
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}" if out else str(part)
    return out or "(record)"


_REQUIRED = re.compile(r"^'(.+)' is a required property$")


def _leaf_errors(error: ValidationError) -> Iterator[ValidationError]:
    """The errors that name a field, below the ``anyOf`` value-or-marker choices.

    Every optional-value field is ``anyOf: [value schema, unavailable marker]``.
    When it fails, the useful error is the one from the value branch (index 0),
    unless the instance is shaped like a marker, when it is the marker branch.
    """
    if error.validator in {"anyOf", "oneOf"} and error.context:
        instance = error.instance
        marker_like = isinstance(instance, dict) and "unavailable" in instance
        branch = 1 if marker_like else 0
        chosen = [e for e in error.context if e.relative_schema_path[0] == branch]
        if chosen:
            for child in chosen:
                yield from _leaf_errors(child)
            return
    yield error


def describe(error: ValidationError) -> str:
    """One error, naming the field."""
    path = list(error.absolute_path)
    if (
        error.validator == "enum"
        and path
        and path[-1] == "unavailable"
        and error.instance in sut.UNAVAILABLE_KINDS
    ):
        # A known marker kind the field does not accept (an identity field
        # holding an ``error`` marker): the field must hold a value.
        field_path = format_path(path[:-1])
        return f"{field_path}: must hold a value here, not an unavailable marker ({error.instance})"
    if sut.is_unavailable(error.instance):
        kind = error.instance["unavailable"]
        return f"{format_path(path)}: must hold a value here, not an unavailable marker ({kind})"
    if error.validator == "required":
        m = _REQUIRED.match(error.message)
        if m:
            return f"missing field: {format_path([*path, m.group(1)])}"
    return f"{format_path(path)}: {error.message}"


def sut_errors(record: Any) -> list[str]:
    """Every reason ``record`` is not a complete sut.json record; empty if it is."""
    validator = Draft202012Validator(schema())
    errors = sorted(
        {describe(leaf) for error in validator.iter_errors(record) for leaf in _leaf_errors(error)}
    )
    if not errors and isinstance(record, dict):
        expected = sut.sut_hash(record)
        if record.get("sut_hash") != expected:
            errors.append(
                f"sut_hash: {record.get('sut_hash')} does not match the record ({expected})"
            )
    return errors


def manifest_errors(manifest: Any) -> list[str]:
    """Every reason ``manifest`` is not a valid corpus manifest; empty if it is.

    Beyond the schema: labels and paths are unique, and a generated entry's
    packet count and average packet size match its generator parameters.
    """
    validator = Draft202012Validator(schema(MANIFEST_SCHEMA))
    errors = sorted(
        {
            describe(leaf)
            for error in validator.iter_errors(manifest)
            for leaf in _leaf_errors(error)
        }
    )
    if errors or not isinstance(manifest, dict):
        return errors
    first: dict[tuple[str, object], int] = {}
    for i, entry in enumerate(manifest["entries"]):
        for key in ("label", "path"):
            seen = first.setdefault((key, entry[key]), i)
            if seen != i:
                errors.append(
                    f"entries[{i}].{key}: duplicate {entry[key]!r} (also entries[{seen}])"
                )
        gen = entry.get("generator")
        if gen is not None:
            for key, expected in (
                ("packets", gen["packets"]),
                ("avg_packet_bytes", gen["frame_bytes"]),
            ):
                if entry[key] != expected:
                    errors.append(
                        f"entries[{i}].{key}: {entry[key]} "
                        f"does not match its generator ({expected})"
                    )
    return errors


@dataclass
class Report:
    """The outcome of validating one file."""

    path: str
    kind: str
    errors: list[str] = field(default_factory=list)
    fields: int = 0
    unavailable: list[tuple[str, str, str]] = field(default_factory=list)
    scope: str = ""
    #: What a valid record of a kind other than ``sut`` holds, in a few words.
    summary: str = ""

    @property
    def ok(self) -> bool:
        return not self.errors


class UnsupportedRecord(ValueError):
    """The file is not a kind of record ``mbench validate`` checks yet."""


class UnreadableRecord(ValueError):
    """The file cannot be read as text (it is not UTF-8)."""


def validate_file(path: str | Path) -> Report:
    """Validate one file.

    Raises :class:`OSError`, :class:`UnreadableRecord`, :class:`UnsupportedRecord`.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise UnreadableRecord(
            f"{p}: unreadable: not UTF-8 text ({exc.reason} at byte {exc.start})"
        ) from None
    if p.suffix.lower() in {".yaml", ".yml"}:
        return _validate_yaml(p, text)
    if is_report(p):
        return _validate_report(p, text)
    if is_sweep_report(p):
        return _validate_sweep_md(p, text)
    try:
        record = json.loads(text)
    except ValueError as exc:
        return Report(str(p), "json", [f"not valid JSON: {exc}"])
    if is_truth(p, record):
        return _validate_truth(p, record)
    if is_run(record):
        return _validate_run(p, record)
    if is_sweep(p, record):
        return _validate_sweep(p, record)
    if not (isinstance(record, dict) and ("sut_hash" in record or "schema_version" in record)):
        raise UnsupportedRecord(
            f"{p}: not a record mbench validate checks (no schema_version or "
            "sut_hash, and not a truth file); it checks sut.json, runs/*.json, "
            "corpus/manifest.yaml, <pcap>.truth.json, campaigns/<x>.yaml "
            "and SWEEP*.json"
        )
    report = Report(str(p), "sut", sut_errors(record), scope=str(record.get("scope", "")))
    report.fields = sut.field_count(record)
    report.unavailable = sut.unavailable_fields(record)
    return report


def is_truth(path: Path, data: Any) -> bool:
    """A file named ``<pcap>.truth.json``, or a JSON object holding
    ``pcap_sha256`` and ``attacks``."""
    return path.name.endswith(".truth.json") or (
        isinstance(data, dict) and "pcap_sha256" in data and "attacks" in data
    )


def _validate_truth(p: Path, data: Any) -> Report:
    """Check a ground-truth file: the schema, then ``truth.parse``'s own checks."""
    from mbench import truth

    report = Report(str(p), "ground truth")
    try:
        gt = truth.parse(data)
    except truth.TruthError as exc:
        report.errors = exc.problems
        return report
    n = len(gt.attacks)
    report.summary = f"{n} attack{'s' if n != 1 else ''}, tolerance {gt.tolerance_s:g} s"
    return report


def is_manifest(path: Path, data: Any) -> bool:
    """A file named ``manifest.yaml``, or a YAML mapping with ``entries``."""
    return path.stem == "manifest" or (isinstance(data, dict) and "entries" in data)


def is_campaign(path: Path, data: Any) -> bool:
    """A file under ``campaigns/``, or a YAML mapping with a ``question``."""
    return path.parent.name == "campaigns" or (isinstance(data, dict) and "question" in data)


def is_ruleset(path: Path, data: Any) -> bool:
    """A file under ``rulesets/``, or a YAML mapping marked ``kind: ruleset``."""
    return path.parent.name == "rulesets" or (
        isinstance(data, dict) and data.get("kind") == "ruleset"
    )


def ruleset_errors(definition: Any) -> list[str]:
    """Every reason ``definition`` is not a valid ruleset def; empty if it is."""
    validator = Draft202012Validator(schema(RULESET_SCHEMA))
    return sorted(
        {
            describe(leaf)
            for error in validator.iter_errors(definition)
            for leaf in _leaf_errors(error)
        }
    )


def campaign_errors(campaign: Any, manifest_path: Path | None = None) -> list[str]:
    """Every reason ``campaign`` is not a valid campaign file; empty if it is.

    Beyond the schema: the listed tools must resolve to an adapter
    (:data:`mbench.adapters.ADAPTERS`), and ``corpus[].label`` must name an
    entry of the corpus manifest (``manifest_path``, default
    :data:`mbench.corpus.DEFAULT_MANIFEST`) when it is readable.
    """
    validator = Draft202012Validator(schema(CAMPAIGN_SCHEMA))
    errors = sorted(
        {
            describe(leaf)
            for error in validator.iter_errors(campaign)
            for leaf in _leaf_errors(error)
        }
    )
    if errors or not isinstance(campaign, dict):
        return errors
    from mbench import adapters, corpus

    known = sorted(adapters.ADAPTERS)
    for i, tool in enumerate(campaign["tools"]):
        if tool not in adapters.ADAPTERS:
            errors.append(f"tools[{i}]: {tool!r} has no adapter (known: {', '.join(known)})")
    for i, item in enumerate(campaign["cpusets"]):
        cpuset = item["cpuset"] if isinstance(item, dict) else item
        if not cpuset or cpuset.startswith("core:"):
            continue  # "" pins nothing; core:<type>[@n] resolves against the host at run time
        # A descending range (5-2) parses to nothing: the run would record a
        # cpuset that pins no cpu — mislabelled, so it is rejected.
        descending = any(
            int(hi) < int(lo)
            for part in cpuset.split(",")
            if "-" in part
            for lo, hi in [part.split("-", 1)]
        )
        if descending or not sut.parse_cpulist(cpuset):
            errors.append(f"cpusets[{i}]: {cpuset!r} is empty or has a descending range")
    if manifest_path is None:
        manifest_path = corpus.DEFAULT_MANIFEST
    for i, item in enumerate(campaign["corpus"]):
        if "label" not in item:
            continue
        try:
            manifest = corpus.load(manifest_path)
        except (OSError, corpus.ManifestError):
            continue  # no manifest to check the label against: the runner reports it
        if corpus.find_entry(manifest, item["label"]) is None:
            errors.append(
                f"corpus[{i}].label: no manifest entry for {item['label']!r} in {manifest_path}"
            )
    return errors


def is_run(data: Any) -> bool:
    """A run record under ``results/*/runs/``: it carries cell and passes."""
    return (
        isinstance(data, dict)
        and isinstance(data.get("cell"), dict)
        and isinstance(data.get("passes"), list)
    )


#: ``REPORT.md`` (the first batch's report) and ``REPORT-<batch>.md``.
REPORT_NAME = re.compile(r"^REPORT(?:-(?P<batch>\d{8}T\d{6}Z(?:-\d+)?))?\.md$")
#: The batch a ``runs/`` file belongs to: ``<batch>-NN-<slug>.json``.
RUN_BATCH = re.compile(r"^(?P<batch>\d{8}T\d{6}Z(?:-\d+)?)-\d+-")


def is_report(path: Path) -> bool:
    """A results report file: ``REPORT.md`` or ``REPORT-<batch>.md``."""
    return path.suffix.lower() == ".md" and path.name.startswith("REPORT")


def _batch_key(batch: str) -> tuple[str, int]:
    """The write order of a batch id: ``TS`` then ``TS-2``, ``TS-3``, ..."""
    base, _, n = batch.rpartition("-")
    return (base, int(n)) if n.isdigit() else (batch, 1)


def _validate_report(p: Path, text: str) -> Report:
    """Check a REPORT file: it must be a fresh render of what it recorded.

    The runner renders over every run file in the results directory at the
    end of a batch, so ``REPORT.md`` covers the first batch and each
    ``REPORT-<batch>.md`` covers every batch up to its own; a ``mbench
    report`` re-render carries a fresh batch id and covers them all. The
    host table comes from the newest ``sut*.json`` present at that point.
    """
    from mbench.report import render

    report = Report(str(p), "report")
    match = REPORT_NAME.fullmatch(p.name)
    if match is None:
        report.errors = [
            f"{p.name}: report files are REPORT.md or REPORT-<batch>.md "
            "(a batch like 20260101T000000Z)"
        ]
        return report
    directory = p.parent
    _, runs = render.load_dir(directory)
    run_batches = {m.group("batch") for r in runs if (m := RUN_BATCH.match(r.name))}
    batch = match.group("batch")
    if batch is None:
        if not run_batches:
            report.errors = [f"{directory}: no runs/*.json records to render REPORT.md against"]
            return report
        batch = min(run_batches, key=_batch_key)
    key = _batch_key(batch)
    covered = [
        r for r in runs if (m := RUN_BATCH.match(r.name)) and _batch_key(m.group("batch")) <= key
    ]
    if not covered:
        report.errors = [f"{p.name}: no runs/*.json records at or before batch {batch}"]
        return report
    host: dict[str, Any] | None = None
    host_batch = ""
    for name in directory.glob("sut*.json"):
        stem = name.stem
        b = "" if stem == "sut" else stem.removeprefix("sut-")
        if _batch_key(b) <= _batch_key(batch) and _batch_key(b) >= _batch_key(host_batch):
            try:
                data = json.loads(name.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                host, host_batch = data, b
    campaign = next(
        (meta for run in covered if isinstance((meta := run.record.get("campaign")), dict)),
        None,
    )
    expected = render.render(campaign, host, covered)
    if expected == text:
        n = len(covered)
        report.summary = f"batch {batch}, a faithful render over {n} run file{'s' * (n != 1)}"
        return report
    have_lines, want_lines = text.splitlines(), expected.splitlines()
    for i, (have, want) in enumerate(zip(have_lines, want_lines, strict=False), 1):
        if have != want:
            report.errors = [f"line {i}: {have!r} differs from a fresh render's {want!r}"]
            break
    else:
        report.errors = [
            f"stale report: {len(have_lines)} lines where a fresh render has {len(want_lines)}"
        ]
    return report


def is_sweep(path: Path, data: Any) -> bool:
    """A ``SWEEP*.json`` summary, or a JSON object marked ``kind: sweep``."""
    return path.name.startswith("SWEEP") or (isinstance(data, dict) and data.get("kind") == "sweep")


def sweep_errors(record: Any) -> list[str]:
    """Every reason ``record`` is not a valid SWEEP.json summary; empty if it is."""
    validator = Draft202012Validator(schema(SWEEP_SCHEMA))
    return sorted(
        {describe(leaf) for error in validator.iter_errors(record) for leaf in _leaf_errors(error)}
    )


def _validate_sweep(p: Path, data: Any) -> Report:
    """Check a SWEEP.json summary against the sweep schema."""
    report = Report(str(p), "sweep", sweep_errors(data))
    if report.ok and isinstance(data, dict):
        n = len(data["steps"])
        if data["mode"] == "search":
            result = data["result"] or {}
            report.summary = (
                f"binary search over {data['param']}, {n} probe{'s' * (n != 1)},"
                f" best {result.get('best')}"
            )
        else:
            report.summary = f"{n} step{'s' * (n != 1)} over {data['param']}"
    return report


#: ``SWEEP.md`` (the first sweep's summary) and ``SWEEP-<batch>.md`` /
#: ``SWEEP-<batch>-N.md`` — the same suffixing ``runner._unique`` gives.
SWEEP_NAME = re.compile(r"^SWEEP(?:-\d{8}T\d{6}Z)?(?:-\d+){0,2}\.md$")


def is_sweep_report(path: Path) -> bool:
    """A sweep summary's markdown form: ``SWEEP.md`` or ``SWEEP-<batch>.md``."""
    return path.suffix.lower() == ".md" and path.name.startswith("SWEEP")


def _validate_sweep_md(p: Path, text: str) -> Report:
    """Check a SWEEP.md: it must be a fresh render of its sibling SWEEP*.json.

    The summary markdown carries the same stem as its JSON: ``SWEEP.md``
    renders ``SWEEP.json``, ``SWEEP-<batch>.md`` renders
    ``SWEEP-<batch>.json``.
    """
    from mbench import sweep

    report = Report(str(p), "sweep report")
    if SWEEP_NAME.fullmatch(p.name) is None:
        report.errors = [
            f"{p.name}: sweep summaries are SWEEP.md or SWEEP-<batch>.md "
            "(a batch like 20260101T000000Z)"
        ]
        return report
    sibling = p.with_suffix(".json")
    try:
        data = json.loads(sibling.read_text(encoding="utf-8"))
    except OSError:
        report.errors = [f"{p.name}: no sibling {sibling.name} to re-render from"]
        return report
    except ValueError as exc:
        report.errors = [f"{sibling.name}: not valid JSON: {exc}"]
        return report
    errors = sweep_errors(data)
    if errors:
        report.errors = [f"{sibling.name}: {e}" for e in errors]
        return report
    expected = sweep.render_summary_md(data)
    if expected == text:
        n = len(data["steps"])
        report.summary = f"a faithful render over {n} step{'s' * (n != 1)}"
        return report
    have_lines, want_lines = text.splitlines(), expected.splitlines()
    for i, (have, want) in enumerate(zip(have_lines, want_lines, strict=False), 1):
        if have != want:
            report.errors = [f"line {i}: {have!r} differs from a fresh render's {want!r}"]
            break
    else:
        report.errors = [
            f"stale summary: {len(have_lines)} lines where a fresh render has {len(want_lines)}"
        ]
    return report


def _validate_run(p: Path, data: Any) -> Report:
    """Check a run record: its embedded sut.json must validate in run scope.

    A run without an embedded SUT (an adapter-failure record) is checked as
    the empty record: the schema names everything that is missing.
    """
    embedded = data["sut"] if isinstance(data.get("sut"), dict) else {}
    report = Report(str(p), "run", sut_errors(embedded))
    if report.ok:
        measured = [x for x in data["passes"] if x.get("kind") == "measured"]
        ok = sum(1 for x in measured if x.get("status") == "ok")
        report.summary = (
            f"status {data.get('status', '?')}, {ok}/{len(measured)} measured passes ok"
        )
    return report


def _validate_yaml(p: Path, text: str) -> Report:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return Report(str(p), "yaml", [f"not valid YAML: {exc}"])
    if is_manifest(p, data):
        report = Report(str(p), "corpus manifest", manifest_errors(data))
        if report.ok:
            entries = data["entries"]
            local = sum(1 for e in entries if e["local_only"])
            report.summary = f"{len(entries)} entries, {local} local-only"
        return report
    if is_ruleset(p, data):
        report = Report(str(p), "ruleset", ruleset_errors(data))
        if report.ok:
            security = data.get("security") or {}
            report.summary = f"{data['tool']}, security {'on' if security.get('enable') else 'off'}"
        return report
    if is_campaign(p, data):
        report = Report(str(p), "campaign", campaign_errors(data))
        if report.ok:
            pairs = 0
            for rs in data["rulesets"]:
                rs_t = set(rs.get("threads", ())) if isinstance(rs, dict) else set()
                for cs in data["cpusets"]:
                    cs_t = set(cs.get("threads", ())) if isinstance(cs, dict) else set()
                    pairs += sum(
                        1
                        for t in data["threads"]
                        if (not rs_t or t in rs_t) and (not cs_t or t in cs_t)
                    )
            cells = (
                len(data["tools"])
                * len(data.get("config_profiles") or ["recommended"])
                * len(data["corpus"])
                * pairs
            )
            report.summary = (
                f"{cells} matrix cell{'s' if cells != 1 else ''}, "
                f"repeats {data['repeats']}, timeout {data['timeout_s']:g} s"
            )
        return report
    raise UnsupportedRecord(
        f"{p}: not a corpus manifest, campaign or ruleset def "
        "(no entries, question or kind: ruleset); it also checks sut.json "
        "and <pcap>.truth.json"
    )
