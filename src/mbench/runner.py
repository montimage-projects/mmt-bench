"""The campaign runner (#8): isolation, warm-up, repeats, pinning, timeouts.

``mbench run campaigns/<x>.yaml`` expands the campaign's matrix
(:mod:`mbench.matrix`), runs each cell as one warm-up pass plus ``repeats``
measured passes in offline mode (:mod:`mbench.modes.offline`), and writes:

.. code-block:: text

    results/<date>-<campaign>/
        sut.json                    the campaign's host-scope SUT record
        runs/<batch>-<NN>-<slug>.json   one run per matrix cell
        REPORT.md                   rendered over every run file in the dir

Everything under a results directory is **append-only**: :func:`write` opens
files ``O_EXCL``, so an existing file is never overwritten and a re-run of
the same campaign on the same date only adds a new ``<batch>-*.json`` per
cell (and ``sut-<batch>.json`` / ``REPORT-<batch>.md`` when the plain names
are taken).

Each run embeds its full SUT record — the campaign's host-scope record with
``scope`` flipped to ``run``, the adapter's ``tools`` item, the run's times,
the pcap sha256 and the run container's cgroup limits. A record that fails
``mbench validate``'s check marks the run ``invalid``; it is written but
excluded from every report table. A pass that exceeds ``timeout_s`` is
killed and recorded ``timeout``; it never counts as a measurement.

For a ``quiet_host`` campaign the runner only **prints** the commands that
stop and restart ``vllm-qwen.service`` and ``vllm-health-watchdog.timer``
(``systemctl --user``, user units — the decision of 2026-11-21); it never
runs them and never uses sudo.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from mbench import hostsrc, sut, truth, validate
from mbench.adapters import ADAPTERS
from mbench.adapters.base import Adapter, Json
from mbench.matrix import Campaign, Cell
from mbench.modes import offline

#: Where results go, relative to the working directory.
DEFAULT_RESULTS = Path("results")

#: The vLLM units a quiet-host campaign needs stopped/started, and the
#: commands printed for Luong (user units: `systemctl --user`, never sudo).
QUIET_STOP = "systemctl --user stop vllm-qwen.service vllm-health-watchdog.timer"
QUIET_START = "systemctl --user start vllm-qwen.service vllm-health-watchdog.timer"


def utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _batch_id(ts: datetime) -> str:
    return ts.strftime("%Y%m%dT%H%M%SZ")


def write(path: Path, text: str) -> None:
    """Write ``text`` to ``path``, failing when the file already exists.

    Results are append-only (AGENTS.md): every result file goes through this
    ``O_EXCL`` open, so nothing under ``results/<date>-<campaign>/`` is ever
    overwritten or replaced.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _unique(path: Path, batch: str, ext: str) -> Path:
    """``name.ext``, or ``name-<batch>.ext`` when the plain name is taken."""
    if not path.exists():
        return path
    return path.with_name(f"{path.stem}-{batch}{ext}")


def _free_batch(directory: Path, batch: str) -> str:
    """A batch id ``directory`` has not seen: ``batch``, else ``batch-2``, ...

    Every file of one batch carries the id (``runs/<batch>-*.json``,
    ``sut-<batch>.json``, ``REPORT-<batch>.md``), so checking for any of
    them — plus the first batch's plain ``sut.json`` and ``REPORT.md`` —
    keeps a repeat run under the same clock from reusing names.
    """
    runs = directory / "runs"
    candidate = batch
    n = 1
    while True:
        taken = (
            any(runs.glob(f"{candidate}-*.json"))
            or (directory / f"sut-{candidate}.json").exists()
            or (directory / f"REPORT-{candidate}.md").exists()
        )
        if n == 1:
            taken = taken or (directory / "sut.json").exists() or (directory / "REPORT.md").exists()
        if not taken:
            return candidate
        n += 1
        candidate = f"{batch}-{n}"


def core_type(record: dict[str, Json], cpuset: Sequence[int]) -> Json:
    """The model name of the core type covering ``cpuset``, from the SUT record.

    ``"unpinned"`` when the run was not pinned, the model name when every cpu
    is of one type, ``"mixed: A+B"`` across types, and an unavailable marker
    when the record cannot say.
    """
    if not cpuset:
        return "unpinned"
    cpu = record.get("host", {}).get("cpu", {})
    core_types = cpu.get("core_types") if isinstance(cpu, dict) else None
    if not isinstance(core_types, list) or not core_types:
        return sut.unavailable("error", "the SUT record has no cpu.core_types")
    types: dict[str, list[int]] = {}
    unknown: list[int] = []
    for cpu_id in cpuset:
        name = next(
            (
                ct["model_name"]
                for ct in core_types
                if isinstance(ct, dict)
                and isinstance(ct.get("cpus"), str)
                and cpu_id in sut.parse_cpulist(ct["cpus"])
                and isinstance(ct.get("model_name"), str)
            ),
            None,
        )
        if name is None:
            unknown.append(cpu_id)
        else:
            types.setdefault(name, []).append(cpu_id)
    if len(types) == 1 and not unknown:
        return next(iter(types))
    covered = "+".join(sorted(types))
    if types:
        return f"mixed: {covered}" + (
            f" (+unknown: {sut.format_cpulist(unknown)})" if unknown else ""
        )
    return sut.unavailable("error", f"no core type covers cpus {sut.format_cpulist(cpuset)}")


def run_scope_sut(
    host_record: dict[str, Json],
    tools: list[dict[str, Json]],
    per_run: dict[str, Json],
    run_times: tuple[datetime, datetime],
    pcaps: Sequence[dict[str, str]],
) -> dict[str, Json]:
    """The run-scope SUT record: the host record plus the run's own fields.

    ``sut_hash`` is recomputed — it covers only the hardware and OS sections,
    so it equals the host record's — and the record must validate under the
    schema's run scope (``tools`` a real array, ``harness.run`` and
    ``harness.pcaps`` objects, ``container_runtime.limits.per_run`` a
    cgroup-limits object).
    """
    record = copy.deepcopy(host_record)
    start, end = run_times
    record["scope"] = "run"
    record["tools"] = tools
    runtime = record.get("container_runtime")
    if isinstance(runtime, dict) and isinstance(runtime.get("limits"), dict):
        runtime["limits"]["per_run"] = per_run
    # A missing or marker container_runtime/harness stays untouched: the
    # schema check below then marks the run invalid rather than crashing.
    harness = record.get("harness")
    if isinstance(harness, dict):
        harness["run"] = {"start": _iso(start), "end": _iso(end)}
        harness["pcaps"] = list(pcaps)
    # An unhashable record is an invalid one; validate reports why.
    with contextlib.suppress(KeyError, TypeError):
        record["sut_hash"] = sut.sut_hash(record)
    return record


def _slug(cell: Cell) -> str:
    """A short filename-safe summary of the cell."""
    raw = (
        f"{cell.tool}-{cell.corpus.label}-{cell.ruleset.id}-"
        f"{cell.config_profile}-t{cell.threads}-c{cell.cpuset_str or 'all'}"
    )
    return re.sub(r"[^a-z0-9._-]+", "_", raw.lower())[:80]


def _pass_record(
    kind: str, n: int, outcome: offline.Outcome, gt: truth.GroundTruth | None, tool: str
) -> dict[str, Json]:
    """One pass of a run as the run's JSON records it."""
    record: dict[str, Json] = {
        "kind": kind,
        "n": n,
        "status": outcome.status,
        "wall_s": round(outcome.wall_s, 6),
        "returncode": outcome.returncode,
    }
    if outcome.status != "ok":
        record["detail"] = outcome.detail
        return record
    assert outcome.counters is not None and outcome.alerts is not None
    counters = outcome.counters
    wall = outcome.wall_s
    record.update(
        {
            "packets": counters.packets,
            "bytes": counters.bytes,
            "drops": counters.drops,
            "gbps": round(counters.bytes * 8 / wall / 1e9, 4) if wall > 0 else None,
            "mpps": round(counters.packets / wall / 1e6, 4) if wall > 0 else None,
            "alerts": len(outcome.alerts),
            "extra": dict(counters.extra),
        }
    )
    if gt is not None:
        record["detection"] = truth.score(outcome.alerts, gt, tool=tool).to_dict()
    return record


def run_cell(
    adapter: Adapter,
    campaign: Campaign,
    cell: Cell,
    *,
    workdir: Path,
    stage_dir: Path,
    tmpfs: bool,
    host_record: dict[str, Json],
    batch: str,
    clock: Callable[[], datetime] = utcnow,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Json]:
    """Run one matrix cell: one warm-up pass, then ``repeats`` measured ones.

    Returns the run record, which the caller writes under ``runs/``. The
    record embeds the run-scope SUT; when that record does not validate, the
    run is ``invalid``.
    """
    started = clock()
    staged = offline.stage_pcap(cell.corpus.path, cell.corpus.sha256, stage_dir)

    passes: list[dict[str, Json]] = []
    plan = [("warmup", 0), *[("measured", n) for n in range(1, campaign.repeats + 1)]]
    for kind, n in plan:
        outcome = offline.run_pass(
            adapter,
            cell.ruleset,
            cell.config_profile,
            workdir / ("warmup" if kind == "warmup" else f"pass-{n}"),
            staged,
            cell.threads,
            cell.cpuset,
            campaign.timeout_s,
            clock=monotonic,
        )
        passes.append(_pass_record(kind, n, outcome, cell.corpus.truth, adapter.name))
    ended = clock()

    problems: list[str] = []
    try:
        tools = [adapter.tools_record()]
    except Exception as exc:
        tools = []
        problems.append(f"tools record: {type(exc).__name__}: {exc}")
    try:
        per_run = adapter.container_limits(cell.cpuset)
    except Exception as exc:
        marker = sut.unavailable("error", f"the run's container limits: {exc}")
        per_run = {"cpu_max": marker, "memory_max": marker, "cpuset_cpus": marker}

    run_sut = run_scope_sut(
        host_record,
        tools,
        per_run,
        (started, ended),
        [{"name": cell.corpus.label, "sha256": cell.corpus.sha256}],
    )
    problems.extend(validate.sut_errors(run_sut))

    measured = [p for p in passes if p["kind"] == "measured"]
    ok = sum(1 for p in measured if p["status"] == "ok")
    if problems:
        status = "invalid"
    elif ok == 0:
        status = "timeout" if any(p["status"] == "timeout" for p in measured) else "error"
    elif ok < len(measured):
        status = "partial"
    else:
        status = "ok"

    cell_desc: dict[str, Json] = {
        "index": cell.index,
        "tool": cell.tool,
        "ruleset": {"id": cell.ruleset.id, "sha256": cell.ruleset.sha256()},
        "config_profile": cell.config_profile,
        "corpus": cell.corpus.ref,
        "threads": cell.threads,
        "cpuset": cell.cpuset_str,
        "core_type": core_type(host_record, cell.cpuset),
    }
    return {
        "schema_version": 1,
        "batch": batch,
        "campaign": campaign.meta(),
        "cell": cell_desc,
        "status": status,
        "problems": problems,
        "started_at": _iso(started),
        "ended_at": _iso(ended),
        "mode": {"name": "offline", "pcap_staged": staged.name, "tmpfs": tmpfs},
        "passes": passes,
        "sut": run_sut,
    }


@dataclass
class CampaignOutcome:
    """What ``run_campaign`` left on disk."""

    directory: Path
    sut_file: Path | None
    run_files: list[Path] = field(default_factory=list)
    report_file: Path | None = None
    runs: list[dict[str, Json]] = field(default_factory=list)

    @property
    def valid(self) -> int:
        return sum(1 for r in self.runs if r["status"] in ("ok", "partial"))

    @property
    def invalid(self) -> int:
        return sum(1 for r in self.runs if r["status"] == "invalid")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.runs if r["status"] in ("timeout", "error"))


def _collect_sut() -> dict[str, Json]:
    """The campaign's host-scope record, collected as the invoking user.

    The hostname is anonymised to ``sut`` (results are committed to a public
    repository); the collector never uses sudo.
    """
    return sut.collect(hostsrc.LiveSource(), sut.Options(alias="sut"))


def run_campaign(
    campaign: Campaign,
    *,
    results_dir: Path = DEFAULT_RESULTS,
    adapters: Mapping[str, Callable[[], Adapter]] | None = None,
    collect: Callable[[], dict[str, Json]] | None = None,
    batch: str | None = None,
    clock: Callable[[], datetime] = utcnow,
    monotonic: Callable[[], float] = time.monotonic,
    tmpfs: Path | bool | None = None,
    work_root: Path | None = None,
    out: Callable[[str], None] = print,
    err: Callable[[str], None] = lambda line: print(line, file=sys.stderr),
) -> CampaignOutcome:
    """Run ``campaign`` and write its results directory.

    ``collect`` returns the campaign's host-scope SUT record (default: a live
    collection as the invoking user, anonymised). ``adapters`` maps tool
    names to adapter factories (default: ``mbench.adapters.ADAPTERS``).
    ``tmpfs`` selects the staging directory: ``None`` or ``True``
    auto-detects, a :class:`Path` forces one, ``False`` disables tmpfs
    staging (recorded as ``tmpfs: false``).
    """
    factories = dict(ADAPTERS) if adapters is None else dict(adapters)
    collect_sut = _collect_sut if collect is None else collect
    now = clock()
    directory = results_dir / f"{now.strftime('%Y-%m-%d')}-{campaign.name}"
    batch_id = _free_batch(directory, batch or _batch_id(now))
    runs_dir = directory / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    outcome = CampaignOutcome(directory, None)

    if campaign.quiet_host:
        out("mbench run: this campaign asks for a quiet host — run this first:")
        out(f"    {QUIET_STOP}")
        out("mbench run: and when it finishes:")
        out(f"    {QUIET_START}")
        err("mbench run: the harness does not run these itself (no sudo).")

    host_record = collect_sut()
    sut_file = _unique(directory / "sut.json", batch_id, ".json")
    write(sut_file, json.dumps(host_record, indent=2, ensure_ascii=False) + "\n")
    outcome.sut_file = sut_file

    if tmpfs is None or tmpfs is True:
        stage_dir_root = offline.tmpfs_dir()
    elif tmpfs is False:
        stage_dir_root = None
    else:
        stage_dir_root = tmpfs
    if stage_dir_root is None:
        err("mbench run: no tmpfs mount found: captures are staged on the regular filesystem")

    with tempfile.TemporaryDirectory(prefix="mbench-run-", dir=work_root) as work_root_dir:
        work = Path(work_root_dir)
        on_tmpfs = stage_dir_root is not None
        stage_dir = work / "staged"
        if stage_dir_root is not None:
            stage_dir = stage_dir_root / f"mbench-{batch_id}"
        for cell in campaign.cells:
            try:
                adapter = factories[cell.tool]()
            except Exception as exc:
                err(f"cell {cell.index} ({cell.tool}): adapter failed: {exc}")
                record = {
                    "schema_version": 1,
                    "batch": batch_id,
                    "campaign": campaign.meta(),
                    "cell": {"index": cell.index, "tool": cell.tool},
                    "status": "error",
                    "problems": [f"adapter {cell.tool}: {type(exc).__name__}: {exc}"],
                    "started_at": _iso(now),
                    "ended_at": _iso(now),
                    "mode": {"name": campaign.mode, "tmpfs": on_tmpfs},
                    "passes": [],
                }
            else:
                record = run_cell(
                    adapter,
                    campaign,
                    cell,
                    workdir=work / f"cell-{cell.index:03d}",
                    stage_dir=stage_dir,
                    tmpfs=on_tmpfs,
                    host_record=host_record,
                    batch=batch_id,
                    clock=clock,
                    monotonic=monotonic,
                )
            outcome.runs.append(record)
            path = runs_dir / f"{batch_id}-{cell.index:03d}-{_slug(cell)}.json"
            write(path, json.dumps(record, indent=2, ensure_ascii=False) + "\n")
            outcome.run_files.append(path)
            err(f"cell {cell.index + 1}/{len(campaign.cells)} ({_slug(cell)}): {record['status']}")

    from mbench.report import render

    report = render.render_dir(directory)
    report_file = _unique(directory / "REPORT.md", batch_id, ".md")
    write(report_file, report)
    outcome.report_file = report_file
    return outcome
