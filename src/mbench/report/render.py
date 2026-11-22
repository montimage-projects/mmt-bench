"""Render REPORT.md over a results directory (#8), like m-bench.

The report answers the campaign's question: a verdict line, the setup table
from ``sut.json``, and one row per matrix cell — median and IQR over the
*measured* passes only (the warm-up is never counted), the CV flagged when
it exceeds 5 %, the detection rate next to the throughput. A run is listed
explicitly when it is not in the results table: ``invalid`` (its SUT record
failed validation), ``timeout``, ``error`` or ``interrupted`` (no measured
pass completed, or the run crashed or was interrupted).
Runs are compared only when their ``sut_hash`` matches; a mismatch between
the run files in one directory is called out, with a note when it comes only
from the fields that need root to read.
"""

from __future__ import annotations

import json
import random
import statistics
from dataclasses import dataclass, field
from pathlib import Path

from mbench import sut
from mbench.adapters.base import Json

#: The rerun flag of docs/methodology.md: a cell whose coefficient of
#: variation over its measured passes exceeds this is flagged.
CV_FLAG = 0.05

#: The 95% interval's resample count and fixed seed (methodology,
#: Statistics): a bootstrap over the cell's measured-pass values, seeded so
#: a re-render of the same runs reports the same interval.
CI_RESAMPLES = 2000
CI_SEED = 0xB3C1

#: The hashed fields whose value depends on whether the collector ran as
#: root (dmidecode, bpf_jit sysctls): a mismatch confined to these means the
#: runs were probably collected with different privileges, not on a
#: different machine.
_ROOT_ONLY_PATHS = {
    "host.memory.speed",
    "host.memory.type",
    "os.sysctl_net_core.bpf_jit_harden",
    "os.sysctl_net_core.bpf_jit_kallsyms",
    "os.sysctl_net_core.bpf_jit_limit",
}


@dataclass(frozen=True)
class RunFile:
    """A ``runs/*.json`` record, with where it came from."""

    name: str
    record: dict[str, Json]


@dataclass(frozen=True)
class CellStats:
    """A run's statistics over its ok measured passes; ``None`` when it has none."""

    run: RunFile
    measured: list[dict[str, Json]] = field(default_factory=list)
    ok: list[dict[str, Json]] = field(default_factory=list)
    gbps_median: float | None = None
    gbps_iqr: float | None = None
    gbps_cv: float | None = None
    gbps_ci: tuple[float, float] | None = None
    mpps_median: float | None = None
    cpp_median: float | None = None
    cpp_iqr: float | None = None
    detection_rate: float | None = None
    precision: float | None = None


def _median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def _percentile(sorted_xs: list[float], q: float) -> float:
    """The ``q``-percentile of ``sorted_xs``, linear interpolation between ranks."""
    if not sorted_xs:
        raise ValueError("percentile of no values")
    if len(sorted_xs) == 1:
        return sorted_xs[0]
    pos = (len(sorted_xs) - 1) * q / 100
    lo = int(pos)
    frac = pos - lo
    if lo + 1 >= len(sorted_xs):
        return sorted_xs[-1]
    return sorted_xs[lo] + frac * (sorted_xs[lo + 1] - sorted_xs[lo])


def _iqr(values: list[float]) -> float | None:
    """The interquartile range (p75 - p25) of ``values``."""
    if len(values) < 2:
        return 0.0 if values else None
    xs = sorted(values)
    return _percentile(xs, 75) - _percentile(xs, 25)


def _cv(values: list[float]) -> float | None:
    """The coefficient of variation (sample stdev / mean); 0 under 2 samples."""
    if len(values) < 2:
        return 0.0 if values else None
    mean = statistics.fmean(values)
    if mean == 0:
        return None
    return statistics.stdev(values) / mean


def median_ci(values: list[float]) -> tuple[float, float] | None:
    """The 95% interval of the median, bootstrap over the pass values.

    Each of ``CI_RESAMPLES`` resamples of ``values`` (with replacement)
    gives a median; the interval is the 2.5-97.5 percentiles of those
    medians. The generator is seeded (``CI_SEED``), so a re-render over the
    same runs prints the same interval — the report must be reproducible.
    With fewer than two values the interval is the value itself (or absent).
    """
    if not values:
        return None
    if len(values) == 1:
        return (values[0], values[0])
    rng = random.Random(CI_SEED)
    medians = sorted(
        statistics.median(rng.choices(values, k=len(values))) for _ in range(CI_RESAMPLES)
    )
    return (
        _percentile(medians, 2.5),
        _percentile(medians, 97.5),
    )


def cell_stats(run: RunFile) -> CellStats:
    """The statistics of one run file: measured ok passes only."""
    passes = run.record.get("passes") or []
    measured = [p for p in passes if p.get("kind") == "measured"]
    ok = [p for p in measured if p.get("status") == "ok"]
    gbps = [p["gbps"] for p in ok if isinstance(p.get("gbps"), int | float)]
    mpps = [p["mpps"] for p in ok if isinstance(p.get("mpps"), int | float)]
    rates = [
        p["detection"]["detection_rate"]
        for p in ok
        if isinstance(p.get("detection"), dict)
        and isinstance(p["detection"].get("detection_rate"), int | float)
    ]
    precisions = [
        p["detection"]["precision"]
        for p in ok
        if isinstance(p.get("detection"), dict)
        and isinstance(p["detection"].get("precision"), int | float)
    ]
    cpps = [
        p["perf"]["cycles_per_packet"]
        for p in ok
        if isinstance(p.get("perf"), dict)
        and isinstance(p["perf"].get("cycles_per_packet"), int | float)
    ]
    return CellStats(
        run=run,
        measured=measured,
        ok=ok,
        gbps_median=_median(gbps),
        gbps_iqr=_iqr(gbps),
        gbps_cv=_cv(gbps),
        gbps_ci=median_ci(gbps),
        mpps_median=_median(mpps),
        cpp_median=_median(cpps),
        cpp_iqr=_iqr(cpps),
        detection_rate=_median(rates),
        precision=_median(precisions),
    )


def _sut_batch(path: Path) -> tuple[str, int]:
    """The batch key of a ``sut*.json`` name; ``sut.json`` is the oldest.

    Later batches are ``sut-<batch>.json`` and ``sut-<batch>-N.json``; the
    batch id is a UTC timestamp (``YYYYMMDDTHHMMSSZ``) so it sorts as text,
    and the ``-N`` rerun suffix orders numerically.
    """
    stem = path.stem
    if stem == "sut":
        return ("", 0)
    base, _, n = stem.removeprefix("sut-").rpartition("-")
    return (base, int(n)) if n.isdigit() else (stem.removeprefix("sut-"), 1)


def load_dir(directory: Path) -> tuple[dict[str, Json] | None, list[RunFile]]:
    """The ``sut*.json`` host record (newest batch first) and every ``runs/*.json``."""
    host = None
    for name in sorted(directory.glob("sut*.json"), key=_sut_batch, reverse=True):
        try:
            data = json.loads(name.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            host = data
            break
    runs = []
    runs_dir = directory / "runs"
    if runs_dir.is_dir():
        for path in sorted(runs_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                runs.append(RunFile(path.name, data))
    return host, runs


def _get(record: dict[str, Json] | None, path: str, default: str = "—") -> str:
    """A field of the SUT record for the setup table; markers shown as their kind."""
    value: Json = record or {}
    for part in path.split("."):
        if not isinstance(value, dict):
            return default
        value = value.get(part)
    if value is None:
        return default
    if isinstance(value, dict) and "unavailable" in value:
        return f"unavailable ({value['unavailable']})"
    if isinstance(value, dict | list):
        return json.dumps(value)
    return str(value)


def _setup_table(host: dict[str, Json] | None) -> list[str]:
    """The setup table of REPORT.md, from the host-scope sut.json."""
    if host is None:
        return ["*(no sut.json in this directory)*", ""]
    core_types = host.get("host", {}).get("cpu", {}).get("core_types")
    cpu = "—"
    if isinstance(core_types, list) and core_types:
        parts = []
        for ct in core_types:
            if isinstance(ct, dict):
                parts.append(
                    f"{ct.get('model_name', '?')} x{ct.get('count', '?')} "
                    f"(cpus {ct.get('cpus', '?')}, {ct.get('governor', '?')})"
                )
        cpu = ", ".join(parts) if parts else _get(host, "host.cpu.core_types")
    memory = host.get("host", {}).get("memory", {})
    total_kib = memory.get("total_kib") if isinstance(memory, dict) else None
    mem = f"{total_kib / 1048576:.1f} GiB" if isinstance(total_kib, int) else "—"
    nics = host.get("nics")
    nic_names = (
        ", ".join(str(n.get("name")) for n in nics if isinstance(n, dict))
        if isinstance(nics, list)
        else "—"
    )
    rows = {
        "host": _get(host, "host.hostname"),
        "architecture": _get(host, "host.architecture"),
        "machine": (
            f"{_get(host, 'host.dmi_vendor', '?')} {_get(host, 'host.dmi_model', '?')}".strip()
        ),
        "cpu": cpu,
        "memory": mem,
        "nics": nic_names,
        "distro": _get(host, "os.distro"),
        "kernel": f"{_get(host, 'os.kernel.release')} ({_get(host, 'os.kernel.version', '?')})",
        "docker": _get(host, "container_runtime.docker.server_version"),
        "vllm stopped": _get(host, "noise.vllm_stopped"),
    }
    lines = ["| field | value |", "| --- | --- |"]
    lines += [f"| {k} | {v} |" for k, v in rows.items()]
    return [*lines, ""]


def _fmt(v: float | None, fmt: str = "{:.3g}") -> str:
    return fmt.format(v) if v is not None else "—"


def _detected(stats: CellStats) -> str:
    """The detection-rate cell: rate and precision together."""
    if stats.detection_rate is None:
        return "—"
    if stats.precision is None:
        return f"{stats.detection_rate:.0%}"
    return f"{stats.detection_rate:.0%} (p {stats.precision:.0%})"


def _verdict(cells: list[CellStats], question: str) -> str:
    """One sentence answering the campaign's question from the measured cells."""
    measured_cells = [c for c in cells if c.gbps_median is not None]
    if not measured_cells:
        return (
            "**No valid measurement**: no run has an ok measured pass — "
            "see *Invalid and failed runs* below."
        )
    best = max(measured_cells, key=lambda c: c.gbps_median or 0)
    cell = best.run.record.get("cell", {})
    det = ""
    if best.detection_rate is not None:
        det = f", detecting {_fmt(best.detection_rate, '{:.0%}')} of the expected attacks"
    ci = ""
    if best.gbps_ci is not None:
        lo, hi = best.gbps_ci
        ci = f", 95% CI {_fmt(lo, '{:.4g}')}-{_fmt(hi, '{:.4g}')}"
    return (
        f"On this SUT, **{cell.get('tool', '?')}** ({cell.get('config_profile', '?')}, "
        f"{cell.get('threads', '?')} thread(s), {cell.get('core_type', '?')}) reached a median "
        f"**{_fmt(best.gbps_median, '{:.4g}')} Gbit/s**{ci} ({_fmt(best.mpps_median)} Mpps) on "
        f"`{cell.get('corpus', {}).get('label', '?')}`{det} — "
        f"the fastest of {len(measured_cells)} measured cell(s)."
    )


def _differing_paths(a: Json, b: Json, prefix: str = "") -> set[str]:
    """The leaf paths where two hash-input trees differ."""
    if isinstance(a, dict) and isinstance(b, dict):
        out: set[str] = set()
        for key in sorted(set(a) | set(b)):
            out |= _differing_paths(a.get(key), b.get(key), f"{prefix}.{key}" if prefix else key)
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = set()
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            out |= _differing_paths(x, y, f"{prefix}[{i}]")
        return out
    return set() if a == b else {prefix or "(record)"}


def _hash_notes(runs: list[RunFile]) -> list[str]:
    """Warnings about ``sut_hash`` mismatches between the runs."""
    by_hash: dict[str, list[str]] = {}
    for run in runs:
        record = run.record.get("sut")
        if isinstance(record, dict) and isinstance(record.get("sut_hash"), str):
            by_hash.setdefault(record["sut_hash"], []).append(run.name)
    if len(by_hash) <= 1:
        return []
    notes = [
        f"- ⚠ **sut_hash mismatch**: {len(by_hash)} different SUT hashes — "
        "runs are comparable only within one hash:"
    ]
    for h, names in sorted(by_hash.items()):
        notes.append(f"  - `{h}`: {', '.join(names)}")
    # Is the mismatch confined to the fields that need root? Compare the
    # hash inputs of one record per hash.
    records = []
    for h in by_hash:
        run = next(r for r in runs if r.record["sut"]["sut_hash"] == h)
        records.append(sut.hash_input(run.record["sut"]))
    diff: set[str] = set()
    for other in records[1:]:
        diff |= _differing_paths(records[0], other)
    if diff and diff <= _ROOT_ONLY_PATHS:
        notes.append(
            "  - the difference is confined to fields only root can read "
            f"({', '.join(sorted(diff))}): the runs were probably collected "
            "with different privileges, not on a different host."
        )
    else:
        notes.append(f"  - differing fields: {', '.join(sorted(diff)) or '(record)'}")
    return notes


def _results_table(cells: list[CellStats]) -> list[str]:
    """The results table of one core-type series (or of the whole report)."""
    lines = [
        "| corpus | tool | ruleset | profile | threads | cpuset | core type | passes ok "
        "| Gbit/s median (IQR) | Mpps median | cycles/pkt | CV % | detection | run |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for stats in cells:
        cell = stats.run.record.get("cell", {})
        corpus = cell.get("corpus", {})
        cv = stats.gbps_cv
        cv_flag = f"{cv:.1%} ⚠ rerun" if cv is not None and cv > CV_FLAG else _fmt(cv, "{:.1%}")
        cpp = (
            f"{_fmt(stats.cpp_median, '{:.4g}')} ({_fmt(stats.cpp_iqr, '{:.4g}')})"
            if stats.cpp_median is not None
            else "—"
        )
        lines.append(
            "| {corpus} | {tool} | {ruleset} | {profile} | {threads} | {cpuset} | {core} | "
            "{ok}/{n} | {gbps} ({iqr}) | {mpps} | {cpp} | {cv} | {det} | `{run}` |".format(
                corpus=corpus.get("label", "?"),
                tool=cell.get("tool", "?"),
                ruleset=cell.get("ruleset", {}).get("id", "?"),
                profile=cell.get("config_profile", "?"),
                threads=cell.get("threads", "?"),
                cpuset=cell.get("cpuset") or "all",
                core=cell.get("core_type", "?") if isinstance(cell.get("core_type"), str) else "?",
                ok=len(stats.ok),
                n=len(stats.measured),
                gbps=_fmt(stats.gbps_median, "{:.4g}"),
                iqr=_fmt(stats.gbps_iqr, "{:.4g}"),
                mpps=_fmt(stats.mpps_median),
                cpp=cpp,
                cv=cv_flag,
                det=_detected(stats),
                run=stats.run.name,
            )
        )
    lines.append("")
    return lines


def _cell_key(run: RunFile) -> tuple[str, ...]:
    cell = run.record.get("cell", {})
    corpus = cell.get("corpus", {})
    return (
        str(corpus.get("label", "")),
        str(cell.get("tool", "")),
        str(cell.get("ruleset", {}).get("id", "")),
        str(cell.get("config_profile", "")),
        f"{int(cell.get('threads', 0) or 0):04d}",
        str(cell.get("cpuset", "")),
        str(run.name),
    )


def render(
    campaign: dict[str, Json] | None,
    host: dict[str, Json] | None,
    runs: list[RunFile],
) -> str:
    """REPORT.md over ``runs``, with ``campaign`` and ``host`` from the directory."""
    meta = campaign or {}
    name = meta.get("name") or "campaign"
    question = meta.get("question") or "(no question recorded)"
    tools = sorted(
        {
            str(r.record.get("cell", {}).get("tool", "?"))
            for r in runs
            if isinstance(r.record.get("cell"), dict)
        }
    )
    cells = sorted((cell_stats(r) for r in runs), key=lambda s: _cell_key(s.run))
    invalid = [c for c in cells if c.run.record.get("status") == "invalid"]
    failed = [c for c in cells if c.run.record.get("status") in ("timeout", "error", "interrupted")]
    compared = len(tools) > 1

    out: list[str] = [
        f"# {name}: {question}",
        "",
        f"> **Question:** {question}",
        f"> **Verdict:** {_verdict(cells, question)}",
        "",
    ]
    if compared:
        out += [
            "> ⚠ **Tool-comparison report** ("
            + ", ".join(tools)
            + "): keep it under `local/` until the licence and fairness review.",
            "",
        ]
    if meta:
        out += [
            f"mode `{meta.get('mode', 'offline')}` · repeats {meta.get('repeats', '?')} "
            f"· timeout {meta.get('timeout_s', '?')} s"
            + (" · quiet host requested" if meta.get("quiet_host") else ""),
            "",
        ]
    if host is not None and isinstance(host.get("sut_hash"), str):
        out += [f"SUT `{host['sut_hash']}`", ""]

    out += ["## Setup", ""]
    out += _setup_table(host)
    # One table per core-type series when the campaign pinned to several
    # (P1: the X925 and A725 series); a single-type campaign keeps one table.
    series: dict[str, list[CellStats]] = {}
    for stats in cells:
        if stats.run.record.get("status") == "invalid":
            continue
        core = stats.run.record.get("cell", {}).get("core_type")
        key = core if isinstance(core, str) else "—"
        series.setdefault(key, []).append(stats)
    multi = len([k for k in series if k not in {"—", "unpinned"}]) > 1
    for name in sorted(series):
        out += [f"## Results — {name}" if multi else "## Results", ""]
        out += _results_table(series[name])
    out += [
        "Median over the measured passes of each run; the warm-up pass is never "
        "counted. A cell flagged ⚠ rerun has a coefficient of variation over "
        f"{CV_FLAG:.0%} (methodology: rerun before comparing). The Gbit/s 95% "
        "CI is a seeded bootstrap over the cell's measured passes (methodology).",
        "",
    ]
    reasons = sorted(
        {
            f"{p['perf']['unavailable']}: {p['perf'].get('reason', '')}"
            for stats in cells
            for p in stats.measured
            if isinstance(p.get("perf"), dict) and "unavailable" in p["perf"]
        }
    )
    if reasons:
        out += ["- cycles/pkt unavailable — " + "; ".join(reasons), ""]
    if invalid or failed:
        out += ["## Invalid and failed runs", ""]
        out += ["| run | status | detail |", "| --- | --- | --- |"]
        for stats in [*invalid, *failed]:
            record = stats.run.record
            problems = record.get("problems") or []
            detail = (
                f"{len(problems)} problem(s): {problems[0]}"
                if problems
                else f"{len(stats.ok)}/{len(stats.measured)} measured passes ok"
            )
            out.append(f"| `{stats.run.name}` | {record.get('status')} | {detail} |")
        out.append("")
        out += [
            "An `invalid` run's SUT record failed validation: it is written but "
            "excluded from every table above.",
            "",
        ]
    notes = _hash_notes(runs)
    if notes:
        out += ["## Notes", "", *notes, ""]
    if len(cells) == 0:
        out += ["*(no run files found)*", ""]
    return "\n".join(out)


def render_dir(directory: Path | str) -> str:
    """REPORT.md over a results directory (``runs/*.json`` + ``sut*.json``)."""
    directory = Path(directory)
    host, runs = load_dir(directory)
    campaign = None
    for run in runs:
        meta = run.record.get("campaign")
        if isinstance(meta, dict):
            campaign = meta
            break
    return render(campaign, host, runs)
