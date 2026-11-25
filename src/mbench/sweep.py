"""``mbench sweep`` (#17): a one-parameter sweep over a campaign (plan §B2).

Two shapes, both built on the matrix expansion of :mod:`mbench.matrix` and
the runner of :mod:`mbench.runner` — the matrix and run logic are not
written twice:

- **list sweep** — ``mbench sweep <campaign> --param <p> --values
  v1,v2,...`` expands the campaign's matrix with the swept dimension set
  to the given values, a one-axis matrix;
- **binary search** — ``mbench sweep <campaign> --param rate --search
  <lo>:<hi> --until <condition>`` probes the offered rate in a
  deterministic bisection for the highest value satisfying the condition
  — #13's lossless-rate search, which a run matrix cannot express.

Every step is a normal run through :func:`runner.run_campaign` with a
complete SUT record; results go under
``results/<date>-<campaign>-sweep-<param>/`` — the runs, ``sut*.json`` and
``REPORT*.md`` files of every step, append-only — plus a ``SWEEP.json``
summary (checked by ``mbench validate`` against
``schemas/sweep.schema.json``) and the same table as ``SWEEP.md``.

Sweepable parameters
--------------------

``--param`` accepts:

- ``threads`` — the campaign's ``threads`` dimension (integers);
- ``ruleset`` — the ``rulesets`` dimension, by ruleset id (the N-rule
  sweep of #11 is a list sweep over generated ruleset ids);
- ``corpus`` — the ``corpus`` dimension, by manifest label (the
  flow-count sweep of #12 is a list sweep over the ``c-flows-*`` labels);
- ``rate`` — the offered replay rate of the online mode (#13). It is not
  a campaign-file dimension, so the sweep pins it on each cell's
  ``extra`` and every run records it as ``cell.rate``; the online mode
  reads the same field. On an offline campaign it is recorded, never
  played.

Any other name is rejected. ``--search`` is defined for ``rate`` only:
it is the one numeric sweep parameter that is not already a list
dimension.

The stop condition
------------------

``--until`` takes ``<metric><op><value>`` with ``op`` one of ``==``,
``!=``, ``<``, ``<=``, ``>``, ``>=`` and ``metric`` one of the numbers a
run records, aggregated over the step's ok measured passes:

- ``loss`` — ``drops`` / ``packets`` (``drops`` counts only when every
  measured pass reports a drop counter — a run without one cannot claim
  zero loss; the online mode records tool plus kernel drops there, #13);
- ``gbps``, ``mpps`` — medians of the pass rates;
- ``packets``, ``bytes``, ``drops``, ``alerts`` — sums;
- ``detection_rate``, ``precision`` — medians of the passes that scored
  them.

``loss==0`` and ``loss<=0.001`` are the #13 forms. A metric the step did
not record makes the condition false. With ``--values``, ``--until`` is
optional and only marks each step's ``pass`` in the summary; with
``--search`` it is required and drives the bisection, which stops when
the bracket is within ``--tolerance`` (in the parameter's units, default
0 = no early stop), collapses, or ``--max-steps`` probes ran (default
:data:`DEFAULT_MAX_STEPS`). The probe order is deterministic: the upper
bound first — when it satisfies, the answer is exact after one step —
then the bracket's midpoint, keeping ``lo`` feasible and ``hi``
infeasible.
"""

from __future__ import annotations

import copy
import json
import math
import operator
import re
import statistics
import sys
import time
from collections.abc import Callable, Generator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, TypeGuard

import yaml

from mbench import corpus, matrix, runner
from mbench.adapters.base import Adapter, Json
from mbench.metrics import perf


class SweepError(ValueError):
    """The sweep cannot be built: a bad param, value list, range or condition."""

    def __init__(self, message: str, problems: Sequence[str] = ()) -> None:
        self.problems = list(problems)
        super().__init__(message)


#: The parameters ``--param`` accepts.
SWEEPABLE = ("corpus", "rate", "ruleset", "threads")

#: The campaign-file dimension each sweepable parameter sets; ``rate``
#: has none — it is pinned on the cells' ``extra`` instead (:mod:`matrix`).
_DIMENSION: dict[str, str | None] = {
    "threads": "threads",
    "ruleset": "rulesets",
    "corpus": "corpus",
    "rate": None,
}

#: The probe cap of a binary search when ``--max-steps`` is not given.
DEFAULT_MAX_STEPS = 16

#: The metrics ``--until`` conditions may name (see the module docstring).
METRICS = (
    "loss",
    "gbps",
    "mpps",
    "packets",
    "bytes",
    "drops",
    "alerts",
    "detection_rate",
    "precision",
)

_OPS = {
    "==": operator.eq,
    "!=": operator.ne,
    "<=": operator.le,
    ">=": operator.ge,
    "<": operator.lt,
    ">": operator.gt,
}

_CONDITION = re.compile(
    r"^\s*([a-z][a-z0-9_]*)\s*(==|!=|<=|>=|<|>)\s*"
    r"(-?[0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?)\s*$"
)
_BOUNDS = re.compile(r"^\s*([^:]+)\s*:\s*([^:]+)\s*$")

#: A step's status is its runs' worst: ``ok`` < ``partial`` < ``invalid``
#: < ``timeout`` < ``error`` < ``interrupted`` (methodology's statuses).
_SEVERITY = {"ok": 0, "partial": 1, "invalid": 2, "timeout": 3, "error": 4, "interrupted": 5}


@dataclass(frozen=True)
class Condition:
    """A parsed ``--until`` condition: ``<metric><op><threshold>``."""

    metric: str
    op: str
    threshold: float

    def __str__(self) -> str:
        return f"{self.metric}{self.op}{self.threshold:g}"

    def satisfied(self, metrics: Mapping[str, Json]) -> bool:
        """Whether the step's metrics satisfy the condition.

        A metric the step did not record (``None``) never satisfies —
        a run without a drop counter cannot claim ``loss==0``.
        """
        value = metrics.get(self.metric)
        if not _is_num(value):
            return False
        return bool(_OPS[self.op](value, self.threshold))


def _is_num(value: Any) -> TypeGuard[int | float]:
    """A real JSON number (a bool is an int in Python — never a metric)."""
    return isinstance(value, int | float) and not isinstance(value, bool)


def parse_condition(text: str) -> Condition:
    """Parse ``<metric><op><value>``; raise :class:`SweepError` otherwise."""
    match = _CONDITION.match(text)
    if match is None:
        raise SweepError(
            f"--until: {text!r} is not a condition — the grammar is "
            f"<metric><op><value>, e.g. 'loss==0' or 'loss<=0.001' "
            f"(op one of {', '.join(_OPS)})"
        )
    metric, op, threshold = match.group(1), match.group(2), float(match.group(3))
    if metric not in METRICS:
        raise SweepError(
            f"--until: unknown metric {metric!r} (a run records: {', '.join(METRICS)})"
        )
    return Condition(metric, op, threshold)


def parse_bounds(text: str) -> tuple[float, float]:
    """Parse ``--search``'s ``<lo>:<hi>``; raise :class:`SweepError` otherwise."""
    match = _BOUNDS.match(text)
    if match is None:
        raise SweepError(f"--search: {text!r} is not a <lo>:<hi> range")
    try:
        lo, hi = float(match.group(1).strip()), float(match.group(2).strip())
    except ValueError:
        raise SweepError(f"--search: {text!r} is not a numeric <lo>:<hi> range") from None
    if not math.isfinite(lo) or not math.isfinite(hi):
        raise SweepError(f"--search: bounds must be finite, got {text!r}")
    if not lo < hi:
        raise SweepError(f"--search: need lo < hi, got {lo:g}:{hi:g}")
    return lo, hi


def _check_param(param: str) -> None:
    if param not in SWEEPABLE:
        raise SweepError(
            f"--param: unknown sweep parameter {param!r} (sweepable: {', '.join(SWEEPABLE)})"
        )


def _coerce(param: str, value: Any) -> Any:
    """One ``--values`` item as the parameter's type."""
    if param == "threads":
        if isinstance(value, bool):
            raise SweepError(f"--param threads: {value!r} is not an integer")
        try:
            return int(value)
        except (TypeError, ValueError):
            raise SweepError(f"--param threads: {value!r} is not an integer") from None
    if param == "rate":
        if isinstance(value, bool):
            raise SweepError(f"--param rate: {value!r} is not a number")
        try:
            rate = float(value)
        except (TypeError, ValueError):
            raise SweepError(f"--param rate: {value!r} is not a number") from None
        if not math.isfinite(rate):
            raise SweepError(f"--param rate: {value!r} is not finite")
        return rate
    if not isinstance(value, str) or not value:
        raise SweepError(f"--param {param}: {value!r} must be a non-empty string")
    return value


def parse_values(param: str, text: str | Sequence[Any]) -> list[Any]:
    """Parse ``--values`` for ``param``; raise :class:`SweepError` otherwise."""
    _check_param(param)
    if isinstance(text, str):
        raw = [part.strip() for part in text.split(",")]
        if any(not part for part in raw):
            raise SweepError(f"--values: {text!r} is not a comma-separated list of values")
        items: list[Any] = raw
    else:
        items = list(text)
    if not items:
        raise SweepError("--values: at least one value is required")
    return [_coerce(param, v) for v in items]


def _doc_items(param: str, values: Sequence[Any]) -> list[Any]:
    """The ``values`` as items of the parameter's campaign-file dimension."""
    if param == "corpus":
        return [{"label": v} for v in values]
    return list(values)


def _cell_value(param: str, cell: matrix.Cell) -> Any:
    """The value ``param`` takes on ``cell``."""
    if param == "threads":
        return cell.threads
    if param == "ruleset":
        return cell.ruleset.id
    if param == "corpus":
        return cell.corpus.label
    return cell.extra["rate"]


def _median(values: list[int | float]) -> float | None:
    return statistics.median(values) if values else None


def _num(record: Mapping[str, Json], key: str) -> int | float | None:
    """The record's number at ``key``, or ``None`` when it is not one."""
    value = record.get(key)
    return value if _is_num(value) else None


def _record_passes(record: Mapping[str, Json]) -> list[dict[str, Json]]:
    """A run record's pass records, only the ones that are objects."""
    passes = record.get("passes")
    if not isinstance(passes, list):
        return []
    return [p for p in passes if isinstance(p, dict)]


def step_metrics(runs: Sequence[dict[str, Json]]) -> dict[str, Json]:
    """The metrics of one sweep step, over its runs' ok measured passes.

    Every metric of :data:`METRICS`, or ``None`` for what the step did not
    record — never a fabricated 0 — and a ``None`` satisfies no condition.
    ``drops`` (and so ``loss``) counts only when every ok measured pass
    reported a drop counter.
    """
    passes = [
        p
        for record in runs
        for p in _record_passes(record)
        if p.get("kind") == "measured" and p.get("status") == "ok"
    ]
    empty: dict[str, Json] = {metric: None for metric in METRICS}
    if not passes:
        return empty
    drop_values = [_num(p, "drops") for p in passes]
    drops: Json = (
        sum(v for v in drop_values if v is not None)
        if all(v is not None for v in drop_values)
        else None
    )
    packets = sum(v for p in passes if (v := _num(p, "packets")) is not None)
    detections = [d for p in passes if isinstance((d := p.get("detection")), dict)]
    return {
        "loss": (drops / packets) if drops is not None and packets else None,
        "gbps": _median([v for p in passes if (v := _num(p, "gbps")) is not None]),
        "mpps": _median([v for p in passes if (v := _num(p, "mpps")) is not None]),
        "packets": packets,
        "bytes": sum(v for p in passes if (v := _num(p, "bytes")) is not None),
        "drops": drops,
        "alerts": sum(v for p in passes if (v := _num(p, "alerts")) is not None),
        "detection_rate": _median(
            [v for d in detections if (v := _num(d, "detection_rate")) is not None]
        ),
        "precision": _median([v for d in detections if (v := _num(d, "precision")) is not None]),
    }


def _step_status(runs: Sequence[dict[str, Json]]) -> str:
    """A step's status: its runs' worst (``empty`` when it has none)."""
    if not runs:
        return "empty"
    worst = "ok"
    for record in runs:
        status = str(record.get("status"))
        if _SEVERITY.get(status, len(_SEVERITY)) > _SEVERITY[worst]:
            worst = status
    return worst


def _step_record(
    n: int,
    value: Any,
    runs: Sequence[tuple[str, dict[str, Json]]],
    condition: Condition | None,
) -> dict[str, Json]:
    """One ``steps[]`` entry of the summary."""
    metrics = step_metrics([record for _, record in runs])
    return {
        "n": n,
        "value": value,
        "runs": [name for name, _ in runs],
        "status": _step_status([record for _, record in runs]),
        "metrics": {k: (round(v, 6) if _is_num(v) else v) for k, v in metrics.items()},
        "pass": (condition.satisfied(metrics) if condition is not None else None),
    }


def _steps_for(
    param: str,
    cells: Sequence[matrix.Cell],
    values: Sequence[Any],
    named_runs: Sequence[tuple[str, dict[str, Json]]],
    condition: Condition | None,
) -> list[dict[str, Json]]:
    """The ``steps[]`` of a list sweep: its runs grouped by the swept value.

    A value that produced no cells — filtered out by a ``threads``
    restriction — is still a step, with no runs.
    """
    by_index = {cell.index: cell for cell in cells}
    steps = []
    for i, value in enumerate(values):
        step_runs = []
        for run_name, record in named_runs:
            cell = record.get("cell")
            index = cell.get("index") if isinstance(cell, dict) else None
            if (
                isinstance(index, int)
                and not isinstance(index, bool)
                and index in by_index
                and _cell_value(param, by_index[index]) == value
            ):
                step_runs.append((run_name, record))
        steps.append(_step_record(i + 1, value, step_runs, condition))
    return steps


def search_values(
    lo: float,
    hi: float,
    *,
    tolerance: float = 0.0,
    max_steps: int = DEFAULT_MAX_STEPS,
) -> Generator[float, bool, dict[str, Json]]:
    """The deterministic probe order of a max-feasible bisection.

    Yields each value to measure; the caller :meth:`~collections.abc.Generator.send`\\ s
    back whether that step satisfied the stop condition. The first probe
    is ``hi`` — when the whole bracket satisfies the condition the answer
    is exact after one step — then the bracket's midpoint, keeping ``lo``
    the highest value known to satisfy and ``hi`` one known not to. The
    search stops when ``hi - lo`` is within ``tolerance``, the bracket
    collapses to a float midpoint, or ``max_steps`` probes ran.

    Returns (as ``StopIteration.value``) the result: ``best``, the
    highest probed value that satisfied (``None`` when none did),
    ``satisfied``, the ``stop`` reason, the probe count (``steps``) and
    the final ``bracket``.
    """
    best: float | None = None
    steps = 0
    collapsed = False
    satisfied = yield hi
    steps += 1
    if satisfied:
        return {
            "best": hi,
            "satisfied": True,
            "stop": "hi_satisfied",
            "steps": steps,
            "bracket": {"lo": lo, "hi": hi},
        }
    while steps < max_steps and hi - lo > tolerance:
        mid = lo + (hi - lo) / 2
        if mid <= lo or mid >= hi:
            collapsed = True
            break
        satisfied = yield mid
        steps += 1
        if satisfied:
            lo, best = mid, mid
        else:
            hi = mid
    if collapsed:
        stop = "bracket_collapsed"
    else:
        stop = "tolerance" if hi - lo <= tolerance else "max_steps"
    return {
        "best": best,
        "satisfied": best is not None,
        "stop": stop,
        "steps": steps,
        "bracket": {"lo": lo, "hi": hi},
    }


@dataclass
class SweepOutcome:
    """What ``run_sweep`` left on disk."""

    directory: Path
    summary: dict[str, Json]
    summary_json: Path | None = None
    summary_md: Path | None = None
    run_files: list[Path] = field(default_factory=list)
    runs: list[dict[str, Json]] = field(default_factory=list)

    @property
    def valid(self) -> int:
        return sum(1 for r in self.runs if r["status"] in ("ok", "partial"))

    @property
    def invalid(self) -> int:
        return sum(1 for r in self.runs if r["status"] == "invalid")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.runs if r["status"] in ("timeout", "error", "interrupted"))


def _read_doc(path: Path) -> tuple[Any, Path]:
    """The campaign file's parsed document and its path anchor."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise matrix.CampaignError(f"{path}: cannot be read as YAML: {exc}") from None
    return data, matrix.anchor(path)


def _derive(
    data: Any,
    *,
    base: Path,
    name: str,
    path: Path,
    param: str,
    doc_values: Sequence[Any] | None,
    manifest_path: Path,
    topology: dict[str, tuple[int, ...]] | None,
) -> matrix.Campaign:
    """The campaign as the sweep runs it: ``name``, no verdict, one dim set.

    ``verdict_cell`` is dropped: a verdict naming a swept value would no
    longer match every step's cells — the sweep summary is the verdict.
    For ``rate`` there is no campaign dimension to set (``doc_values`` is
    then ``None``); the value reaches the cells through ``extra``.
    """
    doc = copy.deepcopy(data)
    if isinstance(doc, dict):
        doc.pop("verdict_cell", None)
        doc["name"] = name
        dimension = _DIMENSION[param]
        if dimension is not None:
            doc[dimension] = list(doc_values or [])
    return matrix.expand(
        doc,
        base=base,
        manifest_path=manifest_path,
        topology=topology,
        name=name,
        path=path,
    )


def _rate_cells(campaign: matrix.Campaign, value: float) -> list[matrix.Cell]:
    """The campaign's cells with the offered rate pinned on ``extra``."""
    return [replace(cell, extra={**cell.extra, "rate": value}) for cell in campaign.cells]


def _named_runs(outcome: runner.CampaignOutcome) -> list[tuple[str, dict[str, Json]]]:
    """A step's ``(file name, run record)`` pairs — the two lists are parallel."""
    return [(f.name, record) for f, record in zip(outcome.run_files, outcome.runs, strict=True)]


def run_sweep(
    campaign: str | Path,
    *,
    param: str,
    values: str | Sequence[Any] | None = None,
    search: str | None = None,
    until: str | None = None,
    tolerance: float = 0.0,
    max_steps: int = DEFAULT_MAX_STEPS,
    results_dir: Path = runner.DEFAULT_RESULTS,
    manifest_path: Path = corpus.DEFAULT_MANIFEST,
    adapters: Mapping[str, Callable[[], Adapter]] | None = None,
    collect: Callable[[], dict[str, Json]] | None = None,
    clock: Callable[[], datetime] = runner.utcnow,
    monotonic: Callable[[], float] = time.monotonic,
    tmpfs: Path | bool | None = None,
    work_root: Path | None = None,
    perf_probe: perf.Probe | None = None,
    pin_harness: bool = False,
    topology: dict[str, tuple[int, ...]] | None = None,
    out: Callable[[str], None] = print,
    err: Callable[[str], None] = lambda line: print(line, file=sys.stderr),
) -> SweepOutcome:
    """Run the sweep and write its results directory plus the summary.

    ``values`` is a ``v1,v2,...`` string (or an already-parsed sequence);
    ``search`` is ``<lo>:<hi>``. Exactly one of the two is required.
    ``until`` is the stop condition — required for ``search``, optional
    for ``values``. The remaining keyword arguments are
    :func:`runner.run_campaign`'s.
    """
    _check_param(param)
    if values is not None and search is not None:
        raise SweepError("one of --values or --search, not both")
    if search is None and values is None:
        raise SweepError("one of --values <v1,v2,...> or --search <lo>:<hi> is required")
    condition = parse_condition(until) if until is not None else None
    vals: list[Any] = []
    lo = hi = 0.0
    if search is not None:
        if param != "rate":
            raise SweepError(
                "--search is defined over --param rate (the offered rate of the "
                f"online mode, #13); {param!r} is a list dimension — use --values"
            )
        if condition is None:
            raise SweepError("--search needs --until <condition>, e.g. 'loss==0'")
        lo, hi = parse_bounds(search)
        if tolerance < 0:
            raise SweepError(f"--tolerance must be >= 0, got {tolerance:g}")
        if max_steps < 1:
            raise SweepError(f"--max-steps must be >= 1, got {max_steps}")
        mode = "search"
    else:
        assert values is not None
        vals = parse_values(param, values)
        mode = "list"

    path = Path(campaign)
    data, base = _read_doc(path)
    base_name = data.get("name") if isinstance(data, dict) else None
    name = f"{base_name or path.stem}-sweep-{param}"
    now = clock()
    directory = results_dir / f"{now.strftime('%Y-%m-%d')}-{name}"
    batch = runner._batch_id(now)
    started = now

    derived = _derive(
        data,
        base=base,
        name=name,
        path=path,
        param=param,
        doc_values=_doc_items(param, vals) if mode == "list" and param != "rate" else None,
        manifest_path=manifest_path,
        topology=topology,
    )
    if mode == "list" and param == "rate":
        cells = [c for v in vals for c in _rate_cells(derived, v)]
        derived = replace(derived, cells=tuple(replace(c, index=i) for i, c in enumerate(cells)))

    kwargs: dict[str, Any] = {
        "results_dir": results_dir,
        "directory": directory,
        "adapters": adapters,
        "collect": collect,
        "clock": clock,
        "monotonic": monotonic,
        "tmpfs": tmpfs,
        "work_root": work_root,
        "perf_probe": perf_probe,
        "pin_harness": pin_harness,
        "out": out,
        "err": err,
    }
    outcome = SweepOutcome(directory=directory, summary={})
    steps: list[dict[str, Json]] = []
    result: dict[str, Json] | None = None
    interrupted = False
    try:
        if mode == "list":
            run = runner.run_campaign(derived, **kwargs)
            outcome.runs.extend(run.runs)
            outcome.run_files.extend(run.run_files)
            steps = _steps_for(param, derived.cells, vals, _named_runs(run), condition)
        else:
            search_gen = search_values(lo, hi, tolerance=tolerance, max_steps=max_steps)
            try:
                value = next(search_gen)
                while True:
                    step_campaign = replace(derived, cells=tuple(_rate_cells(derived, value)))
                    run = runner.run_campaign(step_campaign, **kwargs)
                    outcome.runs.extend(run.runs)
                    outcome.run_files.extend(run.run_files)
                    named = _named_runs(run)
                    metrics = step_metrics([record for _, record in named])
                    steps.append(_step_record(len(steps) + 1, value, named, condition))
                    try:
                        value = search_gen.send(
                            condition.satisfied(metrics) if condition is not None else False
                        )
                    except StopIteration as stop:
                        if isinstance(stop.value, dict):
                            result = dict(stop.value)
                        break
            finally:
                search_gen.close()
    except BaseException:
        interrupted = True
        # Like the runner's own partial campaign: the steps already on
        # disk still get summarised (for a list sweep the completed cells
        # are read back from the directory).
        if mode == "list" and not steps:
            from mbench.report import render

            try:
                _, runfiles = render.load_dir(directory)
            except OSError:
                runfiles = []
            steps = _steps_for(
                param,
                derived.cells,
                vals,
                [(r.name, r.record) for r in runfiles],
                condition,
            )
        raise
    finally:
        outcome.summary = {
            "schema_version": 1,
            "kind": "sweep",
            "campaign": base_name or path.stem,
            "name": name,
            "param": param,
            "mode": mode,
            "values": vals if mode == "list" else None,
            "search": (
                {"lo": lo, "hi": hi, "tolerance": tolerance, "max_steps": max_steps}
                if mode == "search"
                else None
            ),
            "until": str(condition) if condition is not None else None,
            "started_at": runner._iso(started),
            "ended_at": runner._iso(clock()),
            "interrupted": interrupted,
            "steps": steps,
            "result": result,
        }
        directory.mkdir(parents=True, exist_ok=True)
        json_file = runner._unique(directory / "SWEEP.json", batch, ".json")
        runner.write(json_file, json.dumps(outcome.summary, indent=2, ensure_ascii=False) + "\n")
        # The markdown form shares the JSON's stem — ``mbench validate``
        # re-renders a ``SWEEP*.md`` from the same-named ``SWEEP*.json``.
        md_file = json_file.with_suffix(".md")
        if md_file.exists():
            md_file = runner._unique(directory / "SWEEP.md", batch, ".md")
        runner.write(md_file, render_summary_md(outcome.summary))
        outcome.summary_json = json_file
        outcome.summary_md = md_file
    return outcome


def _fmt(value: Json) -> str:
    """A summary-table cell: numbers compact, missing values a dash."""
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _fmt_pass(flag: Json) -> str:
    """The condition verdict of a step: ``pass``, ``FAIL`` or ``—`` (no condition)."""
    if flag is True:
        return "pass"
    if flag is False:
        return "FAIL"
    return "—"


def render_summary_md(summary: Mapping[str, Any]) -> str:
    """The ``SWEEP.md`` form of a ``SWEEP.json`` summary, deterministic.

    ``mbench validate`` re-renders it from the JSON and compares, the same
    faithful-render check a ``REPORT.md`` gets.
    """
    param = summary["param"]
    mode = summary["mode"]
    lines = [
        f"# Sweep `{summary['name']}` — {summary['campaign']} by `{param}`",
        "",
    ]
    if mode == "search":
        bounds = summary["search"] or {}
        lines.append(
            f"Binary search over `{param}` in [{_fmt(bounds.get('lo'))},"
            f" {_fmt(bounds.get('hi'))}] until `{summary['until']}`"
            f" (tolerance {_fmt(bounds.get('tolerance'))},"
            f" at most {_fmt(bounds.get('max_steps'))} steps)."
        )
    else:
        listed = ", ".join(_fmt(v) for v in summary.get("values") or [])
        lines.append(f"List sweep over `{param}`: {listed}.")
    if mode == "list" and summary.get("until"):
        lines.append(f"Condition `{summary['until']}` marked pass/fail per step.")
    if summary.get("interrupted"):
        lines.append("**The sweep was interrupted** — the steps below are complete results.")
    lines += [
        "",
        "| step | value | runs | status | gbps | mpps | loss | detection | pass |",
        "| ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for step in summary["steps"]:
        metrics = step["metrics"]
        lines.append(
            f"| {step['n']} | {_fmt(step['value'])} | {len(step['runs'])} "
            f"| {step['status']} | {_fmt(metrics.get('gbps'))} "
            f"| {_fmt(metrics.get('mpps'))} | {_fmt(metrics.get('loss'))} "
            f"| {_fmt(metrics.get('detection_rate'))} | {_fmt_pass(step['pass'])} |"
        )
    result = summary.get("result")
    if result is not None:
        probes = result.get("steps", 0)
        lines += [
            "",
            f"**Result:** best {param} {_fmt(result.get('best'))}"
            f" ({result.get('stop')}, {probes} probe{'s' * (probes != 1)};"
            f" final bracket [{_fmt((result.get('bracket') or {}).get('lo'))},"
            f" {_fmt((result.get('bracket') or {}).get('hi'))}])"
            + ("" if result.get("satisfied") else " — no probed value satisfied the condition"),
        ]
    lines += [
        "",
        f"_{len(summary['steps'])} step(s); every step is a full run batch under"
        " `runs/` with its own `sut*.json` — results are append-only._",
        "",
    ]
    return "\n".join(lines)
