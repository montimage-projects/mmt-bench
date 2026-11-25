"""``mbench sweep`` (#17): the list sweep, the binary search, the summary.

Everything runs against :class:`FakeAdapter` — no container, no process —
with ``sutfixtures.replay()`` standing in for the collected host record,
like the runner tests.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from campaignfiles import campaign_doc, layout
from fakeadapter import FakeAdapter
from sutfixtures import replay

from mbench import adapters, matrix, runner, sweep, validate
from mbench.adapters.base import Counters

CLOCK = datetime(2026, 1, 5, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def fake_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(adapters.ADAPTERS, "fake", FakeAdapter)


def _ticks(step: float = 1.0) -> Callable[[], float]:
    """A monotonic clock that advances ``step`` seconds per call."""
    calls = itertools.count()
    return lambda: next(calls) * step


def _run(
    campaign_path: Path,
    manifest: Path,
    tmp_path: Path,
    *,
    adapters: dict[str, Callable[[], FakeAdapter]] | None = None,
    **kwargs: Any,
) -> tuple[sweep.SweepOutcome, list[str], list[str]]:
    logs: list[str] = []
    errs: list[str] = []
    outcome = sweep.run_sweep(
        campaign_path,
        results_dir=tmp_path / "results",
        manifest_path=manifest,
        adapters=adapters or {"fake": lambda: FakeAdapter()},
        collect=lambda: replay(),
        clock=lambda: CLOCK,
        monotonic=_ticks(),
        out=logs.append,
        err=errs.append,
        **kwargs,
    )
    return outcome, logs, errs


def _record(directory: Path, name: str) -> dict[str, Any]:
    record: dict[str, Any] = json.loads((directory / "runs" / name).read_text(encoding="utf-8"))
    return record


def test_a_list_sweep_writes_one_result_per_step(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}], repeats=1))
    outcome, _, _ = _run(
        parts["campaign_path"], parts["manifest"], tmp_path, param="threads", values="1,4"
    )

    directory = outcome.directory
    assert directory == tmp_path / "results" / "2026-01-05-test-sweep-threads"
    assert (directory / "sut.json").is_file()
    assert (directory / "REPORT.md").is_file()
    run_files = sorted((directory / "runs").glob("*.json"))
    assert len(run_files) == 2

    summary = outcome.summary
    assert summary["kind"] == "sweep"
    assert summary["param"] == "threads"
    assert summary["mode"] == "list"
    assert summary["values"] == [1, 4]
    assert summary["until"] is None
    assert summary["interrupted"] is False
    assert outcome.summary_json == directory / "SWEEP.json"
    assert outcome.summary_md == directory / "SWEEP.md"

    # Every step is a full result: a run file whose cell carries the value,
    # with a complete embedded SUT record.
    steps = summary["steps"]
    assert [s["value"] for s in steps] == [1, 4]
    for step in steps:
        assert len(step["runs"]) == 1
        record = _record(directory, step["runs"][0])
        assert record["cell"]["threads"] == step["value"]
        assert record["status"] == "ok"
        assert isinstance(record.get("sut"), dict) and record["sut"].get("sut_hash")
        assert step["status"] == "ok"
        measured = [p for p in record["passes"] if p["kind"] == "measured"]
        assert step["metrics"]["packets"] == sum(p["packets"] for p in measured)


def test_the_summary_files_validate(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}], repeats=1))
    outcome, _, _ = _run(
        parts["campaign_path"], parts["manifest"], tmp_path, param="threads", values="1,4"
    )
    assert outcome.summary_json is not None and outcome.summary_md is not None
    for path in (outcome.summary_json, outcome.summary_md):
        report = validate.validate_file(path)
        assert report.ok, report.errors


def test_a_rate_list_sweep_records_the_rate_on_each_cell(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}], repeats=1))
    outcome, _, _ = _run(
        parts["campaign_path"], parts["manifest"], tmp_path, param="rate", values="500,1000"
    )
    summary = outcome.summary
    assert [s["value"] for s in summary["steps"]] == [500.0, 1000.0]
    for step in summary["steps"]:
        record = _record(outcome.directory, step["runs"][0])
        assert record["cell"]["rate"] == step["value"]


def test_until_marks_each_step_of_a_list_sweep(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}], repeats=1))
    adapters = iter(
        [
            FakeAdapter(run_counters=Counters(200, 64_000, 0)),
            FakeAdapter(run_counters=Counters(200, 64_000, 7)),
        ]
    )
    outcome, _, _ = _run(
        parts["campaign_path"],
        parts["manifest"],
        tmp_path,
        param="threads",
        values="1,4",
        until="loss==0",
        adapters={"fake": lambda: next(adapters)},
    )
    assert [s["pass"] for s in outcome.summary["steps"]] == [True, False]
    losses = [s["metrics"]["loss"] for s in outcome.summary["steps"]]
    assert losses[0] == 0
    assert losses[1] == pytest.approx(7 / 200)


def test_binary_search_converges_to_the_lossless_rate(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}], repeats=1))
    # The bisection probes 1000, 500, 250, 375 in that order; the scripted
    # drops answer them: only 250 is lossless.
    probed: Iterator[FakeAdapter] = iter(
        [
            FakeAdapter(run_counters=Counters(200, 64_000, 10)),
            FakeAdapter(run_counters=Counters(200, 64_000, 10)),
            FakeAdapter(run_counters=Counters(200, 64_000, 0)),
            FakeAdapter(run_counters=Counters(200, 64_000, 10)),
        ]
    )
    outcome, _, _ = _run(
        parts["campaign_path"],
        parts["manifest"],
        tmp_path,
        param="rate",
        search="0:1000",
        until="loss==0",
        max_steps=4,
        adapters={"fake": lambda: next(probed)},
    )
    summary = outcome.summary
    result = summary["result"]
    assert result == {
        "best": 250.0,
        "satisfied": True,
        "stop": "max_steps",
        "steps": 4,
        "bracket": {"lo": 250.0, "hi": 375.0},
    }
    assert [s["value"] for s in summary["steps"]] == [1000.0, 500.0, 250.0, 375.0]
    assert [s["pass"] for s in summary["steps"]] == [False, False, True, False]

    # Every probe is a full run batch of its own: 4 run files and 4 SUT
    # records, each step's run recording cell.rate.
    assert len(outcome.run_files) == 4
    assert len(sorted(outcome.directory.glob("sut*.json"))) == 4
    for step in summary["steps"]:
        record = _record(outcome.directory, step["runs"][0])
        assert record["cell"]["rate"] == step["value"]
        assert record["status"] == "ok"


def test_the_search_stops_when_the_upper_bound_satisfies(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}], repeats=1))
    outcome, _, _ = _run(
        parts["campaign_path"],
        parts["manifest"],
        tmp_path,
        param="rate",
        search="0:1000",
        until="loss==0",
        adapters={"fake": lambda: FakeAdapter(run_counters=Counters(200, 64_000, 0))},
    )
    result = outcome.summary["result"]
    assert result["best"] == 1000.0
    assert result["stop"] == "hi_satisfied"
    assert result["steps"] == 1
    assert len(outcome.summary["steps"]) == 1


def test_an_unknown_param_is_rejected(tmp_path: Path) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}], repeats=1))
    with pytest.raises(sweep.SweepError, match="unknown sweep parameter"):
        sweep.run_sweep(
            parts["campaign_path"],
            param="governor",
            values="performance",
            results_dir=tmp_path / "results",
        )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"param": "rate"}, "is required"),
        (
            {"param": "rate", "values": "500", "search": "0:1000"},
            "not both",
        ),
        (
            {"param": "threads", "search": "0:10", "until": "loss==0"},
            "defined over --param rate",
        ),
        ({"param": "rate", "search": "0:1000"}, "needs --until"),
        ({"param": "rate", "search": "1000:0", "until": "loss==0"}, "lo < hi"),
        ({"param": "rate", "search": "fast:slow", "until": "loss==0"}, "numeric"),
        (
            {"param": "threads", "values": "two,four"},
            "not an integer",
        ),
        (
            {"param": "rate", "values": "500,,1000"},
            "comma-separated list",
        ),
        (
            {"param": "rate", "search": "0:1000", "until": "loss<<0"},
            "not a condition",
        ),
        (
            {"param": "rate", "search": "0:1000", "until": "score==0"},
            "unknown metric",
        ),
        (
            {"param": "rate", "search": "0:1000", "until": "loss==0", "tolerance": -1},
            ">= 0",
        ),
        (
            {"param": "rate", "search": "0:1000", "until": "loss==0", "max_steps": 0},
            ">= 1",
        ),
    ],
)
def test_bad_sweep_options_raise_a_clear_error(
    tmp_path: Path, kwargs: dict[str, Any], match: str
) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}], repeats=1))
    with pytest.raises(sweep.SweepError, match=match):
        sweep.run_sweep(parts["campaign_path"], results_dir=tmp_path / "results", **kwargs)
    # A rejected sweep writes no results.
    assert not (tmp_path / "results").exists()


def test_a_second_sweep_appends_and_never_overwrites(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}], repeats=1))
    first, _, _ = _run(
        parts["campaign_path"], parts["manifest"], tmp_path, param="threads", values="1"
    )
    first_json = first.summary_json
    assert first_json is not None
    first_text = first_json.read_text(encoding="utf-8")

    second, _, _ = _run(
        parts["campaign_path"], parts["manifest"], tmp_path, param="threads", values="1"
    )
    # Same clock: the second sweep lands in the same directory — every file
    # it writes gets the batch suffix, and the first summary is untouched.
    assert second.directory == first.directory
    assert second.summary_json is not None and second.summary_json != first_json
    assert second.summary_md is not None
    assert first_json.read_text(encoding="utf-8") == first_text
    assert sorted(p.name for p in second.directory.glob("SWEEP*")) == [
        "SWEEP-20260105T120000Z.json",
        "SWEEP-20260105T120000Z.md",
        "SWEEP.json",
        "SWEEP.md",
    ]
    for path in (second.summary_json, second.summary_md):
        report = validate.validate_file(path)
        assert report.ok, report.errors


def test_search_values_is_a_deterministic_bisection() -> None:
    # No runs needed: the probe order is a function of the satisfaction
    # answers alone.
    gen = sweep.search_values(0, 100, tolerance=10, max_steps=16)
    probed: list[float] = []
    try:
        value = next(gen)
        while True:
            probed.append(value)
            # The mock condition: values <= 60 satisfy.
            value = gen.send(value <= 60)
    except StopIteration as stop:
        result = stop.value
    assert probed == [100.0, 50.0, 75.0, 62.5, 56.25]
    assert result["best"] == 56.25
    assert result["stop"] == "tolerance"
    assert result["bracket"] == {"lo": 56.25, "hi": 62.5}


def test_a_sweep_over_ruleset_ids(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], rulesets=["rs-a", "rs-b"], repeats=1)
    parts = layout(tmp_path, doc)
    outcome, _, _ = _run(
        parts["campaign_path"],
        parts["manifest"],
        tmp_path,
        param="ruleset",
        values="rs-a,rs-b",
    )
    for step in outcome.summary["steps"]:
        record = _record(outcome.directory, step["runs"][0])
        assert record["cell"]["ruleset"]["id"] == step["value"]
        assert record["status"] == "ok"


def test_runner_accepts_a_pinned_directory(tmp_path: Path, fake_tool: None) -> None:
    # The directory override is what keeps one sweep's batches together
    # even when the clock's date would roll over mid-sweep.
    doc = campaign_doc([{"label": "x"}], repeats=1)
    parts = layout(tmp_path, doc)
    campaign = matrix.load(parts["campaign_path"], manifest_path=parts["manifest"])
    target = tmp_path / "results" / "pinned-name"
    outcome = runner.run_campaign(
        campaign,
        results_dir=tmp_path / "results",
        directory=target,
        adapters={"fake": lambda: FakeAdapter()},
        collect=lambda: replay(),
        clock=lambda: CLOCK,
        monotonic=_ticks(),
    )
    assert outcome.directory == target
