"""The perf wiring of a campaign (#10): ``perf: true`` wraps every measured
pass in ``perf stat`` on the cell's cpuset, a refused perf is a recorded
marker plus Luong's printed runbook, and ``pin_harness`` keeps the harness
on the cores the tool does not use — recorded in the run.
"""

from __future__ import annotations

import itertools
import json
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from campaignfiles import campaign_doc, layout
from fakeadapter import FakeAdapter
from sutfixtures import replay

from mbench import adapters, matrix, runner, validate
from mbench.adapters.base import Counters
from mbench.metrics import perf

CLOCK = datetime(2026, 1, 5, 12, 0, 0, tzinfo=UTC)
# The dgx-spark fixture's real topology: the resolved cpusets must map back
# to the same core type in the recorded SUT.
TOPOLOGY: dict[str, tuple[int, ...]] = {
    "Cortex-A725": (0, 1, 2, 3, 4, 10, 11, 12, 13, 14),
    "Cortex-X925": (5, 6, 7, 8, 9, 15, 16, 17, 18, 19),
}
STAT_CSV = "1000000,,cycles,100.00,,,,\n2000000,,instructions,100.00,,,,\n"


@pytest.fixture
def fake_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(adapters.ADAPTERS, "fake", FakeAdapter)


class FakePopen:
    """The perf stat session: SIGINT ends it; it "wrote" STAT_CSV at start."""

    def __init__(self, argv: Sequence[str]) -> None:
        self.argv = list(argv)
        out = Path(argv[argv.index("-o") + 1])
        out.write_text(STAT_CSV, encoding="utf-8")
        self.signals: list[int] = []

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        pass


def _completed(argv: Sequence[str], rc: int = 0) -> perf.Completed:
    return subprocess.CompletedProcess(list(argv), rc, b"", b"")


def _probe(tmp_path: Path, paranoid: int = 1) -> perf.Probe:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text(f"{paranoid}\n", encoding="utf-8")
    return perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        run=lambda argv: _completed(argv),
        spawn=FakePopen,  # type: ignore[arg-type]
    )


def _campaign(tmp_path: Path, doc: dict[str, Any]) -> matrix.Campaign:
    parts = layout(tmp_path, doc)
    return matrix.load(parts["campaign_path"], manifest_path=parts["manifest"], topology=TOPOLOGY)


def _run(
    campaign: matrix.Campaign, tmp_path: Path, **kwargs: Any
) -> tuple[runner.CampaignOutcome, list[str], list[str]]:
    logs: list[str] = []
    errs: list[str] = []
    outcome = runner.run_campaign(
        campaign,
        results_dir=tmp_path / "results",
        # the corpus fixture holds 200 packets — the fake reports exactly those
        adapters={"fake": lambda: FakeAdapter(run_counters=Counters(200, 640_000, 0))},
        collect=lambda: replay(),
        clock=lambda: CLOCK,
        monotonic=itertools.count(0).__next__,
        out=logs.append,
        err=errs.append,
        **kwargs,
    )
    return outcome, logs, errs


def _load_run(outcome: runner.CampaignOutcome, i: int = 0) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(outcome.run_files[i].read_text(encoding="utf-8"))
    return record


def test_measured_passes_carry_the_perf_record(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], repeats=2, cpusets=["core:x925"], perf=True)
    campaign = _campaign(tmp_path, doc)
    outcome, _, _ = _run(campaign, tmp_path, perf_probe=_probe(tmp_path))
    record = _load_run(outcome)

    assert record["campaign"]["perf"] is True
    assert "perf" not in record["passes"][0]  # the warm-up is not perf'd
    for measured in record["passes"][1:]:
        assert measured["perf"]["cycles"] == 1_000_000
        assert measured["perf"]["instructions"] == 2_000_000
        # the pass's 200 packets divided the cpuset's cycles
        assert measured["perf"]["cycles_per_packet"] == 1_000_000 / 200
    assert validate.sut_errors(record["sut"]) == []


def test_a_refused_perf_is_the_marker_and_the_runbook(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["core:x925"], perf=True)
    campaign = _campaign(tmp_path, doc)
    outcome, logs, _ = _run(campaign, tmp_path, perf_probe=_probe(tmp_path, paranoid=4))
    record = _load_run(outcome)

    measured = record["passes"][1]
    assert measured["perf"]["unavailable"] == "needs_root"
    assert "perf_event_paranoid=4" in measured["perf"]["reason"]
    note = "\n".join(logs)
    assert "cap_perfmon=ep" in note  # the narrowest fix, printed for Luong
    assert "kernel.perf_event_paranoid=1" in note
    # the run is still a valid measurement — the marker is evidence, not a failure
    assert record["status"] == "ok"


def test_a_campaign_without_perf_records_nothing(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["core:x925"])
    campaign = _campaign(tmp_path, doc)
    outcome, _, _ = _run(campaign, tmp_path, perf_probe=None)
    record = _load_run(outcome)
    assert all("perf" not in p for p in record["passes"])
    assert record["campaign"]["perf"] is False


def test_the_harness_pins_itself_off_the_tool_cores(
    tmp_path: Path, fake_tool: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    affinity = set(range(20))
    applied: list[set[int]] = []
    monkeypatch.setattr(runner, "_getaffinity", lambda pid: set(affinity))
    monkeypatch.setattr(runner, "_setaffinity", lambda pid, cpus: applied.append(set(cpus)))
    doc = campaign_doc([{"label": "x"}], cpusets=["core:x925"])
    campaign = _campaign(tmp_path, doc)
    outcome, _, _ = _run(campaign, tmp_path, pin_harness=True)
    record = _load_run(outcome)

    # tool on 5-9,15-19; the harness on the rest, restored when it ended
    a725 = {0, 1, 2, 3, 4, 10, 11, 12, 13, 14}
    assert applied == [a725, affinity]
    assert record["cell"]["harness_cpuset"] == "0-4,10-14"


def test_the_harness_stays_unpinned_when_the_tool_takes_everything(
    tmp_path: Path, fake_tool: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "_getaffinity", lambda pid: {0, 1})
    monkeypatch.setattr(runner, "_setaffinity", lambda pid, cpus: None)
    doc = campaign_doc([{"label": "x"}], cpusets=["0,1"])
    parts = layout(tmp_path, doc)
    campaign = matrix.load(parts["campaign_path"], manifest_path=parts["manifest"])
    outcome, _, errs = _run(campaign, tmp_path, pin_harness=True)
    record = _load_run(outcome)
    assert record["cell"]["harness_cpuset"] == ""
    assert any("stays unpinned" in e for e in errs)


def test_the_report_shows_cycles_and_the_ci(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], repeats=6, cpusets=["core:x925"], perf=True)
    campaign = _campaign(tmp_path, doc)
    outcome, _, _ = _run(campaign, tmp_path, perf_probe=_probe(tmp_path))
    assert outcome.report_file is not None
    text = outcome.report_file.read_text(encoding="utf-8")

    assert "cycles/pkt" in text
    assert "5000" in text  # the median cycles per packet
    assert " CI " in text  # the verdict's order-statistic interval at n ≥ 5


def test_a_marker_lands_in_the_report(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["core:x925"], perf=True)
    campaign = _campaign(tmp_path, doc)
    outcome, _, _ = _run(campaign, tmp_path, perf_probe=_probe(tmp_path, paranoid=4))
    assert outcome.report_file is not None
    text = outcome.report_file.read_text(encoding="utf-8")
    assert "cycles/pkt unavailable" in text
    assert "perf_event_paranoid" in text


def test_two_core_series_get_two_tables(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["core:x925", "core:a725"], perf=True)
    campaign = _campaign(tmp_path, doc)
    outcome, _, _ = _run(campaign, tmp_path, perf_probe=_probe(tmp_path))
    assert outcome.report_file is not None
    text = outcome.report_file.read_text(encoding="utf-8")
    assert "## Results — Cortex-X925" in text
    assert "## Results — Cortex-A725" in text


def test_the_campaign_file_validates(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["core:x925"], perf=True)
    parts = layout(tmp_path, doc)
    errors = validate.campaign_errors(doc, manifest_path=parts["manifest"])
    assert errors == []
    report = validate.validate_file(parts["campaign_path"])
    # validate_file checks the label against the repo manifest: 'x' is not
    # there, but the core: cpuset and perf fields themselves are accepted.
    want = "corpus[0].label: no manifest entry for 'x' in corpus/manifest.yaml"
    assert report.errors == [want]


def test_the_committed_p1_campaign_is_valid() -> None:
    report = validate.validate_file(Path(__file__).parent.parent / "campaigns" / "p1-headline.yaml")
    # c-benign is a label with no manifest entry yet (the capture is a
    # root-only step): that single problem is the expected pending state.
    want = "corpus[0].label: no manifest entry for 'c-benign' in corpus/manifest.yaml"
    assert report.errors == [want]
    data = yaml.safe_load(
        (Path(__file__).parent.parent / "campaigns" / "p1-headline.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert data["question"].startswith(
        "How many Gbit/s can mmt-probe with all 95 rules process on one X925 core"
    )
    assert data["perf"] is True and data["quiet_host"] is True
    # the headline t1 cell runs on exactly one CPU of each core type; tN
    # leaves the reader and output threads room (@N+2)
    by_cpuset = {i["cpuset"]: i["threads"] for i in data["cpusets"]}
    assert by_cpuset == {
        "core:x925@1": [0, 1],
        "core:x925@4": [2],
        "core:x925@6": [4],
        "core:x925@10": [8],
        "core:a725@1": [0, 1],
        "core:a725@4": [2],
        "core:a725@6": [4],
        "core:a725@10": [8],
    }
    # r0/r0b are the t0 main-thread baselines; r-all owns the scaling sweep
    rs = {i["id"]: i.get("threads") for i in data["rulesets"]}
    assert rs == {"r0": [0], "r0b": [0], "r-all": [1, 2, 4, 8]}
    # the verdict names the headline cell (M2)
    assert data["verdict_cell"] == {
        "ruleset": "r-all",
        "corpus": "c-benign",
        "threads": 1,
        "cpuset": "core:x925@1",
    }
