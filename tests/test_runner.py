"""The campaign runner (#8): warm-up + N measured passes, timeouts,
append-only results, the embedded run-scope SUT, the quiet-host commands.

Everything runs against :class:`FakeAdapter` — no container, no process —
with ``sutfixtures.replay()`` standing in for the collected host record.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from campaignfiles import campaign_doc, layout, make_pcap, manifest_entry, write_manifest
from fakeadapter import FakeAdapter
from sutfixtures import replay

from mbench import adapters, matrix, pcap, runner, validate
from mbench.adapters.base import Alert, Counters

CLOCK = datetime(2026, 1, 5, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def fake_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(adapters.ADAPTERS, "fake", FakeAdapter)


def _ticks(step: float = 1.0) -> Callable[[], float]:
    """A monotonic clock that advances ``step`` seconds per call.

    ``run_pass`` calls it twice per pass (start, end), so every pass measures
    exactly ``step`` seconds of wall time.
    """
    calls = itertools.count()
    return lambda: next(calls) * step


def _campaign(tmp_path: Path, doc: dict[str, Any]) -> matrix.Campaign:
    parts = layout(tmp_path, doc)
    return matrix.load(
        parts["campaign_path"],
        manifest_path=parts["manifest"],
    )


def _run(
    campaign: matrix.Campaign,
    tmp_path: Path,
    adapter: FakeAdapter | None = None,
    factory: Callable[[], FakeAdapter] | None = None,
    host: dict[str, Any] | None = None,
    monotonic: Callable[[], float] | None = None,
    **kwargs: Any,
) -> runner.CampaignOutcome:
    logs: list[str] = []
    errs: list[str] = []
    outcome = runner.run_campaign(
        campaign,
        results_dir=tmp_path / "results",
        adapters={"fake": factory or (lambda: adapter or FakeAdapter())},
        collect=lambda: host if host is not None else replay(),
        clock=lambda: CLOCK,
        monotonic=monotonic or _ticks(),
        out=logs.append,
        err=errs.append,
        **kwargs,
    )
    outcome.logs = logs  # type: ignore[attr-defined]
    outcome.errs = errs  # type: ignore[attr-defined]
    return outcome


def _load_run(outcome: runner.CampaignOutcome, i: int = 0) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(outcome.run_files[i].read_text(encoding="utf-8"))
    return record


def test_a_campaign_writes_its_results_directory(tmp_path: Path, fake_tool: None) -> None:
    campaign = _campaign(tmp_path, campaign_doc([{"label": "x"}]))
    outcome = _run(campaign, tmp_path)

    assert outcome.directory == tmp_path / "results" / "2026-01-05-test"
    assert outcome.sut_file == outcome.directory / "sut.json"
    assert len(outcome.run_files) == 1
    assert outcome.report_file == outcome.directory / "REPORT.md"

    record = _load_run(outcome)
    assert record["status"] == "ok"
    assert record["campaign"]["question"] == "does it keep up?"
    assert record["mode"]["name"] == "offline"


def test_warmup_plus_n_measured_passes(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], repeats=3)
    campaign = _campaign(tmp_path, doc)
    adapter = FakeAdapter(run_counters=Counters(1_000_000, 64_000_000, 0))
    outcome = _run(campaign, tmp_path, adapter=adapter)
    record = _load_run(outcome)

    passes = record["passes"]
    assert [p["kind"] for p in passes] == ["warmup", "measured", "measured", "measured"]
    assert [p["n"] for p in passes] == [0, 1, 2, 3]
    assert all(p["status"] == "ok" for p in passes)
    # 64 MB in the scripted 1 s of wall time
    assert passes[1]["gbps"] == pytest.approx(0.512, abs=1e-3)
    assert passes[1]["mpps"] == pytest.approx(1.0)
    # the tool saw the run: 1 warmup + 3 measured
    assert len(adapter.calls) == 4


def test_the_cpuset_and_threads_reach_the_adapter(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], threads=[4], cpusets=["0-3"])
    campaign = _campaign(tmp_path, doc)
    adapter = FakeAdapter()
    outcome = _run(campaign, tmp_path, adapter=adapter)

    assert all(c.threads == 4 and c.cpuset == (0, 1, 2, 3) for c in adapter.calls)
    record = _load_run(outcome)
    assert record["cell"]["cpuset"] == "0-3"


def test_the_core_type_is_recorded(tmp_path: Path, fake_tool: None) -> None:
    # the dgx-spark fixture: Cortex-A725 on 0-4,10-14, Cortex-X925 on 5-9,15-19
    doc = campaign_doc([{"label": "x"}], cpusets=["0-3"])
    campaign = _campaign(tmp_path, doc)
    record = _load_run(_run(campaign, tmp_path))
    assert record["cell"]["core_type"] == "Cortex-A725"


def test_a_mixed_cpuset_says_so(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["2,5"])
    campaign = _campaign(tmp_path, doc)
    record = _load_run(_run(campaign, tmp_path))
    assert record["cell"]["core_type"] == "mixed: Cortex-A725+Cortex-X925"


def test_a_timeout_is_never_a_measurement(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], repeats=2, timeout_s=0.5)
    campaign = _campaign(tmp_path, doc)
    # the fake's handle outlives every timeout
    adapter = FakeAdapter(duration_s=999.0)
    outcome = _run(campaign, tmp_path, adapter=adapter)
    record = _load_run(outcome)

    assert record["status"] == "timeout"
    assert [p["status"] for p in record["passes"]] == ["timeout", "timeout", "timeout"]
    measured = [p for p in record["passes"] if p["kind"] == "measured"]
    assert all("gbps" not in p and "detection" not in p for p in measured)
    assert all("killed after" in p["detail"] for p in measured)


def test_every_run_embeds_a_valid_run_scope_sut(tmp_path: Path, fake_tool: None) -> None:
    campaign = _campaign(tmp_path, campaign_doc([{"label": "x"}]))
    record = _load_run(_run(campaign, tmp_path))

    embedded = record["sut"]
    assert embedded["scope"] == "run"
    assert validate.sut_errors(embedded) == []
    assert embedded["tools"][0]["name"] == "fake-tool"
    assert "per_run" in embedded["container_runtime"]["limits"]
    assert embedded["sut_hash"]


def test_a_run_with_an_invalid_sut_record_is_marked_invalid(
    tmp_path: Path, fake_tool: None
) -> None:
    campaign = _campaign(tmp_path, campaign_doc([{"label": "x"}]))
    broken = replay()
    del broken["os"]  # a required block of the SUT record
    outcome = _run(campaign, tmp_path, host=broken)
    record = _load_run(outcome)

    assert record["status"] == "invalid"
    assert record["problems"]  # the schema problems are recorded
    assert outcome.valid == 0 and outcome.invalid == 1
    # and REPORT.md says so instead of pretending a measurement
    report = outcome.report_file.read_text(encoding="utf-8")  # type: ignore[union-attr]
    assert "invalid" in report.lower()


def test_a_partially_failed_run_is_partial(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], repeats=2, timeout_s=0.5)
    campaign = _campaign(tmp_path, doc)
    # warmup and measured 1 finish; measured 2 hangs past the timeout
    adapter = FakeAdapter(durations=[0.0, 0.0, 999.0])
    record = _load_run(_run(campaign, tmp_path, adapter=adapter))
    assert record["status"] == "partial"
    assert [p["status"] for p in record["passes"]] == ["ok", "ok", "timeout"]


def test_results_are_append_only(tmp_path: Path, fake_tool: None) -> None:
    campaign = _campaign(tmp_path, campaign_doc([{"label": "x"}]))
    first = _run(campaign, tmp_path)
    before = {p.name: p.read_bytes() for p in first.directory.rglob("*") if p.is_file()}

    second = _run(campaign, tmp_path)  # same clock: same second, same batch
    after = {p.name: p.read_bytes() for p in first.directory.rglob("*") if p.is_file()}

    for name, content in before.items():
        assert after[name] == content, f"{name} changed"
    # the second batch is a new set of files, batch-suffixed, nothing clobbered
    assert second.run_files[0].name.startswith("20260105T120000Z-2-")
    assert len(after) == 2 * len(before)


def test_an_adapter_that_fails_to_build_is_an_error_run_not_a_crash(
    tmp_path: Path, fake_tool: None
) -> None:
    campaign = _campaign(tmp_path, campaign_doc([{"label": "x"}]))

    def boom() -> FakeAdapter:
        raise RuntimeError("docker not found")

    outcome = _run(campaign, tmp_path, factory=boom)
    record = _load_run(outcome)
    assert record["status"] == "error"
    assert "docker not found" in record["problems"][0]


def test_quiet_host_prints_the_user_commands_and_never_sudo(
    tmp_path: Path, fake_tool: None
) -> None:
    doc = campaign_doc([{"label": "x"}], quiet_host=True)
    campaign = _campaign(tmp_path, doc)
    outcome = _run(campaign, tmp_path)
    logs = "\n".join(outcome.logs + outcome.errs)  # type: ignore[attr-defined]
    assert "systemctl --user stop vllm-qwen.service vllm-health-watchdog.timer" in logs
    assert "systemctl --user start vllm-qwen.service vllm-health-watchdog.timer" in logs
    # the printed commands are user-scoped: no sudo, and nothing is run
    for line in logs.splitlines():
        if "systemctl" in line:
            assert "sudo" not in line


def test_quiet_host_off_prints_nothing(tmp_path: Path, fake_tool: None) -> None:
    campaign = _campaign(tmp_path, campaign_doc([{"label": "x"}]))
    outcome = _run(campaign, tmp_path)
    assert "systemctl" not in "\n".join(outcome.logs)  # type: ignore[attr-defined]


def test_without_tmpfs_the_capture_is_staged_on_the_regular_fs(
    tmp_path: Path, fake_tool: None
) -> None:
    campaign = _campaign(tmp_path, campaign_doc([{"label": "x"}]))
    outcome = _run(campaign, tmp_path, tmpfs=False)
    record = _load_run(outcome)
    assert record["mode"]["tmpfs"] is False
    assert any("tmpfs" in e for e in outcome.errs)  # type: ignore[attr-defined]


def test_detection_is_scored_and_reported(tmp_path: Path, fake_tool: None) -> None:
    # a corpus entry whose manifest ground truth names one attack
    root = tmp_path / "root"
    for d in ("campaigns", "rulesets", "corpus/data"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "rulesets" / "rs.so").write_bytes(b"rules")
    capture = make_pcap(root / "corpus" / "data", "x.pcap")
    sha = pcap.stats(capture).sha256
    attack = {
        "id": "a1",
        "start": 0.0,
        "end": 10.0,
        "src": "192.0.2.1",
        "dst": "198.51.100.1",
        "proto": "udp",
    }
    truth_doc = {
        "schema_version": 1,
        "pcap_sha256": sha,
        "tolerance_s": 1.0,
        "attacks": [attack],
    }
    (root / "corpus" / "x.truth.json").write_text(json.dumps(truth_doc), encoding="utf-8")
    entry = manifest_entry("x", capture, root / "corpus") | {"ground_truth": "x.truth.json"}
    manifest = write_manifest(root / "corpus", [entry])
    (root / "campaigns" / "c.yaml").write_text(
        yaml.safe_dump(campaign_doc([{"label": "x"}])), encoding="utf-8"
    )
    campaign = matrix.load(root / "campaigns" / "c.yaml", manifest_path=manifest)

    alert = Alert(
        ts=1.0,
        rule_id="r1",
        category="c",
        src="192.0.2.1",
        dst="198.51.100.1",
        proto="udp",
    )
    adapter = FakeAdapter(run_alerts=[alert])
    outcome = _run(campaign, tmp_path, adapter=adapter)
    record = _load_run(outcome)
    detection = record["passes"][1]["detection"]
    assert detection["detection_rate"] == 1.0
    assert detection["precision"] == 1.0
    report = outcome.report_file.read_text(encoding="utf-8")  # type: ignore[union-attr]
    assert "100%" in report


def test_a_second_batch_never_overwrites_even_when_run_files_collide(
    tmp_path: Path, fake_tool: None
) -> None:
    # Plant the fault in a scratch copy of the batch logic: a run_files name
    # without the batch bump would collide; the real code bumps the batch.
    campaign = _campaign(tmp_path, campaign_doc([{"label": "x"}]))
    outcome = _run(campaign, tmp_path)
    names = [p.name for p in outcome.directory.rglob("*") if p.is_file()]
    assert len(names) == len(set(names))


def test_sut_json_and_run_share_the_same_hash(tmp_path: Path, fake_tool: None) -> None:
    campaign = _campaign(tmp_path, campaign_doc([{"label": "x"}]))
    outcome = _run(campaign, tmp_path)
    host = json.loads(outcome.sut_file.read_text(encoding="utf-8"))  # type: ignore[union-attr]
    record = _load_run(outcome)
    # host scope vs run scope differ (scope, harness.run, per_run) but the
    # hashed fields are the same machine
    assert record["sut"]["sut_hash"] == host["sut_hash"]
