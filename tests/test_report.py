"""REPORT.md (#8): question, verdict, setup table, median/IQR/CV per cell,
detection next to throughput, invalid and failed runs listed, sut_hash
mismatches flagged.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sutfixtures import replay

from mbench import runner
from mbench.cli import EXIT_OK, EXIT_USAGE, main
from mbench.report import render

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64


def _pass(gbps: float, *, kind: str = "measured", n: int = 1, status: str = "ok") -> dict[str, Any]:
    p: dict[str, Any] = {
        "kind": kind,
        "n": n,
        "status": status,
        "wall_s": 1.0,
        "returncode": 0 if status == "ok" else None,
    }
    if status == "ok":
        p.update(
            {
                "packets": 1_000_000,
                "bytes": int(gbps * 1e9 / 8),
                "drops": 0,
                "gbps": gbps,
                "mpps": 1.0,
                "alerts": 1,
                "detection": {
                    "detection_rate": 1.0,
                    "precision": 1.0,
                    "tp": 1,
                    "fp": 0,
                    "fn": 0,
                },
            }
        )
    else:
        p["detail"] = status
    return p


def _run(
    name: str,
    gbps_values: list[float],
    *,
    status: str = "ok",
    sut_hash: str = HASH_A,
    warmup_gbps: float | None = 99.0,
    cell_overrides: dict[str, Any] | None = None,
    extra_passes: list[dict[str, Any]] | None = None,
    problems: list[str] | None = None,
) -> render.RunFile:
    passes = []
    if warmup_gbps is not None:
        passes.append(_pass(warmup_gbps, kind="warmup", n=0))
    passes += [_pass(g, n=i) for i, g in enumerate(gbps_values, 1)]
    passes += extra_passes or []
    host = replay()
    host["sut_hash"] = sut_hash
    cell: dict[str, Any] = {
        "index": 0,
        "tool": "mmt-probe",
        "ruleset": {"id": "rs", "sha256": "sha256:" + "0" * 64},
        "config_profile": "recommended",
        "corpus": {"label": "c-small", "sha256": "ab"},
        "threads": 1,
        "cpuset": "0-3",
        "core_type": "Cortex-A725",
    }
    cell.update(cell_overrides or {})
    record: dict[str, Any] = {
        "schema_version": 1,
        "batch": "b",
        "campaign": {"name": "test", "question": "does it keep up?"},
        "cell": cell,
        "status": status,
        "problems": problems or [],
        "passes": passes,
        "sut": host,
    }
    return render.RunFile(name, record)


def test_the_report_has_question_verdict_setup_and_stats() -> None:
    host = replay()
    host["sut_hash"] = HASH_A
    run = _run("r1.json", [1.0, 2.0, 3.0])
    md = render.render({"question": "does it keep up?"}, host, [run])

    assert "does it keep up?" in md
    assert "**Verdict:**" in md and "mmt-probe" in md
    assert "## Setup" in md and "Cortex-A725" in md
    assert "c-small" in md and "100%" in md


def test_median_iqr_and_cv_math() -> None:
    run = _run("r.json", [1.0, 2.0, 3.0, 4.0, 5.0])
    stats = render.cell_stats(run)
    assert stats.gbps_median == 3.0
    assert stats.gbps_iqr == pytest.approx(2.0)
    # cv is sample stdev / mean over the measured ok passes
    assert stats.gbps_cv == pytest.approx(1.5811388 / 3.0, rel=1e-4)


def test_warmup_is_excluded_from_the_statistics() -> None:
    run = _run("r.json", [1.0, 1.0, 1.0], warmup_gbps=99.0)
    stats = render.cell_stats(run)
    assert stats.gbps_median == 1.0  # not 25.75


def test_a_cv_over_5_percent_is_flagged() -> None:
    quiet = _run("quiet.json", [1.00, 1.01, 0.99])
    loud = _run("loud.json", [0.5, 1.0, 1.5])
    md = render.render({}, replay(), [quiet, loud])
    loud_row = next(r for r in md.splitlines() if "`loud.json`" in r)
    quiet_row = next(r for r in md.splitlines() if "`quiet.json`" in r)
    assert "⚠ rerun" in loud_row
    assert "⚠" not in quiet_row


def test_detection_sits_next_to_throughput() -> None:
    run = _run("r.json", [2.0])
    md = render.render({}, replay(), [run])
    line = next(r for r in md.splitlines() if "c-small" in r and "|" in r)
    assert "2" in line and "100%" in line


def test_invalid_timeout_and_error_runs_are_listed() -> None:
    ok = _run("ok.json", [1.0])
    invalid = _run("bad.json", [1.0], status="invalid", problems=["sut: missing field: os"])
    timeout = _run(
        "slow.json",
        [],
        status="timeout",
        warmup_gbps=None,
        extra_passes=[_pass(0, status="timeout", n=1)],
    )
    md = render.render({}, replay(), [ok, invalid, timeout])
    assert "bad.json" in md and "invalid" in md
    assert "slow.json" in md and "timeout" in md
    # the invalid run never reaches the results table; the timeout row shows
    # that nothing measured (no median, no detection)
    rows = [r for r in md.splitlines() if r.startswith("| c-small")]
    assert len(rows) == 2
    assert "bad.json" not in "\n".join(rows)
    slow_row = next(r for r in rows if "`slow.json`" in r)
    assert "—" in slow_row and "0/1" in slow_row


def test_a_sut_hash_mismatch_is_flagged() -> None:
    a = _run("a.json", [1.0], sut_hash=HASH_A)
    b = _run("b.json", [1.0], sut_hash=HASH_B)
    md = render.render({}, replay(), [a, b])
    assert "sut_hash mismatch" in md


def test_matching_hashes_raise_no_flag() -> None:
    a = _run("a.json", [1.0])
    b = _run("b.json", [1.0])
    md = render.render({}, replay(), [a, b])
    assert "mismatch" not in md and "differing" not in md


def test_the_verdict_names_the_fastest_cell() -> None:
    slow = _run("slow.json", [1.0], cell_overrides={"config_profile": "tuned"})
    fast = _run("fast.json", [4.0])
    md = render.render({}, replay(), [slow, fast])
    verdict = md.split("**Verdict:**")[1].split("\n")[0]
    assert "recommended" in verdict and "4" in verdict


def test_a_run_file_with_no_valid_runs_says_so() -> None:
    invalid = _run("bad.json", [], status="invalid", warmup_gbps=None)
    md = render.render({}, replay(), [invalid])
    assert "No valid measurement" in md


def test_render_dir_loads_runs_and_host(tmp_path: Path) -> None:
    directory = tmp_path / "res"
    (directory / "runs").mkdir(parents=True)
    host = replay()
    (directory / "sut.json").write_text(json.dumps(host), encoding="utf-8")
    run = _run("r.json", [1.0])
    (directory / "runs" / "r.json").write_text(json.dumps(run.record), encoding="utf-8")
    md = render.render_dir(directory)
    assert "does it keep up?" in md


def test_load_dir_picks_the_newest_sut_record(tmp_path: Path) -> None:
    # Three batches in one directory: the setup table must show the last
    # batch's host, not the first one's (review L1).
    directory = tmp_path / "res"
    (directory / "runs").mkdir(parents=True)
    for name, tag in (
        ("sut.json", "a" * 64),
        ("sut-20260105T120000Z.json", "b" * 64),
        ("sut-20260105T120000Z-2.json", "c" * 64),
    ):
        record = replay()
        record["sut_hash"] = f"sha256:{tag}"
        (directory / name).write_text(json.dumps(record), encoding="utf-8")
    host, _ = render.load_dir(directory)
    assert host is not None and host["sut_hash"] == "sha256:" + "c" * 64


def test_differing_fields_cover_every_distinct_hash() -> None:
    # Three runs, three hashes; A and B differ on memory, A and C only on
    # the kernel release — a field the A-vs-B diff alone misses (review L2).
    a = _run("a.json", [1.0], sut_hash=HASH_A)
    b = _run("b.json", [1.0], sut_hash=HASH_B)
    c = _run("c.json", [1.0], sut_hash=HASH_C)
    b.record["sut"]["host"]["memory"]["total_kib"] = 1
    c.record["sut"]["os"]["kernel"]["release"] = "other-kernel"
    notes = "\n".join(render._hash_notes([a, b, c]))
    assert "differing fields:" in notes
    assert "host.memory.total_kib" in notes
    assert "os.kernel.release" in notes


# --- mbench report ------------------------------------------------------------


def _results_dir(tmp_path: Path, tools: tuple[str, ...]) -> Path:
    """A results directory with one run file per tool."""
    directory = tmp_path / "res"
    (directory / "runs").mkdir(parents=True)
    for i, tool in enumerate(tools):
        run = _run(f"r{i}.json", [1.0], cell_overrides={"tool": tool})
        (directory / "runs" / f"r{i}.json").write_text(json.dumps(run.record), encoding="utf-8")
    return directory


def test_report_dash_o_outside_local_is_refused_for_a_comparison(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A tool-comparison report stays out of git: -o cannot sneak it into the
    # committed tree (review M1).
    directory = _results_dir(tmp_path, ("mmt-probe", "suricata"))
    out = tmp_path / "COMPARISON.md"
    assert main(["report", str(directory), "-o", str(out)]) == EXIT_USAGE
    assert not out.exists()
    assert "local/" in capsys.readouterr().err


def test_report_dash_o_under_local_writes_a_comparison(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = _results_dir(tmp_path, ("mmt-probe", "suricata"))
    out = tmp_path / "local" / "reports" / "COMPARISON.md"
    out.parent.mkdir(parents=True)
    assert main(["report", str(directory), "-o", str(out)]) == EXIT_OK
    assert "Verdict" in out.read_text(encoding="utf-8")


def test_report_dash_o_dash_prints_a_comparison(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = _results_dir(tmp_path, ("mmt-probe", "suricata"))
    assert main(["report", str(directory), "-o", "-"]) == EXIT_OK
    assert "Verdict" in capsys.readouterr().out


def test_report_without_dash_o_still_prints_a_comparison_outside_local(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = _results_dir(tmp_path, ("mmt-probe", "suricata"))
    assert main(["report", str(directory)]) == EXIT_OK
    captured = capsys.readouterr()
    assert "Verdict" in captured.out
    assert "local/" in captured.err
    assert not (directory / "REPORT.md").exists()


def test_report_dir_writes_report_batch_md_instead_of_overwriting(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A re-render never overwrites: REPORT.md taken -> REPORT-<batch>.md,
    # the runner's own fallback (review L6).
    directory = _results_dir(tmp_path, ("mmt-probe",))
    (directory / "REPORT.md").write_text("the first report\n", encoding="utf-8")
    assert main(["report", str(directory)]) == EXIT_OK
    assert (directory / "REPORT.md").read_text(encoding="utf-8") == "the first report\n"
    reports = [p.name for p in directory.glob("REPORT-*.md")]
    assert len(reports) == 1
    assert "Verdict" in (directory / reports[0]).read_text(encoding="utf-8")


def test_report_dir_twice_in_the_same_second_counts_up(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two re-renders inside the same second: REPORT-<batch>.md is taken, so
    # the fallback counts up like the run files — -2, -3 — instead of
    # failing "exists" (review N2).
    directory = _results_dir(tmp_path, ("mmt-probe",))
    (directory / "REPORT.md").write_text("the first report\n", encoding="utf-8")
    monkeypatch.setattr(runner, "utcnow", lambda: datetime(2026, 1, 5, 12, 0, 0, tzinfo=UTC))
    for _ in range(3):
        assert main(["report", str(directory)]) == EXIT_OK
    assert (directory / "REPORT.md").read_text(encoding="utf-8") == "the first report\n"
    reports = sorted(p.name for p in directory.glob("REPORT-*.md"))
    assert reports == [
        "REPORT-20260105T120000Z-2.md",
        "REPORT-20260105T120000Z-3.md",
        "REPORT-20260105T120000Z.md",
    ]
