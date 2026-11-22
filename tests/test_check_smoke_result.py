"""``tools/ci/check_smoke_result.py``: the smoke CI job's all-ok status gate (#9).

Results are append-only, so the gate is the *newest* batch's run records: an
earlier batch's failed run stays in the directory and is not the gate. The
run record's schema and embedded SUT are ``mbench validate``'s job.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from check_smoke_result import main, status_errors


def _run(directory: Path, batch: str, status: str, *, index: int = 0, **record: Any) -> Path:
    runs = directory / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    passes = [
        {"kind": "warmup", "n": 0, "status": "ok", "wall_s": 0.5},
        {"kind": "measured", "n": 1, "status": "ok", "wall_s": 0.4},
    ]
    path = runs / f"{batch}-{index:02d}-cell.json"
    path.write_text(json.dumps({"status": status, "passes": passes, **record}), encoding="utf-8")
    return path


def test_no_directory_exits_2(tmp_path: Path) -> None:
    assert main([str(tmp_path / "missing")]) == 2
    (tmp_path / "empty").mkdir()
    assert main([str(tmp_path / "empty")]) == 2


def test_no_args_is_a_usage_error() -> None:
    assert main([]) == 2
    assert main(["a", "b"]) == 2


def test_an_ok_run_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(tmp_path, "20260101T000000Z", "ok")
    assert main([str(tmp_path)]) == 0
    assert "all 'ok'" in capsys.readouterr().out


@pytest.mark.parametrize("status", ["partial", "timeout", "error", "interrupted", "invalid"])
def test_a_non_ok_status_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], status: str
) -> None:
    _run(tmp_path, "20260101T000000Z", status)
    assert main([str(tmp_path)]) == 1
    assert f"status {status!r}, not 'ok'" in capsys.readouterr().err


def test_an_ok_run_with_a_failed_measured_pass_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(
        tmp_path,
        "20260101T000000Z",
        "ok",
        passes=[{"kind": "measured", "n": 1, "status": "timeout", "wall_s": 10.0}],
    )
    assert main([str(tmp_path)]) == 1
    assert "measured pass 1" in capsys.readouterr().err


def test_a_failed_warmup_alone_is_not_the_gate(tmp_path: Path) -> None:
    # A run's status is the record's word for it; the gate checks measured
    # passes only, the same field `mbench run`'s own verdict uses.
    _run(
        tmp_path,
        "20260101T000000Z",
        "ok",
        passes=[{"kind": "warmup", "n": 0, "status": "timeout", "wall_s": 10.0}],
    )
    assert main([str(tmp_path)]) == 0


def test_only_the_newest_batch_is_the_gate(tmp_path: Path) -> None:
    # Append-only: a previous failed campaign's run record stays in the
    # directory; the gate is the batch this run produced.
    _run(tmp_path, "20260101T000000Z", "timeout")
    _run(tmp_path, "20260101T000000Z-2", "ok")
    assert main([str(tmp_path)]) == 0


def test_an_older_batch_failure_with_no_new_run_still_fails(tmp_path: Path) -> None:
    _run(tmp_path, "20260101T000000Z", "timeout")
    assert main([str(tmp_path)]) == 1


def test_an_unreadable_record_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "20260101T000000Z-00-cell.json").write_text("{cut off", encoding="utf-8")
    assert main([str(tmp_path)]) == 1
    assert "unreadable run record" in capsys.readouterr().err


def test_a_file_outside_the_batch_naming_is_checked_anyway(tmp_path: Path) -> None:
    # A runs/ file that is not <batch>-NN-<slug>.json is not part of a batch:
    # it is checked regardless, so a stray record cannot dodge the gate.
    _run(tmp_path, "20260101T000000Z", "ok")
    stray = tmp_path / "runs" / "notes.json"
    stray.write_text(json.dumps({"status": "error"}), encoding="utf-8")
    assert main([str(tmp_path)]) == 1


def test_status_errors_reports_both_levels(tmp_path: Path) -> None:
    path = _run(
        tmp_path,
        "20260101T000000Z",
        "partial",
        passes=[{"kind": "measured", "n": 2, "status": "timeout"}],
    )
    errors = status_errors(path)
    assert any("status 'partial'" in e for e in errors)
    assert any("measured pass 2" in e for e in errors)
