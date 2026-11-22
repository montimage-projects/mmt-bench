"""``tools/ci/check_smoke_result.py``: the smoke CI job's gate (#9).

Results are append-only, so the gate is the *newest* batch's run records: an
earlier batch's failed run stays in the directory and is not the gate. Every
measured pass must also report the expected alert count and detection rate
1.0: a broken alert path cannot pass as an ``alerts: 0`` record. The run
record's schema and embedded SUT are ``mbench validate``'s job.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from check_smoke_result import main, record_errors

EXPECTED = "4"
DETECTION = {"rules": {"13": {"expected": 4, "detected": 4, "missed": 0}}, "detection_rate": 1.0}


def _run(directory: Path, batch: str, status: str, *, index: int = 0, **record: Any) -> Path:
    runs = directory / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    passes = [
        {"kind": "warmup", "n": 0, "status": "ok", "wall_s": 0.5},
        {
            "kind": "measured",
            "n": 1,
            "status": "ok",
            "wall_s": 0.4,
            "alerts": 4,
            "detection": DETECTION,
        },
    ]
    path = runs / f"{batch}-{index:02d}-cell.json"
    path.write_text(json.dumps({"status": status, "passes": passes, **record}), encoding="utf-8")
    return path


def _measured(**pass_fields: Any) -> list[dict[str, Any]]:
    base = {"kind": "measured", "n": 1, "status": "ok", "wall_s": 0.4, "alerts": 4}
    base["detection"] = DETECTION
    base.update(pass_fields)
    return [base]


def test_no_directory_exits_2(tmp_path: Path) -> None:
    assert main([str(tmp_path / "missing"), EXPECTED]) == 2
    (tmp_path / "empty").mkdir()
    assert main([str(tmp_path / "empty"), EXPECTED]) == 2


def test_bad_args_is_a_usage_error() -> None:
    assert main([]) == 2
    assert main(["a"]) == 2
    assert main(["a", "b", "c"]) == 2
    assert main(["a", "not-an-int"]) == 2
    assert main(["a", "-1"]) == 2


def test_an_ok_run_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(tmp_path, "20260101T000000Z", "ok")
    assert main([str(tmp_path), EXPECTED]) == 0
    assert "all 'ok'" in capsys.readouterr().out


@pytest.mark.parametrize("status", ["partial", "timeout", "error", "interrupted", "invalid"])
def test_a_non_ok_status_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], status: str
) -> None:
    _run(tmp_path, "20260101T000000Z", status)
    assert main([str(tmp_path), EXPECTED]) == 1
    assert f"status {status!r}, not 'ok'" in capsys.readouterr().err


def test_an_ok_run_with_a_failed_measured_pass_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(status="timeout"))
    assert main([str(tmp_path), EXPECTED]) == 1
    assert "measured pass 1" in capsys.readouterr().err


def test_a_zero_alert_measured_pass_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A broken alert path records an all-ok run with alerts: 0 — the same
    # shape a correct benign run used to have. The expected count is the gate.
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(alerts=0))
    assert main([str(tmp_path), EXPECTED]) == 1
    assert "alerts 0, expected 4" in capsys.readouterr().err


def test_a_wrong_alert_count_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(alerts=3))
    assert main([str(tmp_path), EXPECTED]) == 1
    assert "alerts 3, expected 4" in capsys.readouterr().err


def test_a_detection_rate_below_one_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    detection = {
        "rules": {"13": {"expected": 4, "detected": 3, "missed": 1}},
        "detection_rate": 0.75,
    }
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(detection=detection))
    assert main([str(tmp_path), EXPECTED]) == 1
    assert "detection_rate 0.75, not 1.0" in capsys.readouterr().err


def test_a_missing_detection_field_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(
        tmp_path,
        "20260101T000000Z",
        "ok",
        passes=[{"kind": "measured", "n": 1, "status": "ok", "wall_s": 0.4, "alerts": 4}],
    )
    assert main([str(tmp_path), EXPECTED]) == 1
    assert "detection_rate None, not 1.0" in capsys.readouterr().err


def test_a_failed_warmup_alone_is_not_the_gate(tmp_path: Path) -> None:
    # A run's status is the record's word for it; the gate checks measured
    # passes only, the same field `mbench run`'s own verdict uses.
    _run(
        tmp_path,
        "20260101T000000Z",
        "ok",
        passes=[{"kind": "warmup", "n": 0, "status": "timeout", "wall_s": 10.0}, *_measured()],
    )
    assert main([str(tmp_path), EXPECTED]) == 0


def test_only_the_newest_batch_is_the_gate(tmp_path: Path) -> None:
    # Append-only: a previous failed campaign's run record stays in the
    # directory; the gate is the batch this run produced.
    _run(tmp_path, "20260101T000000Z", "timeout", passes=_measured(alerts=0))
    _run(tmp_path, "20260101T000000Z-2", "ok")
    assert main([str(tmp_path), EXPECTED]) == 0


def test_an_older_batch_failure_with_no_new_run_still_fails(tmp_path: Path) -> None:
    _run(tmp_path, "20260101T000000Z", "timeout")
    assert main([str(tmp_path), EXPECTED]) == 1


def test_an_unreadable_record_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "20260101T000000Z-00-cell.json").write_text("{cut off", encoding="utf-8")
    assert main([str(tmp_path), EXPECTED]) == 1
    assert "unreadable run record" in capsys.readouterr().err


def test_a_file_outside_the_batch_naming_is_checked_anyway(tmp_path: Path) -> None:
    # A runs/ file that is not <batch>-NN-<slug>.json is not part of a batch:
    # it is checked regardless, so a stray record cannot dodge the gate.
    _run(tmp_path, "20260101T000000Z", "ok")
    stray = tmp_path / "runs" / "notes.json"
    stray.write_text(json.dumps({"status": "error"}), encoding="utf-8")
    assert main([str(tmp_path), EXPECTED]) == 1


def test_record_errors_reports_both_levels(tmp_path: Path) -> None:
    path = _run(
        tmp_path,
        "20260101T000000Z",
        "partial",
        passes=[{"kind": "measured", "n": 2, "status": "timeout"}],
    )
    errors = record_errors(path, 4)
    assert any("status 'partial'" in e for e in errors)
    assert any("measured pass 2" in e for e in errors)
