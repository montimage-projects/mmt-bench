"""``tools/ci/check_smoke_result.py``: the smoke CI job's gate (#9, #35).

Results are append-only, so the gate is the *newest* batch's run records: an
earlier batch's failed run stays in the directory and is not the gate. Every
measured pass must also report the expected alert count and detection rate
1.0: a broken alert path cannot pass as an ``alerts: 0`` record. With no
EXPECTED_ALERTS the count is derived per record from its own ground truth —
``cell.corpus.ground_truth`` resolved under the corpus dir and bound by
``pcap_sha256`` — so ``ci.yml`` states the count once, in the ``corpus
gen --data-in-syn`` flag. The run record's schema and its embedded SUT are
``mbench validate``'s job.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from check_smoke_result import main, record_errors

EXPECTED = "4"
PCAP_SHA = "a" * 64
DETECTION = {"rules": {"13": {"expected": 4, "detected": 4, "missed": 0}}, "detection_rate": 1.0}
CORPUS_REF = {
    "label": "smoke",
    "sha256": PCAP_SHA,
    "ground_truth": "data/smoke.truth.json",
    "local_only": False,
}


def _truth(attacks: int = 4, pcap_sha256: str = PCAP_SHA) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "pcap_sha256": pcap_sha256,
        "attacks": [{"id": f"data-in-syn-{i + 1}"} for i in range(attacks)],
    }


@pytest.fixture
def corpus_dir(tmp_path: Path) -> Path:
    """A corpus dir holding the generated ``data/smoke.truth.json``."""
    data = tmp_path / "corpus" / "data"
    data.mkdir(parents=True)
    (data / "smoke.truth.json").write_text(json.dumps(_truth()), encoding="utf-8")
    return tmp_path / "corpus"


def _run(
    directory: Path,
    batch: str,
    status: str,
    *,
    index: int = 0,
    corpus_ref: dict[str, Any] | None = CORPUS_REF,
    **record: Any,
) -> Path:
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
    cell = {"corpus": corpus_ref} if corpus_ref is not None else {}
    path = runs / f"{batch}-{index:02d}-cell.json"
    path.write_text(
        json.dumps({"status": status, "cell": cell, "passes": passes, **record}),
        encoding="utf-8",
    )
    return path


def _measured(**pass_fields: Any) -> list[dict[str, Any]]:
    base = {"kind": "measured", "n": 1, "status": "ok", "wall_s": 0.4, "alerts": 4}
    base["detection"] = DETECTION
    base.update(pass_fields)
    return [base]


def test_no_directory_exits_2(tmp_path: Path) -> None:
    assert main([str(tmp_path / "missing")]) == 2
    (tmp_path / "empty").mkdir()
    assert main([str(tmp_path / "empty")]) == 2


def test_bad_args_is_a_usage_error() -> None:
    assert main([]) == 2
    assert main(["a", "b", "c"]) == 2
    assert main(["a", "not-an-int"]) == 2
    assert main(["a", "-1"]) == 2


def test_an_ok_run_passes(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(tmp_path, "20260101T000000Z", "ok")
    assert main([str(tmp_path)], corpus_dir) == 0
    assert "all 'ok'" in capsys.readouterr().out


@pytest.mark.parametrize("status", ["partial", "timeout", "error", "interrupted", "invalid"])
def test_a_non_ok_status_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str], status: str
) -> None:
    _run(tmp_path, "20260101T000000Z", status)
    assert main([str(tmp_path)], corpus_dir) == 1
    assert f"status {status!r}, not 'ok'" in capsys.readouterr().err


def test_an_ok_run_with_a_failed_measured_pass_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(status="timeout"))
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "measured pass 1" in capsys.readouterr().err


def test_a_zero_alert_measured_pass_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A broken alert path records an all-ok run with alerts: 0 — the same
    # shape a correct benign run used to have. The expected count is the gate.
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(alerts=0))
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "alerts 0, expected 4" in capsys.readouterr().err


@pytest.mark.parametrize("alerts", [3, 5])
def test_a_wrong_alert_count_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str], alerts: int
) -> None:
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(alerts=alerts))
    assert main([str(tmp_path)], corpus_dir) == 1
    assert f"alerts {alerts}, expected 4" in capsys.readouterr().err


def test_a_detection_rate_below_one_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    detection = {
        "rules": {"13": {"expected": 4, "detected": 3, "missed": 1}},
        "detection_rate": 0.75,
    }
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(detection=detection))
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "detection_rate 0.75, not 1.0" in capsys.readouterr().err


def test_a_missing_detection_field_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(
        tmp_path,
        "20260101T000000Z",
        "ok",
        passes=[{"kind": "measured", "n": 1, "status": "ok", "wall_s": 0.4, "alerts": 4}],
    )
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "detection_rate None, not 1.0" in capsys.readouterr().err


def test_a_failed_warmup_alone_is_not_the_gate(tmp_path: Path, corpus_dir: Path) -> None:
    # A run's status is the record's word for it; the gate checks measured
    # passes only, the same field `mbench run`'s own verdict uses.
    _run(
        tmp_path,
        "20260101T000000Z",
        "ok",
        passes=[{"kind": "warmup", "n": 0, "status": "timeout", "wall_s": 10.0}, *_measured()],
    )
    assert main([str(tmp_path)], corpus_dir) == 0


def test_only_the_newest_batch_is_the_gate(tmp_path: Path, corpus_dir: Path) -> None:
    # Append-only: a previous failed campaign's run record stays in the
    # directory; the gate is the batch this run produced.
    _run(tmp_path, "20260101T000000Z", "timeout", passes=_measured(alerts=0))
    _run(tmp_path, "20260101T000000Z-2", "ok")
    assert main([str(tmp_path)], corpus_dir) == 0


def test_an_older_batch_failure_with_no_new_run_still_fails(
    tmp_path: Path, corpus_dir: Path
) -> None:
    _run(tmp_path, "20260101T000000Z", "timeout")
    assert main([str(tmp_path)], corpus_dir) == 1


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


# --- the derived expectation (#35) ----------------------------------------


def test_a_missing_truth_file_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The corpus dir — and with it the git-ignored truth file — is absent:
    # the run cannot prove its alert path, so it fails rather than passing
    # on an empty answer.
    _run(tmp_path, "20260101T000000Z", "ok")
    assert main([str(tmp_path)], tmp_path / "corpus") == 1
    err = capsys.readouterr().err
    assert "ground truth 'data/smoke.truth.json' not found" in err
    assert "EXPECTED_ALERTS" in err


def test_a_truth_for_another_pcap_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (corpus_dir / "data" / "smoke.truth.json").write_text(
        json.dumps(_truth(pcap_sha256="b" * 64)), encoding="utf-8"
    )
    _run(tmp_path, "20260101T000000Z", "ok")
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "is for pcap" in capsys.readouterr().err


def test_an_unreadable_truth_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (corpus_dir / "data" / "smoke.truth.json").write_text("{cut off", encoding="utf-8")
    _run(tmp_path, "20260101T000000Z", "ok")
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "unreadable ground truth" in capsys.readouterr().err


def test_a_truth_without_an_attacks_list_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (corpus_dir / "data" / "smoke.truth.json").write_text(
        json.dumps({"pcap_sha256": PCAP_SHA, "attacks": {"not": "a list"}}), encoding="utf-8"
    )
    _run(tmp_path, "20260101T000000Z", "ok")
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "no attacks list" in capsys.readouterr().err


def test_a_truth_path_escaping_the_corpus_dir_fails(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ref = {**CORPUS_REF, "ground_truth": "../outside.truth.json"}
    (tmp_path / "outside.truth.json").write_text(json.dumps(_truth()), encoding="utf-8")
    _run(tmp_path, "20260101T000000Z", "ok", corpus_ref=ref)
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "not found" in capsys.readouterr().err


def test_a_record_without_a_corpus_reference_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(tmp_path, "20260101T000000Z", "ok", corpus_ref=None)
    assert main([str(tmp_path)]) == 1
    assert "EXPECTED_ALERTS" in capsys.readouterr().err


def test_a_record_without_a_ground_truth_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A local_only ref carries label and sha256 but never the truth path.
    ref = {"label": "private", "sha256": PCAP_SHA, "local_only": True}
    _run(tmp_path, "20260101T000000Z", "ok", corpus_ref=ref)
    assert main([str(tmp_path)]) == 1
    assert "EXPECTED_ALERTS" in capsys.readouterr().err


def test_a_record_with_no_measured_passes_needs_no_truth(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A cell that never reached a measured pass has nothing to check the
    # count against: the gate reports its real errors, never a corpus error.
    _run(
        tmp_path,
        "20260101T000000Z",
        "error",
        corpus_ref=None,
        passes=[{"kind": "warmup", "n": 0, "status": "error"}],
    )
    assert main([str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "status 'error'" in err and "EXPECTED_ALERTS" not in err


def test_a_bare_truth_name_resolves_manifest_relative(tmp_path: Path, corpus_dir: Path) -> None:
    # ``ground_truth`` is a manifest path, relative to the corpus dir: a
    # bare name resolves to corpus/<name>.
    (corpus_dir / "data" / "smoke.truth.json").rename(corpus_dir / "smoke.truth.json")
    ref = {**CORPUS_REF, "ground_truth": "smoke.truth.json"}
    _run(tmp_path, "20260101T000000Z", "ok", corpus_ref=ref)
    assert main([str(tmp_path)], corpus_dir) == 0


def test_the_gate_does_not_search_for_the_truth(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Only the named path resolves: the same file under corpus/data/ is not
    # picked up for a bare-name ref.
    ref = {**CORPUS_REF, "ground_truth": "smoke.truth.json"}
    _run(tmp_path, "20260101T000000Z", "ok", corpus_ref=ref)
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "not found" in capsys.readouterr().err


def test_a_derived_count_follows_the_truth_not_a_constant(
    tmp_path: Path, corpus_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The expectation is the truth's attack count, not a baked-in 4: a
    # 3-attack truth expects 3 alerts.
    (corpus_dir / "data" / "smoke.truth.json").write_text(
        json.dumps(_truth(attacks=3)), encoding="utf-8"
    )
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(alerts=3))
    assert main([str(tmp_path)], corpus_dir) == 0
    _run(tmp_path, "20260101T000000Z-2", "ok", passes=_measured(alerts=4))
    assert main([str(tmp_path)], corpus_dir) == 1
    assert "alerts 4, expected 3" in capsys.readouterr().err


def test_the_override_needs_no_truth_file(tmp_path: Path) -> None:
    # The explicit count is the binding-free path: for a results dir checked
    # without its corpus the truth file is simply absent.
    _run(tmp_path, "20260101T000000Z", "ok")
    assert main([str(tmp_path), EXPECTED], tmp_path / "corpus") == 0


def test_the_override_still_gates_wrong_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(tmp_path, "20260101T000000Z", "ok", passes=_measured(alerts=5))
    assert main([str(tmp_path), EXPECTED]) == 1
    assert "alerts 5, expected 4" in capsys.readouterr().err
