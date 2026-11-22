r"""Fail when a results directory's newest run records are not all ``ok``.

``mbench run`` exits 0 when at least one run is valid, but a campaign can
still have recorded ``partial``, ``timeout``, ``error``, ``interrupted`` or
``invalid`` runs. The smoke campaign's CI job needs the stricter gate (#9):
the run records of the newest batch must have finished ``ok``, with every
measured pass ``ok`` too — and every measured pass must report the expected
alert count and a detection rate of 1.0 against the corpus entry's ground
truth, so a broken alert path cannot pass as an ``alerts: 0`` record.
Results are append-only, so an earlier batch's failed run stays in the
directory and is not the gate. The record's schema and its embedded SUT are
``mbench validate``'s job; this check is the status and detection gate only.

Usage: ``python tools/ci/check_smoke_result.py RESULTS_DIR [EXPECTED_ALERTS]``
— the campaign's ``results/<date>-<name>/`` directory. With no
EXPECTED_ALERTS the expected count is derived per run record from the run's
own ground truth: ``cell.corpus.ground_truth`` names a truth file relative
to the corpus directory, resolved under ``corpus/`` exactly the way the
runner resolved it, and its ``pcap_sha256`` must equal the record's pcap
sha256. The expected count is then ``len(attacks)`` — the number of attacks
the pass's detection was scored against. That equals the alert count only
when every attack raises exactly one alert, which the generated
``--data-in-syn`` truth guarantees (one SYN packet, one attack, one rule-13
alert). A record with measured passes whose truth is missing, unreadable,
bound to another pcap or absent from the corpus reference cannot prove its
alert path and fails — the gate never passes on an empty answer.

EXPECTED_ALERTS remains as the explicit, binding-free override for a
results dir checked without its corpus — the truth file lives under the
git-ignored ``corpus/data/`` and is generated per host, never committed —
or for a corpus whose attacks may raise more than one alert each. It is
never the CI path: the workflow states the count once, in the
``--data-in-syn`` flag.

Exit 0 when the newest batch's ``runs/<batch>-*.json`` are all ``ok`` with
that detection, 1 when one is not, 2 when there was nothing to check: no
directory, no run files, or a bad argument — an empty answer never passes
silently.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

#: The batch a ``runs/`` file belongs to: ``<batch>-NN-<slug>.json``.
RUN_BATCH = re.compile(r"^(?P<batch>\d{8}T\d{6}Z(?:-\d+)?)-\d+-")

#: The corpus directory the run records' ``ground_truth`` paths are
#: relative to: ``tools/ci/check_smoke_result.py`` → repo root → ``corpus/``.
CORPUS_DIR = Path(__file__).resolve().parents[2] / "corpus"


def _batch_key(batch: str) -> tuple[str, int]:
    """The write order of a batch id: ``TS`` then ``TS-2``, ``TS-3``, ..."""
    base, _, n = batch.rpartition("-")
    return (base, int(n)) if n.isdigit() else (batch, 1)


def _resolve_truth(ref: dict[str, Any], corpus_dir: Path) -> Path | None:
    """The truth file the record's corpus entry names, under ``corpus_dir``.

    ``ground_truth`` in a run record is the manifest entry's path, relative
    to the corpus directory — the same resolution the runner used — so
    ``data/smoke.truth.json`` resolves to ``corpus/data/smoke.truth.json``.
    Anything resolving outside ``corpus_dir`` is rejected.
    """
    rel = ref.get("ground_truth")
    if not isinstance(rel, str) or not rel:
        return None
    root = corpus_dir.resolve()
    resolved = (root / rel).resolve()
    if resolved.is_relative_to(root) and resolved.is_file():
        return resolved
    return None


def _derived_expected(data: dict[str, Any], corpus_dir: Path, name: str) -> tuple[int, str | None]:
    """The expected alert count from the record's own ground truth.

    Returns ``(count, None)`` or ``(-1, error)``. The truth's attack count
    is the expectation: every attack of the generated ``--data-in-syn``
    truth raises exactly one alert.
    """
    cell = data.get("cell")
    ref = cell.get("corpus") if isinstance(cell, dict) else None
    if not isinstance(ref, dict):
        return -1, (
            f"{name}: no corpus reference to derive the expected alert count"
            " from; pass EXPECTED_ALERTS"
        )
    rel = ref.get("ground_truth")
    if not isinstance(rel, str) or not rel:
        return -1, (f"{name}: the corpus reference names no ground truth; pass EXPECTED_ALERTS")
    path = _resolve_truth(ref, corpus_dir)
    if path is None:
        return -1, (
            f"{name}: ground truth {rel!r} not found under {corpus_dir.resolve()};"
            " pass EXPECTED_ALERTS"
        )
    try:
        truth_doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return -1, f"{name}: unreadable ground truth {rel!r} ({exc})"
    if not isinstance(truth_doc, dict):
        return -1, f"{name}: unreadable ground truth {rel!r} (not an object)"
    if truth_doc.get("pcap_sha256") != ref.get("sha256"):
        return -1, (
            f"{name}: ground truth {rel!r} is for pcap "
            f"{truth_doc.get('pcap_sha256')!r}, not {ref.get('sha256')!r}"
        )
    attacks = truth_doc.get("attacks")
    if not isinstance(attacks, list):
        return -1, f"{name}: ground truth {rel!r} has no attacks list"
    return len(attacks), None


def record_errors(
    path: Path, expected_alerts: int | None, corpus_dir: Path = CORPUS_DIR
) -> list[str]:
    """One error per non-``ok`` status or wrong detection in the run record."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"{path.name}: unreadable run record ({exc})"]
    if not isinstance(data, dict):
        return [f"{path.name}: unreadable run record (not an object)"]
    errors = []
    status = data.get("status")
    if status != "ok":
        errors.append(f"{path.name}: status {status!r}, not 'ok'")
    passes = data.get("passes")
    measured = (
        [p for p in passes if isinstance(p, dict) and p.get("kind") == "measured"]
        if isinstance(passes, list)
        else []
    )
    expected = expected_alerts
    if expected is None and measured:
        expected, err = _derived_expected(data, corpus_dir, path.name)
        if err is not None:
            errors.append(err)
    for p in measured:
        where = f"{path.name}: measured pass {p.get('n')}"
        if p.get("status") != "ok":
            errors.append(f"{where}: status {p.get('status')!r}, not 'ok'")
        if expected is not None and expected >= 0:
            alerts = p.get("alerts")
            if alerts != expected:
                errors.append(f"{where}: alerts {alerts!r}, expected {expected}")
        detection = p.get("detection")
        rate = detection.get("detection_rate") if isinstance(detection, dict) else None
        if rate != 1.0:
            errors.append(f"{where}: detection_rate {rate!r}, not 1.0")
    return errors


def main(argv: Sequence[str] | None = None, corpus_dir: Path = CORPUS_DIR) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) not in (1, 2):
        print("usage: check_smoke_result.py RESULTS_DIR [EXPECTED_ALERTS]", file=sys.stderr)
        return 2
    directory = Path(args[0])
    expected_alerts: int | None = None
    if len(args) == 2:
        try:
            expected_alerts = int(args[1])
        except ValueError:
            expected_alerts = -1
        if expected_alerts < 0:
            print("usage: check_smoke_result.py RESULTS_DIR [EXPECTED_ALERTS]", file=sys.stderr)
            print(
                f"check_smoke_result: EXPECTED_ALERTS must be an integer >= 0: {args[1]!r}",
                file=sys.stderr,
            )
            return 2
    runs_dir = directory / "runs"
    files = sorted(runs_dir.glob("*.json")) if runs_dir.is_dir() else []
    if not files:
        print(f"check_smoke_result: no runs/*.json records in {directory}", file=sys.stderr)
        return 2
    batches = {m.group("batch") for f in files if (m := RUN_BATCH.match(f.name))}
    newest = max(batches, key=_batch_key, default=None)
    checked = [
        f for f in files if (m := RUN_BATCH.match(f.name)) is None or m.group("batch") == newest
    ]
    errors = [e for f in checked for e in record_errors(f, expected_alerts, corpus_dir)]
    for error in errors:
        print(f"check_smoke_result: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"check_smoke_result: batch {newest or '?'}, {len(checked)} run(s), all 'ok'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
