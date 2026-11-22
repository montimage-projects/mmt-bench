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

Usage: ``python tools/ci/check_smoke_result.py RESULTS_DIR EXPECTED_ALERTS``
— the campaign's ``results/<date>-<name>/`` directory and the alert count
the smoke corpus entry's ground truth leads every measured pass to report.
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

#: The batch a ``runs/`` file belongs to: ``<batch>-NN-<slug>.json``.
RUN_BATCH = re.compile(r"^(?P<batch>\d{8}T\d{6}Z(?:-\d+)?)-\d+-")


def _batch_key(batch: str) -> tuple[str, int]:
    """The write order of a batch id: ``TS`` then ``TS-2``, ``TS-3``, ..."""
    base, _, n = batch.rpartition("-")
    return (base, int(n)) if n.isdigit() else (batch, 1)


def record_errors(path: Path, expected_alerts: int) -> list[str]:
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
    if isinstance(passes, list):
        for p in passes:
            if not (isinstance(p, dict) and p.get("kind") == "measured"):
                continue
            where = f"{path.name}: measured pass {p.get('n')}"
            if p.get("status") != "ok":
                errors.append(f"{where}: status {p.get('status')!r}, not 'ok'")
            alerts = p.get("alerts")
            if alerts != expected_alerts:
                errors.append(f"{where}: alerts {alerts!r}, expected {expected_alerts}")
            detection = p.get("detection")
            rate = detection.get("detection_rate") if isinstance(detection, dict) else None
            if rate != 1.0:
                errors.append(f"{where}: detection_rate {rate!r}, not 1.0")
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: check_smoke_result.py RESULTS_DIR EXPECTED_ALERTS", file=sys.stderr)
        return 2
    directory = Path(args[0])
    try:
        expected_alerts = int(args[1])
    except ValueError:
        expected_alerts = -1
    if expected_alerts < 0:
        print("usage: check_smoke_result.py RESULTS_DIR EXPECTED_ALERTS", file=sys.stderr)
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
    errors = [e for f in checked for e in record_errors(f, expected_alerts)]
    for error in errors:
        print(f"check_smoke_result: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"check_smoke_result: batch {newest or '?'}, {len(checked)} run(s), all 'ok'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
