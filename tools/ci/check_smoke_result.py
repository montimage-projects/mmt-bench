r"""Fail when a results directory's newest run records are not all ``ok``.

``mbench run`` exits 0 when at least one run is valid, but a campaign can
still have recorded ``partial``, ``timeout``, ``error``, ``interrupted`` or
``invalid`` runs. The smoke campaign's CI job needs the stricter gate (#9):
the run records of the newest batch must have finished ``ok``, with every
measured pass ``ok`` too. Results are append-only, so an earlier batch's
failed run stays in the directory and is not the gate. The record's schema
and its embedded SUT are ``mbench validate``'s job; this check is the status
gate only.

Usage: ``python tools/ci/check_smoke_result.py RESULTS_DIR`` — the campaign's
``results/<date>-<name>/`` directory. Exit 0 when the newest batch's
``runs/<batch>-*.json`` are all ``ok``, 1 when one is not, 2 when there was
nothing to check: no directory or no run files, so an empty answer never
passes silently.
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


def status_errors(path: Path) -> list[str]:
    """One error per non-``ok`` status in the run record ``path``."""
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
            if isinstance(p, dict) and p.get("kind") == "measured" and p.get("status") != "ok":
                errors.append(
                    f"{path.name}: measured pass {p.get('n')}: status {p.get('status')!r}, not 'ok'"
                )
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: check_smoke_result.py RESULTS_DIR", file=sys.stderr)
        return 2
    directory = Path(args[0])
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
    errors = [e for f in checked for e in status_errors(f)]
    for error in errors:
        print(f"check_smoke_result: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"check_smoke_result: batch {newest or '?'}, {len(checked)} run(s), all 'ok'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
