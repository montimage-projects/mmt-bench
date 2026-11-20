"""Access to the dgx-spark fixtures under ``tests/fixtures/dgx-spark/``.

``sources.json`` is a sanitised :class:`~mbench.hostsrc.RecordingSource`
snapshot of one ``mbench sut`` run on dgx-spark (see the README next to it).
``sut.json`` is the record the collector builds when it replays that snapshot
with :func:`replay_options`; regenerate it with ``MBENCH_REGEN_FIXTURES=1``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

from mbench import sut
from mbench.hostsrc import SnapshotSource, command_key

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "dgx-spark"
SOURCES = FIXTURES / "sources.json"
GOLDEN = FIXTURES / "sut.json"
ALIAS = "dgx-spark"

HARNESS = sut.HarnessInfo(
    mbench_version="0.1.0",
    mbench_commit="0" * 40,
    mbench_dirty=False,
    python_version="3.12.0",
    python_implementation="CPython",
)


@cache
def snapshot() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(SOURCES.read_text(encoding="utf-8"))
    return data


def file_text(path: str, answer: int = 0) -> str:
    """What dgx-spark returned for ``path`` (the ``answer``-th read)."""
    value = snapshot()["files"][path][answer]
    assert isinstance(value, str), f"{path} was not readable: {value}"
    return value


def command_stdout(*argv: str) -> str:
    entry = snapshot()["commands"][command_key(argv)][0]
    assert entry["returncode"] == 0, entry
    return str(entry["stdout"])


def source() -> SnapshotSource:
    return SnapshotSource(snapshot())


def fixed_clock() -> datetime:
    return datetime(2026, 11, 20, 22, 0, 0, tzinfo=UTC)


def replay_options(**overrides: Any) -> sut.Options:
    options = sut.Options(alias=ALIAS, harness=HARNESS, clock=fixed_clock)
    for key, value in overrides.items():
        setattr(options, key, value)
    return options


def replay(**overrides: Any) -> dict[str, Any]:
    return sut.collect(source(), replay_options(**overrides))
