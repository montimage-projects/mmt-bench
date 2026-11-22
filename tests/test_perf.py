"""``mbench.metrics.perf`` (#10): the perf stat parser, the availability
probe and its unavailable markers, and Luong's root-only enable note.

Nothing here runs the host's perf: the probe's ``run`` and ``spawn`` are
injected fakes, and the recorded ``perf stat -x ,`` output is host-neutral.
"""

from __future__ import annotations

import signal
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from mbench.metrics import perf

#: A recorded ``perf stat -a -C 5 -x , -e cycles -e instructions`` output,
#: host-neutral: comment lines, one <not counted> row, real count rows.
STAT_CSV = """# started on 2026-01-05T12:00:00
1234567,,cycles,100.00,,,,
2345678,,instructions,100.00,,,,
<not counted>,,branch-misses,100.00,,,,
# ended
"""

#: ``cpu-cycles`` is an event perf reports under its own name: it must not
#: be taken for the ``cycles`` event — matching is on the name exactly.
TRICKY_CSV = """999,,cpu-cycles,100.00,,,,
777,,cpu-cycles/foo/,100.00,,,,
"""

#: A ``perf stat -x ,`` output scoped to one cgroup: each counter row
#: carries the cgroup name as a trailing field.
CGROUP_CSV = """1234567,,cycles,100.00,,,,system.slice/docker-abc.scope
2345678,,instructions,100.00,,,,system.slice/docker-abc.scope
"""


class FakePopen:
    """The ``perf stat`` session process: SIGINT ends it, then ``out`` is read."""

    def __init__(self, argv: Sequence[str], writes: dict[Path, str]) -> None:
        self.argv = list(argv)
        self.signals: list[int] = []
        self.killed = False
        out = Path(argv[argv.index("-o") + 1]) if "-o" in argv else None
        if out is not None and out in writes:
            out.write_text(writes[out], encoding="utf-8")

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        self.killed = True


def _completed(argv: Sequence[str], rc: int = 0, stderr: bytes = b"") -> perf.Completed:
    return subprocess.CompletedProcess(list(argv), rc, b"", stderr)


def test_the_csv_parser_reads_cycles_and_instructions() -> None:
    assert perf.parse_stat_csv(STAT_CSV) == {"cycles": 1234567.0, "instructions": 2345678.0}


def test_the_parser_matches_event_names_exactly() -> None:
    counts = perf.parse_stat_csv(TRICKY_CSV)
    assert counts == {}  # cpu-cycles is its own event, not "cycles"


def test_the_parser_ignores_not_supported() -> None:
    text = "<not supported>,,cycles,100.00,,,,\n500,,instructions,100.00,,,,\n"
    assert perf.parse_stat_csv(text) == {"instructions": 500.0}


# --- availability detection ----------------------------------------------------


def test_a_missing_perf_binary_is_a_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mbench.metrics.perf.shutil.which", lambda name: None)
    probe = perf.Probe(paranoid_path=tmp_path / "nope")
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "missing_tool"
    assert "perf" in marker["reason"]


def test_paranoid_4_is_needs_root_with_the_value(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("4\n", encoding="utf-8")
    calls: list[Sequence[str]] = []

    def canary(argv: Sequence[str]) -> perf.Completed:
        calls.append(argv)
        return _completed(argv, 1, b"no permission")

    probe = perf.Probe(binary="/usr/bin/perf", paranoid_path=knob, run=canary)
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "needs_root"
    assert "perf_event_paranoid=4" in marker["reason"]
    assert probe.paranoid == 4
    assert calls == []  # the canary never runs: the knob already answers


def test_a_refused_canary_is_the_marker(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("1\n", encoding="utf-8")
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        run=lambda argv: _completed(argv, 129, b"event syntax error"),
    )
    marker = probe.unavailable
    assert marker is not None and "perf stat refused" in marker["reason"]


def test_a_passing_canary_leaves_the_probe_available(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("1\n", encoding="utf-8")
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        run=lambda argv: _completed(argv),
    )
    assert probe.unavailable is None


# --- a session -----------------------------------------------------------------


def _spawned() -> tuple[list[FakePopen], Callable[[Sequence[str]], subprocess.Popen[bytes]]]:
    procs: list[FakePopen] = []

    def spawn(argv: Sequence[str]) -> subprocess.Popen[bytes]:
        proc = FakePopen(argv, {})
        procs.append(proc)
        return proc  # type: ignore[return-value]

    return procs, spawn


def test_a_session_counts_the_cpuset_and_divides(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("1\n", encoding="utf-8")
    spawned, spawn = _spawned()
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        run=lambda argv: _completed(argv),
        spawn=spawn,
    )
    session = probe.start([5, 6])
    assert session is not None and session.scope == "cpuset"
    # the exact argv this perf build gets (re-reviewed: events precede -G)
    assert spawned[0].argv == [
        "/usr/bin/perf",
        "stat",
        "-e",
        "cycles",
        "-e",
        "instructions",
        "-a",
        "-C",
        "5-6",
        "-x",
        ",",
        "-o",
        str(session.out),
        "--",
        "sleep",
        perf._SESSION_CAP_S,
    ]
    session.out.write_text(STAT_CSV, encoding="utf-8")

    record = probe.record(session, 1000)
    assert record["cycles"] == 1234567.0
    assert record["cycles_per_packet"] == pytest.approx(1234.567)
    assert record["instructions_per_cycle"] == pytest.approx(2345678 / 1234567)
    assert spawned[0].signals == [signal.SIGINT]  # stopped like a Ctrl-C
    assert not session.out.exists()  # the csv never outlives the pass


def test_the_cgroup_scope_counts_the_passs_own_container(tmp_path: Path) -> None:
    # The run's own container is the tighter scope; on this perf build
    # `-G` must follow the events ("must define events before cgroups")
    # and needs system-wide `-a`.
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("1\n", encoding="utf-8")
    spawned, spawn = _spawned()
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        run=lambda argv: _completed(argv),
        spawn=spawn,
    )
    session = probe.start([5, 6], "system.slice/docker-" + "ab" * 32 + ".scope")
    assert session is not None and session.scope == "cgroup"
    argv = spawned[0].argv
    assert argv == [
        "/usr/bin/perf",
        "stat",
        "-e",
        "cycles",
        "-e",
        "instructions",
        "-a",
        "-G",
        "system.slice/docker-" + "ab" * 32 + ".scope",
        "-x",
        ",",
        "-o",
        str(session.out),
        "--",
        "sleep",
        perf._SESSION_CAP_S,
    ]
    assert "-C" not in argv
    session.out.write_text(CGROUP_CSV, encoding="utf-8")
    record = probe.record(session, 1000)
    assert record["scope"] == "cgroup"
    assert record["cycles"] == 1234567.0
    assert record["cycles_per_packet"] == pytest.approx(1234.567)


def test_the_parser_tolerates_the_cgroup_column() -> None:
    # -G output carries the cgroup name on each row; the count is field 0
    # and the event name matched exactly wherever the column lands.
    assert perf.parse_stat_csv(CGROUP_CSV) == {
        "cycles": 1234567.0,
        "instructions": 2345678.0,
    }


def test_an_unpinned_pass_is_not_applicable(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("1\n", encoding="utf-8")
    probe = perf.Probe(
        binary="/usr/bin/perf", paranoid_path=knob, run=lambda argv: _completed(argv)
    )
    assert probe.start([]) is None
    record = probe.record(None, None)
    assert record["unavailable"] == "not_applicable"


def test_an_unavailable_probe_marks_every_pass(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("4\n", encoding="utf-8")
    probe = perf.Probe(binary="/usr/bin/perf", paranoid_path=knob)
    record = probe.record(None, 100)
    assert record["unavailable"] == "needs_root"


def test_an_empty_count_file_is_an_error_marker(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("1\n", encoding="utf-8")
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        run=lambda argv: _completed(argv),
        spawn=lambda argv: FakePopen(argv, {}),  # type: ignore[arg-type,return-value]
    )
    session = probe.start([5])
    assert session is not None
    session.out.write_text("", encoding="utf-8")
    record = probe.record(session, 10)
    assert record["unavailable"] == "error"


# --- Luong's runbook ------------------------------------------------------------


def test_the_enable_note_prints_both_options_and_the_restore(tmp_path: Path) -> None:
    marker = {"unavailable": "needs_root", "reason": "kernel.perf_event_paranoid=4"}
    lines = perf.enable_note(marker, 4)
    text = "\n".join(lines)
    assert "cap_perfmon=ep" in text  # option A: the narrow capability
    assert "kernel.perf_event_paranoid=1" in text  # option B: the sysctl
    assert "kernel.perf_event_paranoid=4" in text  # the restore value
    assert "never runs these" in text  # the harness only prints them
