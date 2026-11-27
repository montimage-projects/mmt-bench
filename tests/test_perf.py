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
    probe = perf.Probe(paranoid_path=tmp_path / "nope", env={}, home=tmp_path)
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "missing_tool"
    assert "perf" in marker["reason"]


def test_a_pinned_uncapped_binary_at_paranoid_4_is_needs_root(tmp_path: Path) -> None:
    # A pinned binary gets the same access checks as a discovered one:
    # no getcap, so the refused canary answers — and names the knob.
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("4\n", encoding="utf-8")
    calls: list[Sequence[str]] = []

    def canary(argv: Sequence[str]) -> perf.Completed:
        calls.append(list(argv))
        return _completed(argv, 1, b"no permission")

    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        which=lambda name: None,
        run=canary,
    )
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "needs_root"
    assert "perf_event_paranoid=4" in marker["reason"]
    assert probe.paranoid == 4
    assert len(calls) == 1  # the canary ran: the knob alone is not the verdict


def test_a_pinned_capped_binary_at_paranoid_4_is_available(tmp_path: Path) -> None:
    # The review finding: a working pinned binary must not be rejected on
    # the paranoid knob alone — CAP_PERFMON lifts it, and getcap says so.
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("4\n", encoding="utf-8")
    calls, run = _fake_run(caps={"/usr/bin/perf": "cap_perfmon=ep"})
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        which=lambda name: "/fake/getcap" if name == "getcap" else None,
        run=run,
    )
    assert probe.unavailable is None
    assert [Path(str(c[0])).name for c in calls] == ["getcap", "perf"]


def test_a_pinned_missing_binary_is_missing_tool(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("4\n", encoding="utf-8")
    probe = perf.Probe(binary=str(tmp_path / "gone"), paranoid_path=knob, which=lambda name: None)
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "missing_tool"
    assert "gone" in marker["reason"]


def test_a_refused_canary_is_the_marker(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("1\n", encoding="utf-8")
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        which=lambda name: None,
        run=lambda argv: _completed(argv, 129, b"event syntax error"),
    )
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "needs_root"
    assert "perf stat refused" in marker["reason"]
    assert "perf_event_paranoid=1" in marker["reason"]  # the hint names the knob


def test_a_refused_canary_below_paranoid_1_is_an_error(tmp_path: Path) -> None:
    # At 0 the kernel allows CPU-wide counting to anyone, so a refusal is
    # a real error, not an access marker.
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("0\n", encoding="utf-8")
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        which=lambda name: None,
        run=lambda argv: _completed(argv, 129, b"event syntax error"),
    )
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "error"
    assert "perf stat refused" in marker["reason"]
    assert "perf_event_paranoid" not in marker["reason"]  # no knob hint at 0


def test_a_passing_canary_leaves_the_probe_available(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("1\n", encoding="utf-8")
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        which=lambda name: None,
        run=lambda argv: _completed(argv),
    )
    assert probe.unavailable is None


# --- binary discovery (issue #50) ----------------------------------------------
#
# Order: $MBENCH_PERF, then ~/.local/bin/perf-mbench, then perf on PATH. Each
# found binary is verified — kernel-match against the fake linux-tools
# reference under tmp_path, then cap_perfmon via a faked getcap (or the
# canary when getcap is absent) — and the first candidate passing wins.

RELEASE = "6.17.0-test"
KERNEL_BLOB = b"fake-perf-binary"


def _knob(tmp_path: Path, level: int) -> Path:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text(f"{level}\n", encoding="utf-8")
    return knob


def _tools_dir(tmp_path: Path, blob: bytes = KERNEL_BLOB) -> Path:
    """A fake ``/usr/lib/linux-tools/<release>/perf`` reference."""
    ref = tmp_path / "linux-tools" / RELEASE
    ref.mkdir(parents=True, exist_ok=True)
    (ref / "perf").write_bytes(blob)
    return tmp_path / "linux-tools"


def _copy(path: Path, blob: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return path


def _fake_run(
    caps: dict[str, str] | None = None, canary_rc: int = 0, canary_stderr: bytes = b""
) -> tuple[list[Sequence[str]], Callable[[Sequence[str]], perf.Completed]]:
    """A ``run`` fake: getcap answers from ``caps``, anything else is the canary."""
    calls: list[Sequence[str]] = []

    def run(argv: Sequence[str]) -> perf.Completed:
        calls.append(list(argv))
        if Path(str(argv[0])).name == "getcap":
            out = f"{argv[1]} {(caps or {}).get(str(argv[1]), '')}\n".encode()
            return subprocess.CompletedProcess(list(argv), 0, out, b"")
        return _completed(argv, canary_rc, canary_stderr)

    return calls, run


def _discover(
    tmp_path: Path,
    *,
    paranoid: int = 1,
    env: dict[str, str] | None = None,
    home: Path | None = None,
    which: Callable[[str], str | None] | None = None,
    run: Callable[[Sequence[str]], perf.Completed],
    spawn: Callable[[Sequence[str]], subprocess.Popen[bytes]] | None = None,
) -> perf.Probe:
    return perf.Probe(
        paranoid_path=_knob(tmp_path, paranoid),
        env={} if env is None else env,
        home=tmp_path / "nohome" if home is None else home,
        release=RELEASE,
        tools_dir=_tools_dir(tmp_path),
        which=(lambda name: None) if which is None else which,
        run=run,
        spawn=perf._default_spawn if spawn is None else spawn,
    )


def test_the_env_override_wins(tmp_path: Path) -> None:
    # $MBENCH_PERF beats two other *working* candidates — the order the
    # issue pins, not just fall-through on failure.
    env_binary = _copy(tmp_path / "elsewhere" / "my-perf", KERNEL_BLOB)
    home = tmp_path / "home"
    _copy(home / ".local" / "bin" / "perf-mbench", KERNEL_BLOB)
    path_binary = _copy(tmp_path / "bin" / "perf", KERNEL_BLOB)
    calls, run = _fake_run()
    spawned, spawn = _spawned()
    probe = _discover(
        tmp_path,
        env={perf.ENV_BINARY: str(env_binary)},
        home=home,
        which=lambda name: str(path_binary) if name == "perf" else None,
        run=run,
        spawn=spawn,
    )
    assert probe.unavailable is None
    # The env binary was verified and the other two were never even tried.
    assert calls == [
        [
            str(env_binary),
            "stat",
            "-a",
            "-e",
            "cycles",
            "-x",
            ",",
            "--",
            "sleep",
            "0.05",
        ]
    ]
    session = probe.start([5])
    assert session is not None
    session.out.write_text(STAT_CSV, encoding="utf-8")
    assert probe.record(session, 10)["binary"] == str(env_binary)
    assert spawned[0].argv[0] == str(env_binary)


def test_the_default_copy_beats_path_perf(tmp_path: Path) -> None:
    # Second in the order: a working perf-mbench is selected over a
    # working PATH perf — the priority among successes, #50.
    home = tmp_path / "home"
    binary = _copy(home / ".local" / "bin" / "perf-mbench", KERNEL_BLOB)
    path_binary = _copy(tmp_path / "bin" / "perf", KERNEL_BLOB)
    calls, run = _fake_run()
    _spawned_list, spawn = _spawned()
    probe = _discover(
        tmp_path,
        home=home,
        which=lambda name: str(path_binary) if name == "perf" else None,
        run=run,
        spawn=spawn,
    )
    assert probe.unavailable is None
    assert calls == [[str(binary), "stat", "-a", "-e", "cycles", "-x", ",", "--", "sleep", "0.05"]]
    session = probe.start([5])
    assert session is not None
    session.out.write_text(STAT_CSV, encoding="utf-8")
    assert probe.record(session, 10)["binary"] == "~/.local/bin/perf-mbench"


def test_the_default_perf_mbench_copy_is_found_and_capped(tmp_path: Path) -> None:
    home = tmp_path / "home"
    binary = _copy(home / ".local" / "bin" / "perf-mbench", KERNEL_BLOB)
    calls, run = _fake_run(caps={str(binary): "cap_perfmon=ep"})
    probe = _discover(
        tmp_path,
        paranoid=4,
        home=home,
        which=lambda name: "/fake/getcap" if name == "getcap" else None,
        run=run,
    )
    assert probe.unavailable is None
    assert Path(str(calls[0][0])).name == "getcap"  # the cap check precedes the canary
    assert calls[0][1] == str(binary)
    assert calls[1][0] == str(binary)  # then the one-event stat canary


def test_path_perf_is_the_last_candidate(tmp_path: Path) -> None:
    path_perf = _copy(tmp_path / "bin" / "perf", b"#!/bin/sh\nexec real-perf\n")
    calls, run = _fake_run()
    probe = _discover(
        tmp_path, which=lambda name: str(path_perf) if name == "perf" else None, run=run
    )
    assert probe.unavailable is None
    assert calls[0][0] == str(path_perf)


def test_a_stale_copy_is_rejected_before_any_subprocess(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _copy(home / ".local" / "bin" / "perf-mbench", b"old-perf")
    calls, run = _fake_run()
    probe = _discover(tmp_path, paranoid=4, home=home, run=run)
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "needs_root"
    assert "stale" in marker["reason"] and "sha256" in marker["reason"]
    assert "~/.local/bin/perf-mbench" in marker["reason"]  # never the absolute home path
    assert calls == []


def test_a_stale_copy_falls_through_to_path_perf(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _copy(home / ".local" / "bin" / "perf-mbench", b"old-perf")
    path_perf = _copy(tmp_path / "bin" / "perf", b"#!/bin/sh\nexec real-perf\n")
    calls, run = _fake_run()
    probe = _discover(
        tmp_path,
        paranoid=4,
        home=home,
        which=lambda name: str(path_perf) if name == "perf" else None,
        run=run,
    )
    assert probe.unavailable is None
    assert calls[0][0] == str(path_perf)


@pytest.mark.parametrize("paranoid", (1, 4))
def test_an_uncapped_binary_is_rejected(tmp_path: Path, paranoid: int) -> None:
    # CPU-wide counting already needs CAP_PERFMON at paranoid 1 — getcap
    # reports no capabilities, so the candidate is rejected with no canary.
    home = tmp_path / "home"
    _copy(home / ".local" / "bin" / "perf-mbench", KERNEL_BLOB)
    calls, run = _fake_run(caps={})  # getcap reports no capabilities
    probe = _discover(
        tmp_path,
        paranoid=paranoid,
        home=home,
        which=lambda name: "/fake/getcap" if name == "getcap" else None,
        run=run,
    )
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "needs_root"
    assert "cap_perfmon" in marker["reason"]
    assert len(calls) == 1 and Path(str(calls[0][0])).name == "getcap"  # no canary


@pytest.mark.parametrize("paranoid", (1, 4))
def test_a_capped_binary_is_accepted(tmp_path: Path, paranoid: int) -> None:
    home = tmp_path / "home"
    binary = _copy(home / ".local" / "bin" / "perf-mbench", KERNEL_BLOB)
    calls, run = _fake_run(caps={str(binary): "cap_perfmon=ep"})
    probe = _discover(
        tmp_path,
        paranoid=paranoid,
        home=home,
        which=lambda name: "/fake/getcap" if name == "getcap" else None,
        run=run,
    )
    assert probe.unavailable is None
    assert [Path(str(c[0])).name for c in calls] == ["getcap", "perf-mbench"]


def test_an_uncapped_binary_at_paranoid_0_skips_the_cap_check(tmp_path: Path) -> None:
    # At 0 the kernel refuses nothing: no getcap call, the canary decides.
    home = tmp_path / "home"
    binary = _copy(home / ".local" / "bin" / "perf-mbench", KERNEL_BLOB)
    calls, run = _fake_run()
    probe = _discover(
        tmp_path,
        paranoid=0,
        home=home,
        which=lambda name: "/fake/getcap" if name == "getcap" else None,
        run=run,
    )
    assert probe.unavailable is None
    assert [Path(str(c[0])).name for c in calls] == ["perf-mbench"]
    assert calls[0][0] == str(binary)


def test_without_getcap_the_canary_is_the_cap_probe(tmp_path: Path) -> None:
    home = tmp_path / "home"
    binary = _copy(home / ".local" / "bin" / "perf-mbench", KERNEL_BLOB)
    calls, run = _fake_run()  # no getcap on this PATH at all
    probe = _discover(tmp_path, paranoid=4, home=home, run=run)
    assert probe.unavailable is None
    assert calls[0][0] == str(binary)


def test_an_env_override_to_a_missing_file_is_named(tmp_path: Path) -> None:
    calls, run = _fake_run()
    probe = _discover(tmp_path, env={perf.ENV_BINARY: str(tmp_path / "gone")}, run=run)
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "missing_tool"
    assert "gone" in marker["reason"]
    assert calls == []


def test_every_failed_candidate_is_named_in_the_marker(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _copy(home / ".local" / "bin" / "perf-mbench", b"old-perf")
    path_perf = _copy(tmp_path / "bin" / "perf", KERNEL_BLOB)
    calls, run = _fake_run(canary_rc=1, canary_stderr=b"no permission")
    probe = _discover(
        tmp_path,
        paranoid=4,
        home=home,
        which=lambda name: str(path_perf) if name == "perf" else None,
        run=run,
    )
    marker = probe.unavailable
    assert marker is not None and marker["unavailable"] == "needs_root"
    assert "~/.local/bin/perf-mbench" in marker["reason"]
    assert str(path_perf) in marker["reason"]
    # the stale copy is rejected without a subprocess; path perf ran the canary
    canary = [str(path_perf), "stat", "-a", "-e", "cycles", "-x", ",", "--", "sleep", "0.05"]
    assert calls == [canary]


def test_the_second_pmu_reporting_not_counted_is_not_an_error() -> None:
    # ``perf stat -a -C 5`` on the mixed X925/A725 cores: events print under
    # their PMU's name, the PMU owning the pinned core counts, and the other
    # reports <not counted> for the same event — the count survives.
    dual_pmu_csv = (
        "<not counted>,,armv8_pmuv3_0/cycles/,0.00,,,\n"
        "229555794,,armv8_pmuv3_1/cycles/,1001519808,100.00,,\n"
        "<not counted>,,armv8_pmuv3_0/instructions/,0.00,,,\n"
        "271188376,,armv8_pmuv3_1/instructions/,1001518688,100.00,,\n"
    )
    want = {"cycles": 229555794.0, "instructions": 271188376.0}
    assert perf.parse_stat_csv(dual_pmu_csv) == want
    # the <not counted> row order does not matter either way
    reversed_csv = "\n".join(reversed(dual_pmu_csv.strip().splitlines())) + "\n"
    assert perf.parse_stat_csv(reversed_csv) == want


def test_two_pmus_counting_the_same_event_sum() -> None:
    # The cgroup scope counts ``-a`` without a -C filter: both PMUs then
    # count, and the pass's cycles are their sum — not whichever row was last.
    csv = "10,,armv8_pmuv3_0/cycles/,100.00,,,\n25,,armv8_pmuv3_1/cycles/,100.00,,,\n"
    assert perf.parse_stat_csv(csv) == {"cycles": 35.0}


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
        which=lambda name: None,
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
    assert record["binary"] == "/usr/bin/perf"  # the record names the binary used
    assert spawned[0].signals == [signal.SIGINT]  # stopped like a Ctrl-C
    assert not session.out.exists()  # the csv never outlives the pass


def test_the_record_names_the_discovered_binary(tmp_path: Path) -> None:
    home = tmp_path / "home"
    binary = _copy(home / ".local" / "bin" / "perf-mbench", KERNEL_BLOB)
    _spawned_list, spawn = _spawned()
    _run_calls, run = _fake_run(caps={str(binary): "cap_perfmon=ep"})
    probe = _discover(
        tmp_path,
        paranoid=4,
        home=home,
        which=lambda name: "/fake/getcap" if name == "getcap" else None,
        run=run,
        spawn=spawn,
    )
    session = probe.start([5])
    assert session is not None
    session.out.write_text(STAT_CSV, encoding="utf-8")
    record = probe.record(session, 1000)
    assert record["binary"] == "~/.local/bin/perf-mbench"


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
        which=lambda name: None,
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
        binary="/usr/bin/perf",
        paranoid_path=knob,
        which=lambda name: None,
        run=lambda argv: _completed(argv),
    )
    assert probe.start([]) is None
    record = probe.record(None, None)
    assert record["unavailable"] == "not_applicable"


def test_an_unavailable_probe_marks_every_pass(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("4\n", encoding="utf-8")
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        which=lambda name: None,
        run=lambda argv: _completed(argv, 1, b"no permission"),
    )
    record = probe.record(None, 100)
    assert record["unavailable"] == "needs_root"


def test_an_empty_count_file_is_an_error_marker(tmp_path: Path) -> None:
    knob = tmp_path / "perf_event_paranoid"
    knob.write_text("1\n", encoding="utf-8")
    probe = perf.Probe(
        binary="/usr/bin/perf",
        paranoid_path=knob,
        which=lambda name: None,
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
    assert "perf-mbench" in text  # the binary the probe finds second
    assert (
        "install -Dm700 /usr/lib/linux-tools/$(uname -r)/perf ~/.local/bin/perf-mbench" in text
    )  # the exact copy line
    assert "kernel.perf_event_paranoid=0" in text  # option B: the sysctl
    assert "kernel.perf_event_paranoid=4" in text  # the restore value
    assert "never runs these" in text  # the harness only prints them
