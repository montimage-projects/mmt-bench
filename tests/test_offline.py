"""The offline mode (#8): tmpfs discovery, sha256 staging, the measured pass."""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest
from campaignfiles import make_pcap
from fakeadapter import FakeAdapter, FakeProcess

from mbench.adapters.base import Counters, Ruleset
from mbench.modes import offline

MOUNTS = """\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/nvme0n1p2 / ext4 rw,relatime 0 0
tmpfs /run/user/1000 tmpfs rw,nosuid,nodev,relatime 0 0
"""


def test_tmpfs_mounts_prefers_dev_shm() -> None:
    points = offline.tmpfs_mounts(MOUNTS)
    assert points == [Path("/dev/shm"), Path("/run"), Path("/run/user/1000")]


def test_tmpfs_dir_is_none_without_a_tmpfs() -> None:
    mounts = "sysfs /sys sysfs rw 0 0\n/dev/sda / ext4 rw 0 0\n"
    assert offline.tmpfs_dir(mounts) is None


def test_staging_names_the_file_by_its_sha256(tmp_path: Path) -> None:
    capture = make_pcap(tmp_path, "private-name.pcap")
    staged = offline.stage_pcap(capture, "ab" * 32, tmp_path / "staged")
    assert staged.name == "ab" * 32 + ".pcap"
    assert staged.read_bytes() == capture.read_bytes()
    # staging is idempotent
    assert offline.stage_pcap(capture, "ab" * 32, tmp_path / "staged") == staged


def _pass(
    adapter: FakeAdapter,
    tmp_path: Path,
    timeout: float = 5.0,
    expected_packets: int | None = None,
    step: float = 1.0,
) -> offline.Outcome:
    calls = itertools.count()
    return offline.run_pass(
        adapter,
        Ruleset("rs", tmp_path / "rs.so"),
        "recommended",
        tmp_path / "wd",
        tmp_path / "x.pcap",
        1,
        (),
        timeout,
        expected_packets=expected_packets,
        clock=lambda: next(calls) * step,
    )


def test_an_ok_pass_carries_counters_and_alerts(tmp_path: Path) -> None:
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(run_counters=Counters(10, 640, 2))
    outcome = _pass(adapter, tmp_path)
    assert outcome.status == "ok"
    assert outcome.counters == Counters(10, 640, 2)
    assert outcome.wall_s >= 0


def test_a_pass_over_the_timeout_is_killed_and_marked(tmp_path: Path) -> None:
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(duration_s=999.0)
    outcome = _pass(adapter, tmp_path, timeout=0.1)
    assert outcome.status == "timeout"
    assert "killed after" in outcome.detail
    # a timeout never measures: no counters, no alerts
    assert outcome.counters is None and outcome.alerts is None


def test_a_nonzero_exit_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter()
    monkeypatch.setattr(adapter, "run_offline", lambda *a, **k: FakeProcess(returncode=3))
    outcome = _pass(adapter, tmp_path)
    assert outcome.status == "error"
    assert outcome.returncode == 3


@pytest.mark.parametrize(
    "returncode",
    [128 + 11, -11],
    ids=["128-plus-signum", "negative-returncode"],
)
def test_a_signal_death_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    # #42: the fork probe dies by the signal on an offline crash — a shell
    # sees 128 + signum, a Python caller a negative returncode — so a crash
    # is an error pass, never a masked ok.
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter()
    monkeypatch.setattr(adapter, "run_offline", lambda *a, **k: FakeProcess(returncode=returncode))
    outcome = _pass(adapter, tmp_path)
    assert outcome.status == "error"
    assert outcome.returncode == returncode


def test_a_crashing_start_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter()

    def boom(*a: object, **k: object) -> FakeProcess:
        raise RuntimeError("docker daemon gone")

    monkeypatch.setattr(adapter, "run_offline", boom)
    outcome = _pass(adapter, tmp_path)
    assert outcome.status == "error"
    assert "docker daemon gone" in outcome.detail


def test_an_error_from_wait_kills_the_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A RuntimeError out of wait() returns an error pass — and the tool is
    # dead: for Docker the container, not only the client (review B2).
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    handle = FakeProcess()
    adapter = FakeAdapter()
    monkeypatch.setattr(adapter, "run_offline", lambda *a, **k: handle)

    def boom(timeout: float | None = None) -> int:
        raise RuntimeError("daemon gone")

    monkeypatch.setattr(handle, "wait", boom)
    outcome = _pass(adapter, tmp_path)
    assert outcome.status == "error"
    assert "daemon gone" in outcome.detail
    assert handle.killed


def test_a_keyboardinterrupt_kills_the_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Ctrl-C escapes wait(): the pass propagates it — after killing the tool
    # (review B2: a BaseException never leaves the container running).
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    handle = FakeProcess()
    adapter = FakeAdapter()
    monkeypatch.setattr(adapter, "run_offline", lambda *a, **k: handle)

    def ctrl_c(timeout: float | None = None) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(handle, "wait", ctrl_c)
    with pytest.raises(KeyboardInterrupt):
        _pass(adapter, tmp_path)
    assert handle.killed


def test_a_keyboardinterrupt_in_run_offline_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A Ctrl-C while the tool starts leaves no handle behind to kill.
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter()

    def ctrl_c(*a: object, **k: object) -> FakeProcess:
        raise KeyboardInterrupt

    monkeypatch.setattr(adapter, "run_offline", ctrl_c)
    with pytest.raises(KeyboardInterrupt):
        _pass(adapter, tmp_path)


def test_prepare_must_have_run_first(tmp_path: Path) -> None:
    # run_pass prepares itself; a bare run_offline refuses (the fake enforces
    # the adapter contract)
    adapter = FakeAdapter()
    with pytest.raises(RuntimeError, match="prepare"):
        adapter.run_offline(tmp_path / "x.pcap", 1, ())


# --- the pass's integrity and timing (review B2/B3) ----------------------------


def test_a_clean_pass_on_the_tool_interval_is_the_tool_basis(tmp_path: Path) -> None:
    # B3: the rates prefer the tool's own processing interval when it sits
    # inside the wall window; overhead is init + teardown.
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(
        run_counters=Counters(10, 640, 0, {"processing_s": 0.5, "abnormal_exit": False})
    )
    outcome = _pass(adapter, tmp_path)
    assert outcome.status == "ok"
    assert outcome.timing == {
        "wall_s": 1.0,
        "processing_s": 0.5,
        "basis": "tool",
        "overhead_s": 0.5,
    }


def test_no_tool_interval_falls_back_to_wall_labelled(tmp_path: Path) -> None:
    # B3: a tool that reports no processing interval is measured on wall
    # time — the record says so, never silently.
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(run_counters=Counters(10, 640, 0))
    outcome = _pass(adapter, tmp_path)
    assert outcome.status == "ok"
    assert outcome.timing == {"wall_s": 1.0, "processing_s": None, "basis": "wall"}


def test_a_tool_interval_outside_the_wall_window_is_invalid(tmp_path: Path) -> None:
    # B3's cross-check: a processing interval that cannot fit in the window
    # that produced it is not a measurement.
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(run_counters=Counters(10, 640, 0, {"processing_s": 9.0}))
    outcome = _pass(adapter, tmp_path)
    assert outcome.status == "invalid"
    assert "processing interval" in outcome.detail


def test_an_abnormal_exit_is_never_an_ok_pass(tmp_path: Path) -> None:
    # B2: the tool's signal handler can mask an abort as return code 0 —
    # its own output decides, and an abort is never a measurement.
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(
        run_counters=Counters(
            10,
            640,
            None,
            {"abnormal_exit": True, "exit_detail": "malloc(): unaligned tcache chunk"},
        )
    )
    outcome = _pass(adapter, tmp_path)
    assert outcome.status == "invalid"
    assert "abnormally" in outcome.detail


def test_a_packet_count_mismatch_is_invalid(tmp_path: Path) -> None:
    # B2: the corpus manifest's packet count is the ground truth the
    # tool-counted packets answer to.
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(run_counters=Counters(199, 640, 0))
    outcome = _pass(adapter, tmp_path, expected_packets=200)
    assert outcome.status == "invalid"
    assert "199" in outcome.detail and "200" in outcome.detail
    assert outcome.expected_packets == 200


def test_the_matching_packet_count_stays_ok(tmp_path: Path) -> None:
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(run_counters=Counters(200, 640, 0))
    outcome = _pass(adapter, tmp_path, expected_packets=200)
    assert outcome.status == "ok"


def test_a_report_shorter_than_the_pass_is_invalid(tmp_path: Path) -> None:
    # B2's residual gap (re-review): the status lines keep the pass's
    # packet count whole while the reports were cut mid-record — the
    # report's own sums answer to the pass total.
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(
        run_counters=Counters(
            1_000_000,
            64_000_000,
            0,
            {"report_packets": 901_281, "report_bytes": 57_681_984, "status_lines": 2},
        )
    )
    outcome = _pass(adapter, tmp_path, expected_packets=1_000_000)
    assert outcome.status == "invalid"
    assert "901281" in outcome.detail and "1000000" in outcome.detail


def test_a_zero_byte_report_for_packets_is_invalid(tmp_path: Path) -> None:
    # A report truncated before any volume row: 0 bytes for a pass that
    # counted packets is a broken report, never an ok measurement.
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(
        run_counters=Counters(
            1_000_000, 0, 0, {"report_packets": 0, "report_bytes": 0, "status_lines": 2}
        )
    )
    outcome = _pass(adapter, tmp_path, expected_packets=1_000_000)
    assert outcome.status == "invalid"
    assert "0 bytes for 1000000 packets" in outcome.detail


def test_consistent_report_sums_stay_ok(tmp_path: Path) -> None:
    (tmp_path / "rs.so").write_bytes(b"rules")
    make_pcap(tmp_path, "x.pcap")
    adapter = FakeAdapter(
        run_counters=Counters(
            1_000_000,
            64_000_000,
            0,
            {"report_packets": 1_000_000, "report_bytes": 64_000_000, "status_lines": 2},
        )
    )
    outcome = _pass(adapter, tmp_path, expected_packets=1_000_000)
    assert outcome.status == "ok"
