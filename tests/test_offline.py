"""The offline mode (#8): tmpfs discovery, sha256 staging, the measured pass."""

from __future__ import annotations

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


def _pass(adapter: FakeAdapter, tmp_path: Path, timeout: float = 5.0) -> offline.Outcome:
    return offline.run_pass(
        adapter,
        Ruleset("rs", tmp_path / "rs.so"),
        "recommended",
        tmp_path / "wd",
        tmp_path / "x.pcap",
        1,
        (),
        timeout,
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
