"""``mbench sut`` on the host running the tests (dgx-spark, or a CI runner).

These tests only read the host, as ``mbench sut`` always does. They check that
the collector produces a record that validates wherever it runs, which is what
lets CI catch a host the parsers do not handle.

A host with no physical NIC (a plain container, whose only interface is a veth)
gets ``--nic`` with that veth, so the record still describes a NIC; the marker
recorded without ``--nic`` has its own test.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from mbench import hostsrc, sut, validate
from mbench.cli import EXIT_INVALID, EXIT_OK, EXIT_USAGE, main

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mbench sut reads Linux /proc and /sys"
)

NET = "/sys/class/net"


def interfaces() -> list[str]:
    try:
        return sorted(os.listdir(NET))
    except OSError:
        return []


def physical_nics() -> list[str]:
    """The interfaces ``mbench sut`` always records: those with a device."""
    return [n for n in interfaces() if os.path.lexists(f"{NET}/{n}/device")]


def nic_args() -> list[str]:
    """``--nic VETH`` on a host with no physical NIC, else nothing."""
    if physical_nics():
        return []
    virtual = [n for n in interfaces() if n != "lo"] or interfaces()
    return ["--nic", virtual[0]] if virtual else []


FAST = ["--sample-seconds", "0.05", "--top", "3", *nic_args()]


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def test_sut_writes_a_record_that_validates(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "sut.json"
    assert main(["sut", "-o", str(out), *FAST]) == EXIT_OK
    err = capsys.readouterr().err
    assert f"mbench sut: wrote {out}: scope host" in err
    record = load(out)
    assert validate.sut_errors(record) == [], json.dumps(record, indent=1)[:4000]
    assert main(["validate", str(out)]) == EXIT_OK
    for path, kind, reason in sut.unavailable_fields(record):
        assert kind in sut.UNAVAILABLE_KINDS and reason, path
        assert f"{path}: {reason}" in err  # every marker is reported on stderr


def test_sut_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["sut", *FAST]) == EXIT_OK
    record = json.loads(capsys.readouterr().out)
    assert record["scope"] == "host"


def test_sut_anonymise(tmp_path: Path) -> None:
    out = tmp_path / "sut.json"
    assert main(["sut", "--anonymise", "-o", str(out), *FAST]) == EXIT_OK
    assert load(out)["host"]["hostname"] == "sut"
    assert main(["sut", "--anonymise", "bench-1", "-o", str(out), *FAST]) == EXIT_OK
    host = load(out)["host"]
    assert (host["hostname"], host["hostname_anonymised"]) == ("bench-1", True)


def test_sut_record_sources_replays(tmp_path: Path) -> None:
    out, snap = tmp_path / "sut.json", tmp_path / "sources.json"
    argv = ["sut", "--anonymise", "ci", "--record-sources", str(snap), "-o", str(out), *FAST]
    assert main(argv) == EXIT_OK
    live = load(out)
    nics = nic_args()[1:]
    replayed = sut.collect(
        hostsrc.SnapshotSource.load(snap), sut.Options(alias="ci", top_n=3, extra_nics=nics)
    )
    assert validate.sut_errors(replayed) == []
    assert replayed["nics"] == live["nics"]
    # The checkout's path (asked of git for the commit) is not in the recording.
    text = snap.read_text(encoding="utf-8")
    assert str(Path(sut.__file__).resolve().parent.parent) not in text
    assert '"git"' not in text
    assert replayed["host"]["cpu"]["core_types"] == live["host"]["cpu"]["core_types"]


def test_sut_rejects_bad_options(tmp_path: Path) -> None:
    assert main(["sut", "--sample-seconds", "0", "-o", str(tmp_path / "x")]) == EXIT_USAGE
    assert main(["sut", "--nic", "no-such-iface0", "-o", str(tmp_path / "x"), *FAST]) == EXIT_USAGE
    assert not (tmp_path / "x").exists()


@pytest.mark.skipif(bool(physical_nics()), reason="this host has a physical NIC")
def test_sut_without_a_physical_nic_records_a_marker(tmp_path: Path) -> None:
    out = tmp_path / "sut.json"
    fast = ["--sample-seconds", "0.05", "--top", "3"]
    assert main(["sut", "-o", str(out), *fast]) == EXIT_OK
    record = load(out)
    assert sut.is_unavailable(record["nics"]) and "--nic" in record["nics"]["reason"]
    assert main(["validate", str(out)]) == EXIT_OK


def test_sut_exits_1_when_its_own_record_does_not_validate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sutfixtures import GOLDEN

    broken = load(GOLDEN)
    broken["nics"] = []  # what 6ed2ddb wrote on a host with no physical NIC
    monkeypatch.setattr(sut, "collect", lambda source, options: broken)
    out = tmp_path / "sut.json"
    assert main(["sut", "-o", str(out)]) == EXIT_INVALID
    err = capsys.readouterr().err
    assert "mbench sut: the record is INVALID" in err
    assert "nics: [] should be non-empty" in err
