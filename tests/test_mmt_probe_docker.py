"""The mmt-probe adapter (#6) against the real image — the Docker-marked
integration test.

It is skipped wherever docker is not usable (CI). The image is the one built
by ``tools/docker/mmt-probe/``; when the tag is absent the test builds it.
The check pcap, its ``check/expect`` file and the rule set all come from the
image itself (``/opt/mmt/check``), pinned by the mmt-security commit the
image is built from, so the test needs nothing from the host but docker.
"""

from __future__ import annotations

import json
import re
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest

from mbench import pcap, truth
from mbench.adapters.base import ImageRef, Ruleset, tools_record_errors
from mbench.adapters.mmt_probe import CliDocker, MmtProbeAdapter

#: The check case: pcap inside the image, its expected sha256, and what
#: mmt-security's check/expect says it must raise (one rule-13 alert).
CHECK_PCAP = "14.illegal_port.pcap"
CHECK_EXPECT = "14.illegal_port.csv"
CHECK_PCAP_SHA256 = "4ae1e5aa7911aa66ba7a3e754f3ae7a60a50c766cf4ab646eb09e6aba940349a"

IMAGE = "mmt-bench/mmt-probe:local"


def _docker_usable() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.docker

needs_docker = pytest.mark.skipif(not _docker_usable(), reason="docker is not usable")


@pytest.fixture(scope="module")
def adapter() -> MmtProbeAdapter:
    """The adapter on the built image, pinned by the daemon's image id.

    Builds the image first when the tag is absent.
    """
    docker = CliDocker()
    try:
        return MmtProbeAdapter(IMAGE, docker=docker)
    except Exception:
        MmtProbeAdapter.build(IMAGE, docker=docker)
        return MmtProbeAdapter(IMAGE, docker=docker)


def _run_ref(adapter: MmtProbeAdapter) -> str:
    ref = adapter.image
    assert isinstance(ref, ImageRef), "the adapter image must be resolvable to a digest"
    return ref.ref


def _extract(adapter: MmtProbeAdapter, name: str, image_path: str, dest: Path) -> Path:
    """Copy ``image_path`` out of the image into ``dest`` (an mbench- container)."""
    out = dest / name
    proc = adapter.docker.run(
        [
            "run",
            "--rm",
            "--name",
            f"mbench-mmt-probe-extract-{secrets.token_hex(4)}",
            "--network",
            "none",
            "-w",
            "/",
            "-v",
            f"{dest.resolve()}:/data",
            _run_ref(adapter),
            "cp",
            "-r",
            image_path,
            f"/data/{name}",
        ],
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return out


@needs_docker
def test_offline_run_on_the_check_pcap(adapter: MmtProbeAdapter, tmp_path: Path) -> None:
    # Inputs extracted from the image: the pcap, its expect file, the rules.
    pcap_path = _extract(adapter, CHECK_PCAP, f"/opt/mmt/check/pcap/{CHECK_PCAP}", tmp_path)
    expect_path = _extract(adapter, CHECK_EXPECT, f"/opt/mmt/check/expect/{CHECK_EXPECT}", tmp_path)
    rules_dir = _extract(adapter, "mmt-rules", "/opt/mmt/security/rules", tmp_path)

    # The pcap is the pinned one.
    stats = pcap.stats(pcap_path)
    assert stats.sha256 == CHECK_PCAP_SHA256

    ruleset = Ruleset("mmt-security-v1.2.20", rules_dir)
    files = adapter.prepare(ruleset, "recommended", tmp_path / "work")
    assert (tmp_path / "work" / "mmt-probe.conf") in files

    handle = adapter.run_offline(pcap_path, threads=0, cpuset=[])
    assert handle.wait(timeout=120) == 0

    # Counters equal the pcap's packet count and wire size.
    counters = adapter.counters()
    assert counters.packets == stats.packets
    assert counters.bytes == stats.wire_bytes
    assert counters.drops == 0

    # The alerts, normalised.
    alerts = adapter.alerts()
    assert len(alerts) >= 1

    # Ground truth from check/expect: each line is an expected alert;
    # ts/endpoints/proto come from its trace's last event.
    attacks = []
    for i, line in enumerate(expect_path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        row = line.split(",", 8)
        if len(row) < 9:
            continue
        trace = json.loads(row[8])
        events = [trace[k] for k in sorted(trace) if k.startswith("event_")]
        atts = [a for e in events for a in e.get("attributes", [])]
        src = next((v for k, v in atts if k in ("ip.src", "arp.ar_sip")), None)
        dst = next((v for k, v in atts if k in ("ip.dst", "arp.ar_tip")), None)
        assert src and dst, f"expect row {i}: no endpoints"
        attacks.append(
            {
                "id": f"expect-{i}-rule-{row[4]}",
                "start": events[-1]["timestamp"] - 1,
                "end": events[-1]["timestamp"] + 1,
                "src": src,
                "dst": dst,
                "proto": atts[0][0].split(".", 1)[0],
                "rule_ids": {"mmt-probe": [row[4]]},
            }
        )
    gt = truth.parse(
        {
            "schema_version": 1,
            "pcap_sha256": stats.sha256,
            "tolerance_s": 1.0,
            "attacks": attacks,
        }
    )
    result = truth.score(alerts, gt, tool=adapter.name)
    # Every expected detection is reported (no missed attack).
    assert result.fn == 0, f"missed attacks: {result.missed}"
    assert result.tp == len(attacks)

    # mmt_sec_standalone on the same pcap, for the alert-count comparison.
    proc = adapter.docker.run(
        [
            "run",
            "--rm",
            "--name",
            f"mbench-mmt-probe-standalone-{secrets.token_hex(4)}",
            "--network",
            "none",
            "-w",
            "/",
            "-v",
            f"{tmp_path.resolve()}:/data",
            _run_ref(adapter),
            "mmt_sec_standalone",
            "-t",
            f"/data/{CHECK_PCAP}",
            "-f",
            "/data/",
        ],
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    standalone = sorted(tmp_path.glob("mmt-security-*.csv"))
    assert standalone, "mmt_sec_standalone produced no CSV"
    standalone_alerts = sum(
        1 for line in standalone[-1].read_text(encoding="utf-8").splitlines() if line.strip()
    )
    # The probe and the standalone engine see the same attacks on this pcap.
    assert len(alerts) == standalone_alerts == len(attacks)

    # The record of the tool under test validates.
    assert tools_record_errors(adapter.tools_record()) == []

    # No mbench- container is left running.
    left = subprocess.run(
        ["docker", "ps", "-q", "--filter", "name=mbench-"],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    assert left == "", f"mbench containers left running: {left}"


@needs_docker
def test_the_pcap_sha_pin_is_the_recorded_one(adapter: MmtProbeAdapter, tmp_path: Path) -> None:
    """The pcap the test runs on is pinned by sha256 — it cannot drift."""
    pcap_path = _extract(adapter, CHECK_PCAP, f"/opt/mmt/check/pcap/{CHECK_PCAP}", tmp_path)
    assert pcap.sha256_file(pcap_path) == CHECK_PCAP_SHA256
    assert re.fullmatch(r"[0-9a-f]{64}", CHECK_PCAP_SHA256)
