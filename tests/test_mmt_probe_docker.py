"""The mmt-probe adapter (#6) against the real image — the Docker-marked
integration test.

It is skipped wherever docker is not usable (CI). The image is the one built
by ``tools/docker/mmt-probe/``; when the tag is absent the test builds it.
The check pcaps, their ``check/expect`` files and the rule set all come from
the image itself (``/opt/mmt/check``), pinned by the mmt-security commit the
image is built from, so the test needs nothing from the host but docker.

Each case runs the adapter on one check pcap and requires the probe's
alerts, ``mmt_sec_standalone``'s alerts and the expect rows to agree, then
scores the alerts against the expect-derived ground truth.
"""

from __future__ import annotations

import json
import re
import secrets
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path

import pytest

from mbench import corpus, pcap, truth
from mbench.adapters.base import ImageRef, Ruleset, tools_record_errors
from mbench.adapters.mmt_probe import (
    CONTAINER_PREFIX,
    CliDocker,
    MmtProbeAdapter,
    _pick_protocol,
)

#: The check cases: pcap inside the image, its expect file, the pcap's
#: pinned sha256 and how many alerts mmt-security says it raises. The
#: ``ignore-remain-flow = false`` config reports every verdict, so probe,
#: standalone and expect agree on the scan pcaps too (review F1).
CHECK_CASES = [
    (
        "14.illegal_port.pcap",
        "14.illegal_port.csv",
        "4ae1e5aa7911aa66ba7a3e754f3ae7a60a50c766cf4ab646eb09e6aba940349a",
        1,
    ),
    (
        "27.udp_scan.pcap",
        "27.udp_scan.csv",
        "a6825bbe1ad6c6a9e71352cc8ad4256990e375ee7320eb99f2da3e6c02f32624",
        4,
    ),
    (
        "26.protocal_scan.pcap",
        "26.protocal_scan.csv",
        "0a92d6fb6b6a8849d679f6d1bca7aad55e473ec888665df6e414abc706d325b4",
        6,
    ),
]

IMAGE = "mmt-bench/mmt-probe:local"

#: The run containers' name prefix — the one "no container left" checks
#: filter on, so a long-lived ``mbench-capture-*`` container elsewhere on
#: the host cannot turn the suite red.
RUN_PREFIX = f"{CONTAINER_PREFIX}mmt-probe-run-"


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
    assert isinstance(adapter.image, ImageRef), "the adapter image must resolve to a digest"
    return adapter._run_image()


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


def _expect_attacks(expect_path: Path, proto_of: Mapping[str, str]) -> list[dict[str, object]]:
    """A ``check/expect`` file's rows as ground-truth attacks.

    Each line is one expected alert; ``ts``/endpoints come from its trace's
    events. ``proto`` is the flow's protocol, taken from the rule's own
    protocol list — the same source as the adapter's ``Alert.proto``
    (docs/methodology.md), never the trace's first attribute namespace
    (``ip.proto_id`` would wrongly say ``ip`` on a UDP scan). A row whose
    rule is not in the inventory omits ``proto``, which truth.py allows.
    """
    attacks = []
    for i, line in enumerate(expect_path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        row = line.split(",", 8)
        if len(row) < 9:
            continue
        trace = json.loads(row[8])
        events = [
            trace[k]
            for k in sorted(
                (k for k in trace if k.startswith("event_")),
                key=lambda k: int(k.rsplit("_", 1)[1]),
            )
        ]
        atts = [a for e in events for a in e.get("attributes", [])]
        src = next((v for k, v in atts if k in ("ip.src", "arp.ar_sip")), None)
        dst = next((v for k, v in atts if k in ("ip.dst", "arp.ar_tip")), None)
        assert src and dst, f"expect row {i}: no endpoints"
        attack = {
            "id": f"expect-{i}-rule-{row[4]}",
            "start": events[-1]["timestamp"] - 1,
            "end": events[-1]["timestamp"] + 1,
            "src": src,
            "dst": dst,
            "rule_ids": {"mmt-probe": [row[4]]},
        }
        if row[4] in proto_of:
            attack["proto"] = proto_of[row[4]]
        attacks.append(attack)
    return attacks


def _standalone_alerts(adapter: MmtProbeAdapter, dest: Path, pcap_name: str) -> int:
    """How many alerts ``mmt_sec_standalone`` raises on the same pcap."""
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
            f"{dest.resolve()}:/data",
            _run_ref(adapter),
            "mmt_sec_standalone",
            "-t",
            f"/data/{pcap_name}",
            "-f",
            "/data/",
        ],
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    standalone = sorted(dest.glob("mmt-security-*.csv"))
    assert standalone, "mmt_sec_standalone produced no CSV"
    return sum(
        1 for line in standalone[-1].read_text(encoding="utf-8").splitlines() if line.strip()
    )


@needs_docker
@pytest.mark.parametrize(("pcap_name", "expect_name", "pcap_sha256", "expect_alerts"), CHECK_CASES)
def test_offline_run_on_the_check_pcap(
    adapter: MmtProbeAdapter,
    tmp_path: Path,
    pcap_name: str,
    expect_name: str,
    pcap_sha256: str,
    expect_alerts: int,
) -> None:
    # Inputs extracted from the image: the pcap, its expect file, the rules.
    pcap_path = _extract(adapter, pcap_name, f"/opt/mmt/check/pcap/{pcap_name}", tmp_path)
    expect_path = _extract(adapter, expect_name, f"/opt/mmt/check/expect/{expect_name}", tmp_path)
    rules_dir = _extract(adapter, "mmt-rules", "/opt/mmt/security/rules", tmp_path)

    # The pcap is the pinned one.
    stats = pcap.stats(pcap_path)
    assert stats.sha256 == pcap_sha256

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

    # Ground truth from check/expect. `proto` is the flow's protocol from
    # the rule's protocol list — the same convention the adapter follows
    # (review F2), so a UDP scan is udp, not the first condition's `ip`.
    proto_of = {r.id: _pick_protocol(r.protocols) for r in adapter.rule_inventory(ruleset)}
    attacks = _expect_attacks(expect_path, proto_of)
    assert len(attacks) == expect_alerts
    gt = truth.parse(
        {
            "schema_version": 1,
            "pcap_sha256": stats.sha256,
            "tolerance_s": 1.0,
            "attacks": attacks,
        }
    )
    # The alerts, normalised: every expected detection is reported and
    # nothing else fires.
    alerts = adapter.alerts()
    result = truth.score(alerts, gt, tool=adapter.name)
    assert result.missed == [], f"missed attacks: {result.missed}"
    assert (result.tp, result.fn, result.fp) == (expect_alerts, 0, 0)

    # The probe and the standalone engine see the same attacks on this pcap.
    assert len(alerts) == _standalone_alerts(adapter, tmp_path, pcap_name)

    # The record of the tool under test validates.
    assert tools_record_errors(adapter.tools_record()) == []

    # No run container is left running.
    left = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name={RUN_PREFIX}"],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    assert left == "", f"run containers left running: {left}"


@needs_docker
@pytest.mark.parametrize(("pcap_name", "pcap_sha256"), [(c[0], c[2]) for c in CHECK_CASES])
def test_the_pcap_sha_pin_is_the_recorded_one(
    adapter: MmtProbeAdapter, tmp_path: Path, pcap_name: str, pcap_sha256: str
) -> None:
    """The pcap the test runs on is pinned by sha256 — it cannot drift."""
    pcap_path = _extract(adapter, pcap_name, f"/opt/mmt/check/pcap/{pcap_name}", tmp_path)
    assert pcap.sha256_file(pcap_path) == pcap_sha256
    assert re.fullmatch(r"[0-9a-f]{64}", pcap_sha256)


@needs_docker
@pytest.mark.parametrize("threads", [1, 2])
def test_snap_len_zero_processes_every_1500b_packet(
    adapter: MmtProbeAdapter, tmp_path: Path, threads: int
) -> None:
    """#42 / fork #3: ``snap-len = 0`` no longer overflows the worker ring.

    Upstream sized the pcap SMP ring elements by ``snap-len`` while packets
    were copied by ``caplen``, so a 1500-B frame at ``snap-len = 0`` crashed
    or starved the worker path (review B1). On the fork build a C-large
    capture must be counted whole at ``thread-nb`` 1 and 2 — the config the
    adapter writes still says 65535, so the test overrides it back to 0.
    """
    pcap_path = tmp_path / "large.pcap"
    corpus.generate(corpus.SETS["c-large"], 0, 2000, 8, pcap_path)
    stats = pcap.stats(pcap_path)
    # The R0-style ruleset: with the engine off there is nothing to stage,
    # so the run exercises only the pcap worker path the bug lived in.
    empty_rules = tmp_path / "no-rules"
    empty_rules.mkdir()
    workdir = tmp_path / "work"
    adapter.prepare(
        Ruleset("r0-like", empty_rules, security=False, allow_empty=True),
        "recommended",
        workdir,
    )
    conf = workdir / "mmt-probe.conf"
    text = conf.read_text(encoding="utf-8")
    assert "snap-len    = 65535" in text
    conf.write_text(text.replace("snap-len    = 65535", "snap-len    = 0"), encoding="utf-8")

    handle = adapter.run_offline(pcap_path, threads=threads, cpuset=[])
    assert handle.wait(timeout=120) == 0

    counters = adapter.counters()
    assert counters.packets == stats.packets
    assert counters.extra["exit_state"] == "clean"
    assert counters.extra["abnormal_exit"] is False


def _wait_for_marker(path: Path, needle: str, timeout_s: float) -> bool:
    """Whether ``needle`` appears in ``path`` within ``timeout_s`` seconds."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if needle in path.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            pass
        time.sleep(0.2)
    return False


@needs_docker
def test_a_crashed_probe_is_never_an_ok_pass(adapter: MmtProbeAdapter, tmp_path: Path) -> None:
    """#42 / fork #4: an offline crash dies by the signal (128 + signum).

    A ``docker kill -SEGV`` on the running probe gives the docker client a
    non-zero exit, so the pass is ``error``; the probe's handler still logs
    ``crash signal received`` before re-raising, so the log markers keep
    the run abnormal as a backstop — never an ``ok`` measurement.
    """
    # A capture big enough that the packet loop lives tens of seconds, so
    # the signal lands mid-run — the same size the signal tests use.
    pcap_path = tmp_path / "big.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 750_000, 256, pcap_path)
    rules_dir = _extract(adapter, "mmt-rules", "/opt/mmt/security/rules", tmp_path)
    workdir = tmp_path / "work"
    adapter.prepare(Ruleset("mmt-security", rules_dir), "recommended", workdir)

    handle = adapter.run_offline(pcap_path, threads=0, cpuset=[])
    run = adapter._run
    assert run is not None
    # Kill once the probe is inside the packet loop — its signal handlers
    # are installed by then, and the run cannot have ended at this size.
    assert _wait_for_marker(run.log_path, "Starting PCAP mode", 300), (
        "the probe never reached the packet loop"
    )
    killed = subprocess.run(
        ["docker", "kill", "--signal=SIGSEGV", run.container_name],
        capture_output=True,
        timeout=30,
    )
    assert killed.returncode == 0, killed.stderr.decode("utf-8", "replace")

    # A real signal death: 128 + SIGSEGV, not a masked exit 0.
    assert handle.wait(timeout=180) == 128 + signal.SIGSEGV

    log = run.log_path.read_text(encoding="utf-8", errors="replace")
    assert "crash signal received" in log
    assert "Exit normally MMT-Probe" not in log
    try:
        counters = adapter.counters()
    except RuntimeError:
        return  # no reports at all: an error pass, still never ok
    assert counters.extra["abnormal_exit"] is True
    assert counters.extra["exit_state"] == "abnormal"
