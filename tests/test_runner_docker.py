"""The runner (#8) end to end with the real mmt-probe adapter — the
Docker-marked integration test.

One tiny campaign cell (one check pcap, one warm-up + one measured pass)
goes through ``runner.run_campaign`` exactly as ``mbench run`` drives it.
The pcap is the mmt-security check capture ``14.illegal_port.pcap``: read
from the local checkout ``~/workspace/mmt/mmt-security-fork/check/pcap``
when it is present, else copied out of the image (the same file, pinned by
sha256 either way). The rules come out of the image.

Skipped wherever docker is not usable (CI).
"""

from __future__ import annotations

import json
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml
from sutfixtures import replay
from test_mmt_probe_docker import _docker_usable, _extract

from mbench import corpus, matrix, pcap, runner, validate
from mbench.adapters.base import Ruleset
from mbench.adapters.mmt_probe import CliDocker, MmtProbeAdapter

pytestmark = pytest.mark.docker
needs_docker = pytest.mark.skipif(not _docker_usable(), reason="docker is not usable")

IMAGE = "mmt-bench/mmt-probe:local"


@pytest.fixture(scope="module")
def adapter() -> MmtProbeAdapter:
    """The adapter on the built image (built first when the tag is absent)."""
    docker = CliDocker()
    try:
        return MmtProbeAdapter(IMAGE, docker=docker)
    except Exception:
        MmtProbeAdapter.build(IMAGE, docker=docker)
        return MmtProbeAdapter(IMAGE, docker=docker)


#: The check pcap: the local private checkout first, the image copy else.
CHECKOUT_PCAP = Path.home() / "workspace/mmt/mmt-security-fork/check/pcap/14.illegal_port.pcap"
IMAGE_PCAP = "/opt/mmt/check/pcap/14.illegal_port.pcap"
PCAP_SHA256 = "4ae1e5aa7911aa66ba7a3e754f3ae7a60a50c766cf4ab646eb09e6aba940349a"


def _check_pcap(adapter: MmtProbeAdapter, tmp_path: Path) -> Path:
    if CHECKOUT_PCAP.is_file():
        return CHECKOUT_PCAP
    return _extract(adapter, "14.illegal_port.pcap", IMAGE_PCAP, tmp_path)


@needs_docker
def test_a_tiny_campaign_runs_end_to_end(adapter: MmtProbeAdapter, tmp_path: Path) -> None:
    pcap_path = _check_pcap(adapter, tmp_path)
    assert pcap.sha256_file(pcap_path) == PCAP_SHA256
    stats = pcap.stats(pcap_path)
    rules_dir = _extract(adapter, "mmt-rules", "/opt/mmt/security/rules", tmp_path)

    cell = matrix.Cell(
        index=0,
        tool="mmt-probe",
        ruleset=Ruleset("mmt-security", rules_dir),
        config_profile="recommended",
        corpus=matrix.CorpusRef(
            label="check-14-illegal-port",
            path=pcap_path,
            sha256=PCAP_SHA256,
            truth=None,
            ref={
                "label": "check-14-illegal-port",
                "sha256": PCAP_SHA256,
                "local_only": True,
            },
        ),
        threads=0,
        cpuset=(),
        cpuset_str="",
    )
    campaign = matrix.Campaign(
        name="integration",
        question="does the harness run a real tool end to end?",
        description="",
        mode="offline",
        quiet_host=False,
        repeats=1,
        timeout_s=300,
        path=tmp_path / "campaigns" / "integration.yaml",
        cells=(cell,),
    )

    outcome = runner.run_campaign(
        campaign,
        results_dir=tmp_path / "results",
        collect=replay,
    )

    # One run file, one REPORT.md, one sut.json; the run measured.
    assert outcome.valid == 1
    record = json.loads(outcome.run_files[0].read_text(encoding="utf-8"))
    assert record["status"] == "ok"
    passes = record["passes"]
    assert [p["kind"] for p in passes] == ["warmup", "measured"]
    measured = passes[1]
    assert measured["status"] == "ok"
    assert measured["packets"] == stats.packets
    # a handful of packets is ~0 Gbit/s once rounded: the fields exist and are
    # non-negative, the packet count is the real check
    assert measured["gbps"] is not None and measured["gbps"] >= 0
    assert measured["mpps"] is not None and measured["mpps"] >= 0
    assert measured["wall_s"] > 0

    # The embedded run-scope SUT validates, and the run file itself checks.
    assert validate.sut_errors(record["sut"]) == []
    assert validate.sut_errors(record["sut"]) == validate.validate_file(outcome.run_files[0]).errors

    # The corpus reference names the capture by label and sha256 only.
    assert record["cell"]["corpus"]["label"] == "check-14-illegal-port"
    assert str(pcap_path) not in outcome.run_files[0].read_text(encoding="utf-8")
    assert "REPORT.md" in outcome.report_file.name  # type: ignore[union-attr]

    # The private checkout path never reaches any result file.
    for result in outcome.directory.rglob("*"):
        if result.is_file():
            assert "mmt-security-fork" not in result.read_text(encoding="utf-8", errors="replace")

    # No mbench- container is left running.
    left = subprocess.run(
        ["docker", "ps", "-q", "--filter", "name=mbench-"],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    assert left == "", f"mbench containers left running: {left}"


def _mbench_containers(name: str = "mbench-") -> str:
    """Every running container id whose name matches ``name``, or ""."""
    return subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name={name}"],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()


@needs_docker
def test_sigint_during_a_pass_leaves_no_container(adapter: MmtProbeAdapter, tmp_path: Path) -> None:
    """Ctrl-C mid-pass kills the run container (review B2).

    ``mbench run`` is spawned for real over a generated capture big enough
    that the measured pass lives tens of seconds; once the pass's
    ``mbench-mmt-probe-run-*`` container is up it gets SIGINT. The
    interrupted cell must still be recorded and no ``mbench-`` container
    may remain.
    """
    rules_dir = _extract(adapter, "mmt-rules", "/opt/mmt/security/rules", tmp_path)

    # A minimal campaign, resolved by its own anchor.
    root = tmp_path / "proj"
    (root / "campaigns").mkdir(parents=True)
    shutil.copytree(rules_dir, root / "rules")
    big = root / "big.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 750_000, 256, big)
    campaign = root / "campaigns" / "sigint.yaml"
    campaign.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "question": "does a Ctrl-C kill the run container?",
                "tools": ["mmt-probe"],
                "rulesets": [{"id": "mmt-security", "path": "rules"}],
                "corpus": [{"path": "big.pcap", "sha256": pcap.sha256_file(big)}],
                "threads": [0],
                "cpusets": [""],
                "repeats": 1,
                "timeout_s": 300,
            }
        ),
        encoding="utf-8",
    )
    results = tmp_path / "results"
    proc = subprocess.Popen(
        [sys.executable, "-m", "mbench", "run", str(campaign), "--results", str(results)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    seen_container = False
    try:
        # Wait for the pass's run container to come up, then Ctrl-C.
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline and proc.poll() is None:
            if _mbench_containers("mbench-mmt-probe-run-"):
                seen_container = True
                break
            time.sleep(0.2)
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=120)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
    assert proc.stderr is not None
    stderr = proc.stderr.read().decode()
    assert seen_container, f"the run container never came up; mbench stderr: {stderr}"

    # The pass was interrupted -> its run record is written, the report is
    # rendered over it, and no mbench- container is left running.
    run_files = sorted(results.rglob("runs/*.json"))
    assert run_files, f"no run file; mbench stderr: {stderr}"
    statuses = {json.loads(p.read_text(encoding="utf-8"))["status"] for p in run_files}
    assert "interrupted" in statuses
    assert list(results.rglob("REPORT*.md")), "no REPORT.md after a Ctrl-C"
    # docker kill is synchronous; a short grace covers the daemon's --rm sweep.
    left = _mbench_containers()
    for _ in range(50):
        if not left:
            break
        time.sleep(0.2)
        left = _mbench_containers()
    assert left == "", f"mbench containers left running: {left}"
