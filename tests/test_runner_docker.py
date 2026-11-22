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
from mbench.modes import offline

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


def _long_campaign(root: Path, rules_dir: Path) -> Path:
    """The signal tests' campaign: a generated capture big enough that a
    measured pass lasts tens of seconds, so a signal can land mid-pass."""
    (root / "campaigns").mkdir(parents=True)
    shutil.copytree(rules_dir, root / "rules")
    big = root / "big.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 750_000, 256, big)
    campaign = root / "campaigns" / "signal.yaml"
    campaign.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "question": "does a signal kill the run container?",
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
    return campaign


def _interrupt_the_pass(proc: subprocess.Popen[bytes], signum: int) -> bool:
    """Send ``signum`` once the pass's container is up; True when it was.

    Waits for the ``mbench-mmt-probe-run-*`` container, signals the
    process and waits it out — then makes sure the process is dead even
    when the container never came up, so the test cannot hang and no
    container can be orphaned by a hard kill.
    """
    deadline = time.monotonic() + 180
    try:
        while time.monotonic() < deadline and proc.poll() is None:
            if _mbench_containers("mbench-mmt-probe-run-"):
                proc.send_signal(signum)
                proc.wait(timeout=120)
                return True
            time.sleep(0.2)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)  # graceful first: the run cleans up
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)
    return False


def _no_mbench_container() -> None:
    """Assert no ``mbench-`` container is left, giving the daemon's --rm a grace."""
    left = _mbench_containers()
    for _ in range(50):
        if not left:
            break
        time.sleep(0.2)
        left = _mbench_containers()
    assert left == "", f"mbench containers left running: {left}"


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
    campaign = _long_campaign(tmp_path / "proj", rules_dir)
    results = tmp_path / "results"
    proc = subprocess.Popen(
        [sys.executable, "-m", "mbench", "run", str(campaign), "--results", str(results)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    seen_container = _interrupt_the_pass(proc, signal.SIGINT)
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
    _no_mbench_container()


@needs_docker
@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGHUP])
def test_sigterm_and_sighup_during_a_pass_take_the_interrupted_path(
    adapter: MmtProbeAdapter, tmp_path: Path, signum: int
) -> None:
    """SIGTERM and SIGHUP mid-pass take the interrupted path (review N1).

    The default kill signals — ``kill``, ``timeout``, CI cancellation,
    ``systemctl stop``, a hung-up terminal — must end like a Ctrl-C: the
    ``mbench-`` container dead, the cell recorded ``interrupted`` with the
    signal named, REPORT.md rendered, the tmpfs stage dir removed, and the
    process exiting ``128 + signum`` as an uncaught signal would.
    """
    rules_dir = _extract(adapter, "mmt-rules", "/opt/mmt/security/rules", tmp_path)
    campaign = _long_campaign(tmp_path / "proj", rules_dir)
    results = tmp_path / "results"
    stage_root = offline.tmpfs_dir()
    staged_before = set(stage_root.glob("mbench-*")) if stage_root else set()
    proc = subprocess.Popen(
        [sys.executable, "-m", "mbench", "run", str(campaign), "--results", str(results)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    seen_container = _interrupt_the_pass(proc, signum)
    assert proc.stderr is not None
    stderr = proc.stderr.read().decode()
    assert seen_container, f"the run container never came up; mbench stderr: {stderr}"
    signame = signal.Signals(signum).name

    # The cell is interrupted and names the signal; REPORT.md is rendered.
    run_files = sorted(results.rglob("runs/*.json"))
    assert run_files, f"no run file; mbench stderr: {stderr}"
    records = [json.loads(p.read_text(encoding="utf-8")) for p in run_files]
    interrupted = [r for r in records if r["status"] == "interrupted"]
    assert interrupted, f"no interrupted run; mbench stderr: {stderr}"
    problems = [p for r in interrupted for p in r["problems"]]
    assert any(signame in p for p in problems), f"{signame} not in problems: {problems}"
    assert list(results.rglob("REPORT*.md")), f"no REPORT.md after {signame}"
    # 128 + signum, the status of an uncaught signal — not -signum (killed).
    assert proc.returncode == 128 + signum

    _no_mbench_container()
    # And the tmpfs stage dir is gone: nothing new under the staging root.
    if stage_root:
        left_dirs = set(stage_root.glob("mbench-*")) - staged_before
        assert not left_dirs, f"stage dirs left on {stage_root}: {left_dirs}"
