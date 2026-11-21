"""The mmt-probe adapter (#6), offline mode — unit tests, no Docker needed.

The fixtures under ``tests/fixtures/mmt-probe/`` are recorded output of the
pinned image (`mmt-bench/mmt-probe`, built from tools/docker/mmt-probe): a
probe report file (``report.json``), the same file trimmed to two of its
eight STIX alerts (``report-arp.json``), the probe's end-of-run log
(``probe.log``), a ``rule_info`` listing (``rule_info.txt``) and the
``versions`` output (``versions.txt``). They hold only the check captures'
own test addresses — no host identifier.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO

import pytest
from fakeadapter import FakeProcess

from mbench import sut
from mbench.adapters import mmt_probe
from mbench.adapters.base import (
    Adapter,
    ImageRef,
    InvalidValue,
    Ruleset,
    tools_record_errors,
)
from mbench.adapters.mmt_probe import MmtProbeAdapter

FIXTURES = Path(__file__).parent / "fixtures" / "mmt-probe"
DIGEST = "sha256:" + "ab" * 32


class RecordingDocker:
    """A :class:`mmt_probe.Docker` that never touches a daemon.

    It records every argv, answers ``image inspect`` with a fixed digest,
    ``run ... versions`` and ``run ... rule_info`` with the fixtures, and
    ``spawn`` with an already-exited process. ``writes`` lists the report
    files the fake run produced (the test fills them with the fixtures).
    """

    def __init__(self, digest: str = DIGEST) -> None:
        self.calls: list[list[str]] = []
        self.spawned: list[list[str]] = []
        self.digest = digest
        self.rule_info_text = (FIXTURES / "rule_info.txt").read_text(encoding="utf-8")
        self.versions_text = (FIXTURES / "versions.txt").read_text(encoding="utf-8")

    def run(
        self, argv: Sequence[str], timeout: float | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(list(argv))
        out = b""
        if argv[:2] == ["image", "inspect"]:
            out = self.digest.encode()
        elif argv[0] == "run" and argv[-1] == "versions":
            out = self.versions_text.encode()
        elif argv[0] == "run" and argv[-1] == "rule_info":
            out = self.rule_info_text.encode()
        return subprocess.CompletedProcess(list(argv), 0, out, b"")

    def spawn(self, argv: Sequence[str], stdout: BinaryIO) -> subprocess.Popen[bytes]:
        self.spawned.append(list(argv))
        return FakeProcess()  # type: ignore[return-value]


def _ruleset(tmp_path: Path) -> Ruleset:
    rules = tmp_path / "set" / "all"
    rules.mkdir(parents=True, exist_ok=True)
    for name in ("a.so", "b.so"):
        (rules / name).write_bytes(b"\x7fELF fake " + name.encode())
    return Ruleset("all", rules)


def _prepared(
    tmp_path: Path, docker: RecordingDocker | None = None
) -> tuple[MmtProbeAdapter, RecordingDocker, Path]:
    docker = docker or RecordingDocker()
    adapter = MmtProbeAdapter(f"img@example.test/probe@{DIGEST}", docker=docker)
    workdir = tmp_path / "work"
    adapter.prepare(_ruleset(tmp_path), "recommended", workdir)
    return adapter, docker, workdir


def _run(adapter: MmtProbeAdapter, workdir: Path, tmp_path: Path) -> None:
    pcap = tmp_path / "input.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    adapter.run_offline(pcap, 1, [0, 1])


def _fill_reports(workdir: Path, fixture: str = "report.json") -> None:
    shutil.copy(FIXTURES / fixture, workdir / "reports" / fixture)


def _fill_log(workdir: Path) -> None:
    shutil.copy(FIXTURES / "probe.log", workdir / "probe.log")


# --- The adapter, image pinning and lifecycle ------------------------------------


def test_it_is_an_adapter() -> None:
    assert isinstance(MmtProbeAdapter(ImageRef("img", DIGEST), docker=RecordingDocker()), Adapter)
    assert MmtProbeAdapter(ImageRef("img", DIGEST), docker=RecordingDocker()).name == "mmt-probe"


def test_a_digest_pinned_reference_is_kept_whole() -> None:
    ref = mmt_probe.parse_image_ref(f"registry.test/mmt/probe@{DIGEST}")
    assert ref.ref == f"registry.test/mmt/probe@{DIGEST}"
    assert ref.digest == DIGEST


def test_a_tag_only_reference_fails() -> None:
    # The criterion: a bare tag cannot prove which image ran.
    with pytest.raises(InvalidValue, match="tag-only"):
        mmt_probe.parse_image_ref("mmt-probe:latest")
    with pytest.raises(InvalidValue, match="tag-only"):
        MmtProbeAdapter("mmt-probe:latest", docker=None)


def test_a_tag_resolves_to_the_daemon_digest() -> None:
    ref = mmt_probe.parse_image_ref("mmt-bench/mmt-probe:local", RecordingDocker())
    assert ref == ImageRef("mmt-bench/mmt-probe:local", DIGEST)


def test_a_tag_the_daemon_cannot_pin_fails() -> None:
    class NoImage(RecordingDocker):
        def run(
            self, argv: Sequence[str], timeout: float | None = None
        ) -> subprocess.CompletedProcess[bytes]:
            self.calls.append(list(argv))
            return subprocess.CompletedProcess(list(argv), 1, b"", b"no such image")

    with pytest.raises(InvalidValue, match="tag-only"):
        mmt_probe.parse_image_ref("missing:tag", NoImage())


def test_run_online_is_a_named_not_implemented(tmp_path: Path) -> None:
    adapter = MmtProbeAdapter(ImageRef("img", DIGEST), docker=RecordingDocker())
    with pytest.raises(NotImplementedError, match="P4"):
        adapter.run_online("veth0", 1, [0])


def test_run_offline_needs_prepare(tmp_path: Path) -> None:
    adapter = MmtProbeAdapter(ImageRef("img", DIGEST), docker=RecordingDocker())
    with pytest.raises(RuntimeError, match="prepare"):
        adapter.run_offline(tmp_path / "x.pcap", 1, [0])


def test_run_offline_needs_a_pcap(tmp_path: Path) -> None:
    adapter, _, _ = _prepared(tmp_path)
    with pytest.raises(FileNotFoundError):
        adapter.run_offline(tmp_path / "missing.pcap", 1, [0])


def test_a_spawn_failure_closes_the_log(tmp_path: Path) -> None:
    class SpawnFails(RecordingDocker):
        def __init__(self) -> None:
            super().__init__()
            self.stdout: BinaryIO | None = None

        def spawn(self, argv: Sequence[str], stdout: BinaryIO) -> subprocess.Popen[bytes]:
            self.stdout = stdout
            raise RuntimeError("spawn failed")

    docker = SpawnFails()
    adapter, _, _ = _prepared(tmp_path, docker)
    pcap = tmp_path / "input.pcap"
    pcap.write_bytes(b"pcap")
    with pytest.raises(RuntimeError, match="spawn failed"):
        adapter.run_offline(pcap, 1, [0])
    assert docker.stdout is not None
    assert docker.stdout.closed


# --- prepare and the run ----------------------------------------------------------


def test_prepare_writes_the_config_and_stages_the_rules(tmp_path: Path) -> None:
    ruleset = _ruleset(tmp_path)
    adapter, _, workdir = _prepared(tmp_path)
    written = adapter.prepare(ruleset, "tuned", workdir / "b")
    assert [p.name for p in written] == ["mmt-probe.conf"]
    conf = (workdir / "b" / "mmt-probe.conf").read_text(encoding="utf-8")
    assert "tuned profile" in conf
    assert 'output-dir   = "/data/reports/"' in conf
    staged = sorted(p.name for p in (workdir / "b" / "mmt-rules").iterdir())
    assert staged == ["a.so", "b.so"]


def test_ignore_remain_flow_is_false_in_both_profiles() -> None:
    # The detection-fair default (review F1): the probe reports every
    # verdict, not only a flow's first; the conf records the value.
    for profile in ("recommended", "tuned"):
        conf = mmt_probe.render_config(profile)
        lines = [s.strip() for s in conf.splitlines() if s.strip().startswith("ignore-remain-flow")]
        assert lines and lines[0].split("=", 1)[1].strip() == "false", profile


def test_an_unknown_profile_is_refused(tmp_path: Path) -> None:
    adapter = MmtProbeAdapter(ImageRef("img", DIGEST), docker=RecordingDocker())
    with pytest.raises(ValueError, match="config profile"):
        adapter.prepare(_ruleset(tmp_path), "custom", tmp_path / "work")


def test_prepare_rejects_an_empty_ruleset(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    adapter = MmtProbeAdapter(ImageRef("img", DIGEST), docker=RecordingDocker())
    with pytest.raises(FileNotFoundError, match=r"no \.so rule"):
        adapter.prepare(Ruleset("empty", empty), "recommended", tmp_path / "work")


def test_a_ruleset_file_without_a_so_suffix_is_refused(tmp_path: Path) -> None:
    # rule_info loads *.so only: staging a non-.so file would silently
    # yield zero rules — refuse it instead (review §7).
    not_a_rule = tmp_path / "rules.xml"
    not_a_rule.write_bytes(b"<rules/>")
    adapter = MmtProbeAdapter(ImageRef("img", DIGEST), docker=RecordingDocker())
    with pytest.raises(InvalidValue, match=r"not a \.so rule file"):
        adapter.prepare(Ruleset("bad", not_a_rule), "recommended", tmp_path / "work")
    with pytest.raises(InvalidValue, match=r"not a \.so rule file"):
        adapter.rule_inventory(Ruleset("bad", not_a_rule))


def test_a_tag_resolved_image_runs_by_its_image_id(tmp_path: Path) -> None:
    # The record pins the resolved image id, so the run must target that
    # id — a retag between resolve and run would otherwise change what
    # ran (review §7).
    docker = RecordingDocker()
    adapter = MmtProbeAdapter("mmt-bench/mmt-probe:local", docker=docker)
    workdir = tmp_path / "work"
    adapter.prepare(_ruleset(tmp_path), "recommended", workdir)
    pcap = tmp_path / "input.pcap"
    pcap.write_bytes(b"pcap")
    adapter.run_offline(pcap, 1, [0])
    adapter.rule_inventory(_ruleset(tmp_path))
    adapter.version()
    for argv in docker.spawned + [c for c in docker.calls if c[0] == "run"]:
        assert DIGEST in argv
        assert "mmt-bench/mmt-probe:local" not in argv


def test_run_offline_runs_an_mbench_container_with_own_mounts_only(tmp_path: Path) -> None:
    adapter, docker, workdir = _prepared(tmp_path)
    pcap = tmp_path / "input.pcap"
    pcap.write_bytes(b"pcap")
    handle = adapter.run_offline(pcap, 4, [2, 3])
    assert handle.wait(timeout=10) == 0
    argv = docker.spawned[-1]
    # The container: --rm, a mbench- name, no network, the adapter's mounts only.
    assert "--rm" in argv
    name = argv[argv.index("--name") + 1]
    # The prefix is pinned literally: it is what keeps the bench containers
    # apart from the production ``mmt-*`` ones.
    assert name.startswith("mbench-")
    assert argv[argv.index("--network") : argv.index("--network") + 2] == ["--network", "none"]
    assert argv[argv.index("--cpuset-cpus") + 1] == "2-3"
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    sources = [m.split(":")[0] for m in mounts]
    for source in sources:
        assert source == str(pcap.resolve()) or source.startswith(str(workdir.resolve()))
    assert any(m == f"{pcap.resolve()}:/pcap/input.pcap:ro" for m in mounts)
    assert any(m.endswith(":/opt/mmt/security/rules:ro") for m in mounts)
    # The probe call: config, offline pcap, the threads override.
    assert "probe" in argv
    assert argv[argv.index("-t") + 1] == "/pcap/input.pcap"
    assert "thread-nb=4" in argv


def test_no_container_outside_the_mbench_prefix_is_touched(tmp_path: Path) -> None:
    # The criterion: only mbench- named containers are started, killed or
    # mounted, whatever the adapter is asked to do.
    adapter, docker, workdir = _prepared(tmp_path)
    _run(adapter, workdir, tmp_path)
    _fill_reports(workdir)
    adapter.counters()
    adapter.alerts()
    adapter.rule_inventory(_ruleset(tmp_path))
    adapter.version()
    adapter.tools_record()
    handle = adapter.run_offline(tmp_path / "input.pcap", 1, [0])
    handle.kill()
    for argv in docker.calls + docker.spawned:
        if "--name" in argv:
            assert argv[argv.index("--name") + 1].startswith("mbench-"), argv
        if argv[0] in ("kill", "stop", "restart", "rm"):
            assert argv[1].startswith("mbench-"), argv
        for i, arg in enumerate(argv[:-1]):
            if arg == "-v":
                source = argv[i + 1].split(":")[0]
                # Only the test's dirs (workdir, pcap, ruleset) or the
                # adapter's own mbench-rules- staging dir may be mounted —
                # never another container's data.
                assert source.startswith(str(tmp_path)) or "mbench-rules-" in source, argv


# --- counters, alerts, rules --------------------------------------------------------


def test_counters_sum_the_reports_and_the_status_line(tmp_path: Path) -> None:
    adapter, _, workdir = _prepared(tmp_path)
    _run(adapter, workdir, tmp_path)
    _fill_reports(workdir)
    _fill_log(workdir)
    counters = adapter.counters()
    # The recorded run: 2 packets, 134 bytes, no drop.
    assert (counters.packets, counters.bytes, counters.drops) == (2, 134, 0)
    assert counters.extra["session_reports"] == 1
    assert counters.extra["stix_alerts"] == 1


def test_counters_raise_when_the_probe_wrote_nothing(tmp_path: Path) -> None:
    # A zero-counter "success" is easier to misread than an error (review
    # §7): a run that produced no report at all raises.
    adapter, _, workdir = _prepared(tmp_path)
    _run(adapter, workdir, tmp_path)
    with pytest.raises(RuntimeError, match="no report"):
        adapter.counters()


def test_the_stix_alert_is_normalised(tmp_path: Path) -> None:
    adapter, _, workdir = _prepared(tmp_path)
    _run(adapter, workdir, tmp_path)
    _fill_reports(workdir)
    alerts = adapter.alerts()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "13"
    assert alert.category == "evasion"
    assert alert.ts == pytest.approx(1492182884.795833)
    assert (alert.src, alert.dst, alert.proto) == ("192.168.56.20", "192.168.0.101", "tcp")


def test_the_arp_alerts_normalise_a_single_ip_and_arp_proto(tmp_path: Path) -> None:
    adapter, _, workdir = _prepared(tmp_path)
    _run(adapter, workdir, tmp_path)
    _fill_reports(workdir, "report-arp.json")
    alerts = adapter.alerts()
    assert [a.rule_id for a in alerts] == ["4", "5"]
    for alert in alerts:
        assert alert.category == "attack"
        assert alert.proto == "arp"
        # The bundle names one address: the alert repeats it on both ends.
        assert alert.src == alert.dst


def test_rule_inventory_lists_the_staged_rules(tmp_path: Path) -> None:
    adapter, _, _ = _prepared(tmp_path)
    rules = {r.id: r for r in adapter.rule_inventory(_ruleset(tmp_path))}
    assert set(rules) == {"13", "15", "4", "5"}
    assert rules["13"].category == "evasion"
    assert rules["13"].protocols == ("ip", "tcp")
    assert rules["13"].stateful is True
    assert rules["4"].layer == "L2/3"
    assert rules["15"].layer == "L7-web"


def test_version_and_the_version_strings(tmp_path: Path) -> None:
    adapter, _, _ = _prepared(tmp_path)
    assert adapter.version() == "1.6.5"
    record = adapter.tools_record()
    assert record["version_strings"]["mmt-probe"].startswith("1.6.5")
    assert "6a0afb46" in record["version_strings"]["mmt-dpi"]
    assert record["build_flags"]["security_module"] is True
    assert record["build_flags"]["stix_format"] is True


def test_build_flags_keys_have_no_leading_space(tmp_path: Path) -> None:
    # "Modules: DPI, PCAP, REPORT, SECURITY" is comma-separated: without a
    # strip the keys were "module_ pcap", "module_ report"... (review F3).
    adapter, _, _ = _prepared(tmp_path)
    record = adapter.tools_record()
    flags = record["build_flags"]
    assert all(key == key.strip() for key in flags), flags
    for module in ("dpi", "pcap", "report", "security"):
        assert flags[f"module_{module}"] is True, flags


def test_the_security_source_repo_is_recorded(tmp_path: Path) -> None:
    # /opt/mmt/VERSIONS's security_repo= pin reaches the tools record, so
    # an upstream-built image is visibly different from the default fork.
    adapter, _, _ = _prepared(tmp_path)
    record = adapter.tools_record()
    assert record["version_strings"]["pin-security_repo"] == (
        "https://github.com/montimage-projects/mmt-security.git"
    )


def test_a_version_less_image_gives_a_marker(tmp_path: Path) -> None:
    class NoVersions(RecordingDocker):
        def run(
            self, argv: Sequence[str], timeout: float | None = None
        ) -> subprocess.CompletedProcess[bytes]:
            self.calls.append(list(argv))
            return subprocess.CompletedProcess(list(argv), 1, b"", b"fail")

    adapter = MmtProbeAdapter(ImageRef("img", DIGEST), docker=NoVersions())
    marker = adapter.version()
    assert sut.is_unavailable(marker)


# --- the tools record --------------------------------------------------------------


def test_the_tools_record_validates(tmp_path: Path) -> None:
    adapter, _, workdir = _prepared(tmp_path)
    _run(adapter, workdir, tmp_path)
    record = adapter.tools_record()
    assert tools_record_errors(record) == []
    assert record["name"] == "mmt-probe"
    assert record["image"]["digest"] == DIGEST
    assert record["ruleset"]["id"] == "all"
    assert "# mbench-config-file: mmt-probe.conf" in record["config"]["content"]


def test_an_incomplete_tools_record_is_rejected(tmp_path: Path) -> None:
    adapter, _, workdir = _prepared(tmp_path)
    _run(adapter, workdir, tmp_path)
    record = adapter.tools_record()
    del record["version_strings"]
    assert tools_record_errors(record)
