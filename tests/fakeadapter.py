"""A fake tool behind the full :class:`~mbench.adapters.base.Adapter` interface.

It starts no container and no process: ``run_offline`` returns a handle that
has already exited, and ``counters`` and ``alerts`` return what the test gave
it. So the runner (#8) and the scoring can be tested without Docker.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from mbench import sut
from mbench.adapters.base import (
    CONFIG_PROFILES,
    Adapter,
    Alert,
    Counters,
    ImageRef,
    Json,
    ProcessHandle,
    RuleInfo,
    Ruleset,
    config_record,
)

FAKE_DIGEST = "sha256:" + "0" * 64


@dataclass
class FakeProcess:
    """A process handle for a run that takes ``duration_s`` (simulated) seconds."""

    returncode: int = 0
    duration_s: float = 0.0
    killed: bool = False

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if timeout is not None and self.duration_s > timeout:
            raise subprocess.TimeoutExpired("fake-tool", timeout)
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self.duration_s = 0.0


@dataclass
class Call:
    """One ``run_offline`` or ``run_online`` call the fake received."""

    mode: str
    target: str
    threads: int
    cpuset: tuple[int, ...]


@dataclass
class FakeAdapter(Adapter):
    """A configurable fake tool.

    ``run_alerts`` and ``run_counters`` are what every run reports;
    ``duration_s`` makes its handle exceed a short timeout.
    """

    run_alerts: list[Alert] = field(default_factory=list)
    run_counters: Counters = field(default_factory=lambda: Counters(0, 0, 0))
    duration_s: float = 0.0
    rules: list[RuleInfo] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    _config_files: list[Path] = field(default_factory=list)
    _workdir: Path | None = None
    _ruleset: Ruleset | None = None

    @property
    def name(self) -> str:
        return "fake-tool"

    def version(self) -> str | sut.Marker:
        return "1.2.3"

    @property
    def image(self) -> ImageRef | sut.Marker:
        return ImageRef("example.invalid/fake-tool:1.2.3", FAKE_DIGEST)

    def prepare(self, ruleset: Ruleset, config_profile: str, workdir: Path) -> list[Path]:
        if config_profile not in CONFIG_PROFILES:
            raise ValueError(f"unknown config profile: {config_profile}")
        workdir.mkdir(parents=True, exist_ok=True)
        main = workdir / "fake.conf"
        main.write_text(f"profile = {config_profile}\nruleset = {ruleset.id}\n", encoding="utf-8")
        rules = workdir / "rules.conf"
        rules.write_text(f"include {ruleset.path.name}\n", encoding="utf-8")
        self._config_files = [main, rules]
        self._workdir = workdir
        self._ruleset = ruleset
        return list(self._config_files)

    def _start(self, mode: str, target: str, threads: int, cpuset: Sequence[int]) -> ProcessHandle:
        if self._workdir is None:
            raise RuntimeError("prepare() first")
        self.calls.append(Call(mode, target, threads, tuple(cpuset)))
        return FakeProcess(duration_s=self.duration_s)

    def run_offline(self, pcap: Path, threads: int, cpuset: Sequence[int]) -> ProcessHandle:
        return self._start("offline", pcap.name, threads, cpuset)

    def run_online(self, iface: str, threads: int, cpuset: Sequence[int]) -> ProcessHandle:
        return self._start("online", iface, threads, cpuset)

    def counters(self) -> Counters:
        return self.run_counters

    def alerts(self) -> list[Alert]:
        return list(self.run_alerts)

    def rule_inventory(self, ruleset: Ruleset) -> list[RuleInfo]:
        return list(self.rules)

    def tools_record(self) -> dict[str, Json]:
        if self._workdir is None or self._ruleset is None:
            raise RuntimeError("prepare() first")
        image = self.image
        return {
            "name": self.name,
            "version": self.version(),
            "image": image.to_dict() if isinstance(image, ImageRef) else image,
            "version_strings": {"fake-engine": "1.2.3", "fake-rules-module": "0.1"},
            "build_flags": {"simd": True, "lto": False},
            "ruleset": {"id": self._ruleset.id, "sha256": self._ruleset.sha256()},
            "config": config_record(self._config_files, self._workdir),
        }
