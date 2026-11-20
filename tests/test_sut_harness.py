"""``harness.mbench_commit``: asked of git through a Source, read-only."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from mbench import sut
from mbench.hostsrc import CommandResult

COMMIT = "a" * 40


class FakeGit:
    """A host whose git answers as if ``package`` were in the work tree ``toplevel``."""

    def __init__(self, toplevel: str, package: str, *, installed: bool = True) -> None:
        self.toplevel = toplevel
        self.package = package
        self.installed = installed
        self.calls: list[list[str]] = []

    def run(self, argv: Sequence[str]) -> CommandResult:
        self.calls.append(list(argv))
        if not self.installed:
            raise FileNotFoundError(2, "command not found: git", "git")
        if "--show-toplevel" in argv:
            return CommandResult(0, f"{self.toplevel}\n", "")
        if "--verify" in argv:
            return CommandResult(0, f"{COMMIT}\n", "")
        if "status" in argv:
            return CommandResult(0, " M src/mbench/sut.py\n", "")
        return CommandResult(1, "", "unexpected")

    def realpath(self, path: str) -> str:
        return os.path.normpath(path)

    def read(self, path: str) -> str:
        raise FileNotFoundError(2, "not here", path)

    def listdir(self, path: str) -> list[str]:
        raise FileNotFoundError(2, "not here", path)

    def sleep(self, seconds: float) -> None:
        return None

    def constants(self) -> dict[str, int]:
        return {"euid": 1000, "page_size": 4096, "clock_ticks": 100}


def test_every_git_call_takes_no_optional_lock() -> None:
    host = FakeGit("/srv/mbench", "/srv/mbench/src/mbench")
    info = sut.HarnessInfo.live(host, "/srv/mbench/src/mbench")
    assert (info.mbench_commit, info.mbench_dirty) == (COMMIT, True)
    assert len(host.calls) == 3
    for argv in host.calls:
        assert argv[:2] == ["git", "--no-optional-locks"], argv


def test_mbench_installed_inside_another_repository_records_no_commit() -> None:
    package = "/srv/project/.venv/lib/python3.12/site-packages/mbench"
    host = FakeGit("/srv/project", package)
    info = sut.HarnessInfo.live(host, package)
    for value in (info.mbench_commit, info.mbench_dirty):
        assert sut.is_unavailable(value)
        assert value["unavailable"] == "not_applicable"
        assert "another repository" in value["reason"]
        assert "/srv" not in value["reason"]  # a reason never names a path
    assert len(host.calls) == 1  # that repository's HEAD is never asked for


def test_git_not_installed() -> None:
    host = FakeGit("/srv/mbench", "/srv/mbench/src/mbench", installed=False)
    info = sut.HarnessInfo.live(host, "/srv/mbench/src/mbench")
    assert info.mbench_commit == sut.unavailable("missing_tool", "git is not installed")


# --- On a real git checkout ---------------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, env=env
    ).stdout


@pytest.fixture
def checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A git work tree laid out like mbench's, with a stale index entry."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    repo = tmp_path / "mbench"
    (repo / "src" / "mbench").mkdir(parents=True)
    (repo / "src" / "mbench" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(
        repo,
        "-c",
        "user.name=test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "init",
    )
    # Same content, older mtime: the index entry is stale, so a plain
    # `git status` would refresh it and rewrite .git/index.
    os.utime(repo / "src" / "mbench" / "__init__.py", (946684800, 946684800))
    return repo


@needs_git
def test_live_git_state_leaves_the_index_untouched(checkout: Path) -> None:
    index = checkout / ".git" / "index"
    before = index.read_bytes()
    info = sut.HarnessInfo.live(package_dir=checkout / "src" / "mbench")
    assert info.mbench_commit == _git(checkout, "rev-parse", "HEAD").strip()
    assert info.mbench_dirty is False
    assert index.read_bytes() == before
    assert not (checkout / ".git" / "index.lock").exists()
    # The check is meaningful: a plain `git status` does rewrite this index.
    _git(checkout, "status", "--porcelain")
    assert index.read_bytes() != before


@needs_git
def test_live_git_state_of_a_package_inside_another_repository(checkout: Path) -> None:
    package = checkout / ".venv" / "lib" / "python3.12" / "site-packages" / "mbench"
    package.mkdir(parents=True)
    info = sut.HarnessInfo.live(package_dir=package)
    assert sut.is_unavailable(info.mbench_commit)
    assert "another repository" in info.mbench_commit["reason"]
