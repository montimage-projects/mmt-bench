"""``tools/ci/check_no_captures.py``: no packet capture is tracked by git (#7)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from check_no_captures import MAGICS, magic_errors, main, name_errors, tracked_files

ROOT = Path(__file__).resolve().parent.parent


def test_magics_match_the_corpus_reader() -> None:
    from mbench import pcap

    assert MAGICS == pcap.MAGICS


@pytest.mark.parametrize(
    "name",
    [
        "x.pcap",
        "x.pcap.gz",
        "x.Pcap",
        "x.PCAP",
        "x.pcapng",
        "x.PcapNG",
        "x.pcapng.zst",
        "x.cap",
        "x.CAP",
        "x.cap.xz",
        "x.erf",
        "x.ERF",
        "sub/dir/x.pcap",
        "corpus/data/x.pcap",
    ],
)
def test_a_capture_name_is_flagged(name: str) -> None:
    assert name_errors([name]) == [f"{name}: tracked capture name"]


@pytest.mark.parametrize("name", ["x.py", "x.capture", "x.pcapx", "corpus/README.md", "x.caplist"])
def test_an_innocent_name_passes(name: str) -> None:
    assert name_errors([name]) == []


def test_a_capture_renamed_past_the_patterns_is_caught(tmp_path: Path) -> None:
    for name in ("x.bin", "corpus/data/blob"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(MAGICS[0] + b"0" * 20)
    (tmp_path / "x.txt").write_text("not a capture", encoding="utf-8")
    errors = magic_errors(tmp_path, ["x.bin", "corpus/data/blob", "x.txt", "staged-deleted"])
    assert errors == [
        "x.bin: tracked file starts with a capture magic",
        "corpus/data/blob: tracked file starts with a capture magic",
    ]


def git_repo(tmp_path: Path) -> Path:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    repo = tmp_path / "repo"
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(tmp_path),
    }
    subprocess.run([git, "init", "-q", str(repo)], check=True, env=env)
    (repo / "README.md").write_text("x", encoding="utf-8")
    subprocess.run([git, "-C", str(repo), "add", "README.md"], check=True, env=env)
    return repo


def test_main_on_the_repo_itself_is_clean() -> None:
    assert main([str(ROOT)]) == 0
    assert tracked_files(ROOT)


def test_main_fails_on_a_tracked_capture(tmp_path: Path) -> None:
    repo = git_repo(tmp_path)
    (repo / "x.pcap").write_bytes(MAGICS[0] + b"0" * 20)
    subprocess.run(
        ["git", "-C", str(repo), "add", "-f", "x.pcap"],
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    assert main([str(repo)]) == 1


def test_main_fails_on_a_renamed_capture(tmp_path: Path) -> None:
    repo = git_repo(tmp_path)
    (repo / "blob.bin").write_bytes(MAGICS[-1] + b"0" * 24)
    subprocess.run(
        ["git", "-C", str(repo), "add", "blob.bin"],
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    assert main([str(repo)]) == 1


def test_main_passes_on_a_clean_repo(tmp_path: Path) -> None:
    repo = git_repo(tmp_path)
    assert main([str(repo)]) == 0


def test_main_fails_closed_without_git(tmp_path: Path) -> None:
    assert main([str(tmp_path)]) == 2
