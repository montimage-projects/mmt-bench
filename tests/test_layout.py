"""The repository layout from plan §B2 exists, so later issues slot in."""

from __future__ import annotations

import importlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: Every module of the §B2 package layout.
MODULES = [
    "mbench",
    "mbench.cli",
    "mbench.sut",
    "mbench.matrix",
    "mbench.runner",
    "mbench.truth",
    "mbench.modes",
    "mbench.modes.offline",
    "mbench.modes.online",
    "mbench.metrics",
    "mbench.metrics.proc",
    "mbench.metrics.perf",
    "mbench.metrics.nic",
    "mbench.adapters",
    "mbench.adapters.base",
    "mbench.adapters.mmt_probe",
    "mbench.adapters.suricata",
    "mbench.adapters.snort3",
    "mbench.report",
    "mbench.report.render",
    "mbench.report.charts",
]

TOP_LEVEL_DIRS = [
    "src/mbench",
    "docs",
    "tools/docker",
    "corpus",
    "rulesets",
    "campaigns",
    "results",
    "tests",
]


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name: str) -> None:
    importlib.import_module(name)


@pytest.mark.parametrize("path", TOP_LEVEL_DIRS)
def test_top_level_dir_exists(path: str) -> None:
    assert (ROOT / path).is_dir()


def test_package_is_typed() -> None:
    assert (ROOT / "src/mbench/py.typed").is_file()


#: Capture and corpus paths git must ignore, in mixed case on purpose.
IGNORED = [
    "x.pcap",
    "x.pcap.gz",
    "x.Pcap",
    "x.PCAP",
    "x.pcapng",
    "x.PcapNG",
    "x.PCAPNG",
    "x.pcapng.zst",
    "x.cap",
    "x.CAP",
    "x.cap.gz",
    "x.erf",
    "x.ERF",
    "x.Erf.xz",
    "sub/dir/x.pcap",
    "corpus/data/x",
    "corpus/data/sub/x.bin",
]

#: Paths that must stay tracked, so the ignore rules are not trivially true.
NOT_IGNORED = ["x.py", "x.capture", "x.pcapx", "corpus/README.md", "README.md"]


def _git_ignores(tmp_path: Path, path: str) -> bool:
    """Whether the repo's .gitignore alone makes git ignore ``path``.

    Runs in a scratch repo holding only a copy of .gitignore, with the user's
    and the system's git config shut out, so neither a global excludes file nor
    a missing .git (a source export) changes the answer.
    """
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
    shutil.copy(ROOT / ".gitignore", repo / ".gitignore")
    proc = subprocess.run(
        [git, "-c", "core.ignorecase=false", "check-ignore", "--no-index", "-q", path],
        cwd=repo,
        env=env,
        check=False,
    )
    assert proc.returncode in {0, 1}, f"git check-ignore failed ({proc.returncode})"
    return proc.returncode == 0


@pytest.mark.parametrize("path", IGNORED)
def test_gitignore_ignores_captures(path: str, tmp_path: Path) -> None:
    assert _git_ignores(tmp_path, path)


@pytest.mark.parametrize("path", NOT_IGNORED)
def test_gitignore_keeps_other_files(path: str, tmp_path: Path) -> None:
    assert not _git_ignores(tmp_path, path)


def test_placeholder_docstrings_name_their_owning_issue() -> None:
    import mbench.cli
    import mbench.report.charts

    assert "the mmt-bench v0 epic (#1)" in (mbench.cli.__doc__ or "")
    assert "#8" in (mbench.report.charts.__doc__ or "")
    assert "No owning issue" not in (mbench.report.charts.__doc__ or "")


def test_results_readme_states_the_sut_record_rule() -> None:
    # Plan §B1: a run without a complete SUT record is invalid.
    text = " ".join((ROOT / "results/README.md").read_text(encoding="utf-8").split())
    assert (
        "Every run embeds its full SUT record (`mbench sut`, #4); a run without a complete "
        "record is invalid and excluded from every table (#8)."
    ) in text
