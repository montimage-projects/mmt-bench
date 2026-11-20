"""The ``mbench`` entry point and its not-implemented subcommand stubs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from mbench import __version__
from mbench.cli import EXIT_NOT_IMPLEMENTED, SUBCOMMANDS, Subcommand, main

EXPECTED = {"sut", "corpus", "run", "sweep", "report", "validate"}
EXPECTED_ISSUES = {"sut": 4, "corpus": 7, "run": 8, "sweep": 17, "report": 8, "validate": 4}


def test_subcommands_are_the_planned_six() -> None:
    assert {s.name for s in SUBCOMMANDS} == EXPECTED
    assert {s.name: s.issue for s in SUBCOMMANDS} == EXPECTED_ISSUES


def test_help_lists_every_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for name in EXPECTED:
        assert name in out


@pytest.mark.parametrize("sub", SUBCOMMANDS, ids=lambda s: s.name)
def test_stub_exits_non_zero_naming_its_issue(
    sub: Subcommand, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([sub.name]) == EXIT_NOT_IMPLEMENTED
    assert EXIT_NOT_IMPLEMENTED != 0
    err = capsys.readouterr().err
    assert f"mbench {sub.name}: not implemented yet (#{sub.issue})" in err


@pytest.mark.parametrize(
    ("argv", "issue"),
    [
        (["sut", "-o", "sut.json"], 4),  # option first
        (["sut", "--anonymise"], 4),
        (["sut", "-o"], 4),  # option missing its value
        (["run", "campaigns/smoke.yaml", "--repeats", "5"], 8),  # positional first
        (["run", "--rate", "5", "x"], 8),
        (["corpus", "gen", "c-small", "--seed", "1"], 7),
        (["validate", "--", "-weird-name.json"], 4),
    ],
)
def test_stub_accepts_the_arguments_of_the_finished_command(
    argv: list[str], issue: int, capsys: pytest.CaptureFixture[str]
) -> None:
    # A call written for the real subcommand still gets the not-implemented
    # message, not an argparse usage error (exit 2).
    assert main(argv) == EXIT_NOT_IMPLEMENTED
    assert f"not implemented yet (#{issue})" in capsys.readouterr().err


def test_unknown_option_without_subcommand_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--frobnicate"])
    assert exc.value.code == 2


@pytest.mark.parametrize(
    "argv",
    [
        ["--bogus", "sut"],
        ["--bogus", "run", "campaigns/smoke.yaml"],
        ["-x", "validate", "sut.json"],
    ],
)
def test_unknown_option_before_subcommand_is_a_usage_error(argv: list[str]) -> None:
    # Only the subcommand's own arguments reach the stub; an unknown global
    # option is still argparse's usage error, not "not implemented".
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_no_subcommand_prints_help_and_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert "usage: mbench" in capsys.readouterr().err


def test_unknown_subcommand_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["frobnicate"])
    assert exc.value.code == 2


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"mbench {__version__}"


def test_module_entry_point() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "mbench", "sut"], capture_output=True, text=True, check=False
    )
    assert proc.returncode == EXIT_NOT_IMPLEMENTED
    assert "mbench sut: not implemented yet (#4)" in proc.stderr


def test_console_script_installed_by_uv_sync() -> None:
    # ``uv sync`` installs the ``mbench`` script next to the venv's interpreter.
    exe = Path(sys.executable).parent / "mbench"
    assert exe.is_file(), f"missing console script {exe}"
    proc = subprocess.run([str(exe), "--help"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    for name in EXPECTED:
        assert name in proc.stdout
