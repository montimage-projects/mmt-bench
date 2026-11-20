"""The agent instructions and founding documents keep their required shape (#3)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / "AGENTS.md"
CLAUDE = ROOT / "CLAUDE.md"
DESIGN = ROOT / "docs/design.md"
METHODOLOGY = ROOT / "docs/methodology.md"
CI = ROOT / ".github/workflows/ci.yml"

#: How a shell command in ci.yml starts (not a YAML key such as ``python-version:``).
COMMAND_PREFIXES = ("uv ", "python ", "python3 ")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _agents_commands() -> list[str]:
    """The commands in AGENTS.md's ``## Commands`` shell block, comments removed."""
    text = _read(AGENTS)
    assert "\n## Commands\n" in text, "AGENTS.md has no ## Commands section"
    section = text.split("\n## Commands\n", 1)[1].split("\n## ", 1)[0]
    block = re.search(r"```sh\n(.*?)```", section, re.DOTALL)
    assert block is not None, "no ```sh block under ## Commands"
    commands = [line.split("#", 1)[0].strip() for line in block.group(1).splitlines()]
    return [c for c in commands if c]


def _without_locked(command: str) -> str:
    return " ".join(word for word in command.split() if word != "--locked")


def _ci_run_lines() -> list[str]:
    lines = []
    for line in _read(CI).splitlines():
        line = line.strip()
        if line.startswith("run: "):
            line = line.removeprefix("run: ")
        elif not line.startswith(COMMAND_PREFIXES):
            continue
        lines.append(_without_locked(line))
    return lines


def test_agents_lists_install_lint_test_and_smoke_commands() -> None:
    commands = _agents_commands()
    for expected in (
        "uv sync",
        "uv run ruff check",
        "uv run ruff format --check",
        "uv run mypy",
        "uv run pytest",
        "uv run mbench --help",
    ):
        assert any(c.startswith(expected) for c in commands), expected


#: CI steps that set up the runner and have no local equivalent in AGENTS.md.
CI_SETUP_ONLY = ("python -m pip install",)


def test_agents_commands_are_the_ones_ci_runs() -> None:
    # Each AGENTS.md command is one CI runs (``--locked`` aside).
    ci = _ci_run_lines()
    for command in _agents_commands():
        assert any(line.startswith(_without_locked(command)) for line in ci), command


def test_every_ci_check_is_listed_in_agents() -> None:
    # And the reverse: a check CI gains must be added to AGENTS.md too.
    commands = [_without_locked(c) for c in _agents_commands()]
    for line in _ci_run_lines():
        if not line.startswith(COMMAND_PREFIXES) or line.startswith(CI_SETUP_ONLY):
            continue
        assert any(line.startswith(c) for c in commands), line


#: A phrase from each operating rule that issue #3 requires.
RULES = [
    "No sudo for agents",
    "Never touch the production mmt-stack containers",
    "Results are append-only",
    "The private dgx-spark capture is never committed or published",
    "The repo is private",
]


@pytest.mark.parametrize("rule", RULES)
def test_agents_states_operating_rule(rule: str) -> None:
    assert rule in _read(AGENTS)


def test_agents_says_the_harness_prints_root_commands_for_luong() -> None:
    assert "printed by the harness for Luong to run" in " ".join(_read(AGENTS).split())


def test_claude_md_points_to_agents_without_restating_it() -> None:
    text = _read(CLAUDE)
    assert "[AGENTS.md](AGENTS.md)" in text
    assert "@AGENTS.md" in text
    for rule in RULES:
        assert rule.lower() not in text.lower(), rule
    assert "```" not in text, "CLAUDE.md must not copy the command block"
    assert len([line for line in text.splitlines() if line.strip()]) <= 6


def test_design_has_track_b_sections_in_order_then_decisions() -> None:
    headings = re.findall(r"^## (.+)$", _read(DESIGN), re.MULTILINE)
    numbered = [h.split(".", 1)[0] for h in headings if re.match(r"B\d+\.", h)]
    assert numbered == [f"B{i}" for i in range(1, 11)]
    assert headings[-1] == "Decisions"


def test_design_decisions_lists_the_five_epic_decisions() -> None:
    text = _read(DESIGN)
    assert "\n## Decisions\n" in text, "design.md has no ## Decisions section"
    decisions = text.split("\n## Decisions\n", 1)[1]
    items = re.findall(r"^(\d+)\. ", decisions, re.MULTILINE)
    assert items == ["1", "2", "3", "4", "5"]
    for phrase in (
        "stays private under montimage-projects",
        "kept local only, never committed or published",
        "veth pair only",
        "the harness prints the commands and Luong runs them",
        "A run without it is invalid",
    ):
        assert phrase in " ".join(decisions.split()), phrase


def test_design_has_no_track_a_content() -> None:
    text = _read(DESIGN)
    assert not re.search(r"^#+ (Track A|A\d+\.)", text, re.MULTILINE)
    for marker in ("mmt_sec_rule_build_info", "check-compat", "MANIFEST.json", "rule_info --"):
        assert marker not in text, marker


@pytest.mark.parametrize(
    "heading",
    [
        "A run without a complete SUT record is invalid",
        "Fair comparison",
        "Offline capacity",
        "Online lossless rate (veth only)",
        "Pinning",
        "Statistics",
        "Correctness gate",
        "Duration and safety",
    ],
)
def test_methodology_has_section(heading: str) -> None:
    assert f"\n## {heading}\n" in _read(METHODOLOGY)


def test_methodology_states_the_statistics_rule() -> None:
    text = _read(METHODOLOGY)
    assert "median and IQR over 5 measured repeats" in text
    assert "above 5 %" in text
