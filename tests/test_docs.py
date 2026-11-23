"""The agent instructions and founding documents keep their required shape (#3)."""

from __future__ import annotations

import hashlib
import re
import shlex
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / "AGENTS.md"
CLAUDE = ROOT / "CLAUDE.md"
DESIGN = ROOT / "docs/design.md"
METHODOLOGY = ROOT / "docs/methodology.md"
CI = ROOT / ".github/workflows/ci.yml"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _agents_commands() -> list[str]:
    """The commands in AGENTS.md's ``## Commands`` shell block, comments removed."""
    text = _read(AGENTS)
    assert "\n## Commands\n" in text, "AGENTS.md has no ## Commands section"
    section = text.split("\n## Commands\n", 1)[1].split("\n## ", 1)[0]
    block = re.search(r"```sh\n(.*?)```", section, re.DOTALL)
    assert block is not None, "no ```sh block under ## Commands"
    commands: list[str] = []
    current = ""
    for raw in block.group(1).splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        current = f"{current} {line}" if current else line
        if current.endswith("\\"):
            # A ``\`` continuation wraps a long command under 80 columns (N3).
            current = current[:-1].rstrip()
            continue
        commands.append(current)
        current = ""
    assert not current, "a `\\` continuation needs a next line"
    return commands


#: The one ``--python`` the normalisation drops: ``uv sync`` pins the
#: setup-python interpreter on CI where AGENTS.md writes neither. Any other
#: spelling — a different interpreter on the sync line, or ``--python`` on
#: another command — stays in the comparable form and fails the checks
#: below: the review planted ``uv run --locked --python 3.12 pytest`` and a
#: changed sync interpreter, and both passed unseen.
UV_SYNC_PYTHON = "$(command -v python)"


def _normalize(command: str) -> str:
    """A command's comparable form: ``--locked`` dropped, and
    ``--python "$(command -v python)"`` dropped on ``uv sync`` only.

    CI runs ``uv sync --locked --python "$(command -v python)"`` where
    AGENTS.md writes ``uv sync --locked``; both reduce to ``uv sync``.
    """
    words = shlex.split(command)
    kept: list[str] = []
    i = 0
    while i < len(words):
        on_sync = kept[:2] == ["uv", "sync"]
        if words[i] == "--locked":
            i += 1
        elif on_sync and words[i : i + 2] == ["--python", UV_SYNC_PYTHON]:
            i += 2
        elif on_sync and words[i] == f"--python={UV_SYNC_PYTHON}":
            i += 1
        else:
            kept.append(words[i])
            i += 1
    return " ".join(kept)


def _ci_run_lines() -> list[str]:
    """Every command a ``run:`` step in ci.yml executes.

    ``run: cmd`` gives one; a ``run: |`` block gives every line in it, less
    comments and blanks. A line starting with an env assignment or
    ``cd … &&`` is kept like any other command, so it fails the
    whole-command comparisons below instead of passing unseen (N1).
    """
    lines = _read(CI).splitlines()
    commands: list[str] = []
    i = 0
    while i < len(lines):
        match = re.match(r"(?:-\s+)?run:\s*(.*)", lines[i].strip())
        if match is None:
            i += 1
            continue
        indent = len(lines[i]) - len(lines[i].lstrip())
        words = match.group(1).split()
        i += 1
        if words and words[0] in ("|", "|-", "|+", ">", ">-", ">+"):
            while i < len(lines):
                body = lines[i]
                if body.strip() and len(body) - len(body.lstrip()) <= indent:
                    break
                if body.strip() and not body.strip().startswith("#"):
                    commands.append(body.strip())
                i += 1
        elif words:
            commands.append(match.group(1).strip())
    return commands


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


def test_agents_lines_stay_within_80_columns() -> None:
    # N3: the review flagged an unwrapped 94-character line; the file stays
    # wrapped — a long shell command takes a ``\`` continuation.
    over = [
        (n, len(line))
        for n, line in enumerate(_read(AGENTS).splitlines(), start=1)
        if len(line) > 80
    ]
    assert not over, f"AGENTS.md lines over 80 columns: {over}"


#: ``run:`` lines that set the runner up, not checks AGENTS.md must list. An
#: exact match is the only way one skips the whole-command comparison below:
#: a changed argument is drift the test reports (N1).
CI_RUNNER_ONLY = {
    "set -euo pipefail",
    "python -m pip install --require-hashes --no-deps -r .github/uv-requirements.txt",
}


def test_agents_commands_are_the_ones_ci_runs() -> None:
    # Each AGENTS.md command is a whole command CI runs, ``--locked`` and
    # the ``uv sync`` interpreter pin aside. Prefix-matching let a planted
    # ``pytest -x tests/unit`` pass unseen, so the match is exact (N1).
    ci = {_normalize(line) for line in _ci_run_lines()}
    for command in _agents_commands():
        assert _normalize(command) in ci, command


def test_every_ci_check_is_listed_in_agents() -> None:
    # And the reverse: a check CI gains must be added to AGENTS.md too, again
    # as a whole command — one starting with an env assignment or
    # ``cd … &&`` matches nothing and fails here (N1).
    commands = {_normalize(c) for c in _agents_commands()}
    for line in _ci_run_lines():
        if line in CI_RUNNER_ONLY:
            continue
        assert _normalize(line) in commands, line


def test_a_python_flag_off_the_sync_line_fails_the_check() -> None:
    # The review planted ``uv run --locked --python 3.12 pytest`` in ci.yml
    # and it passed unseen: the normalisation stripped ``--python`` from
    # every command. Scoped to the sync pin, the drifted line matches
    # nothing AGENTS.md lists.
    commands = {_normalize(c) for c in _agents_commands()}
    assert _normalize("uv run --locked --python 3.12 pytest") not in commands


@pytest.mark.parametrize(
    "line",
    (
        'uv sync --locked --python "$(command -v python3)"',
        "uv sync --locked --python=3.11",
    ),
)
def test_a_changed_sync_interpreter_fails_the_check(line: str) -> None:
    # Same hole on the sync line itself: ``--python`` survives the
    # normalisation unless it spells the pinned interpreter exactly.
    commands = {_normalize(c) for c in _agents_commands()}
    assert _normalize(line) not in commands


def test_the_real_sync_line_still_reduces_to_uv_sync() -> None:
    # The one ``--python`` the normalisation legitimately drops: CI pins
    # ``$(command -v python)`` (the setup-python interpreter) where
    # AGENTS.md writes ``uv sync --locked``.
    sync = [line for line in _ci_run_lines() if line.startswith("uv sync")]
    assert sync, "ci.yml has no uv sync line"
    assert all(_normalize(line) == "uv sync" for line in sync), sync


def test_the_results_dir_command_is_a_command_not_a_comment() -> None:
    # #35: this line used to be commented out, so ``$dir`` stayed empty and
    # both checks below it validated nothing.
    assert "dir=$(ls -dt results/*-smoke | head -1)" in _agents_commands()


def test_the_smoke_gate_invocation_is_exact() -> None:
    # The expected alert count is stated once — the corpus gen's
    # ``--data-in-syn`` flag — and the gate derives it from the run record's
    # own truth file, so the invocation takes no count argument (#35). The
    # startswith mirror above cannot see a re-added argument: pin the whole
    # command, in the workflow and in AGENTS.md alike.
    expected = 'python3 tools/ci/check_smoke_result.py "$dir"'
    assert expected in _agents_commands()
    assert expected in _ci_run_lines()


#: A phrase from each operating rule that issue #3 requires.
RULES = [
    "No sudo for agents",
    "Never touch the production mmt-stack containers",
    "Results are append-only",
    "The private dgx-spark capture is never committed or published",
    "The repo is public",
    "Never commit host identifiers",
    "Tool-comparison reports stay out of git until reviewed",
]


@pytest.mark.parametrize("rule", RULES)
def test_agents_states_operating_rule(rule: str) -> None:
    assert rule in _read(AGENTS)


def test_agents_no_longer_says_the_repo_is_private() -> None:
    text = " ".join(_read(AGENTS).split())
    assert "The repo is private" not in text
    assert "licence and fairness review" in text


def test_gitignore_keeps_local_only_reports_out_of_git() -> None:
    lines = _read(ROOT / ".gitignore").splitlines()
    assert "local/" in lines


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


#: sha256 of the ``## B1.`` … ``## Decisions`` block of docs/design.md — a
#: verbatim copy of the plan, so an edit inside a section must be deliberate
#: and update this pin with it (N2). The heading-order check above cannot
#: see such an edit; the digest can.
DESIGN_B_SECTIONS_SHA256 = "8e7cc8af0da3c2633bfd471995c6d517e524ace4ad735abf8d99175747f8ff00"


def test_design_b_sections_are_verbatim() -> None:
    text = _read(DESIGN)
    start = text.index("## B1.")
    end = text.index("## Decisions")
    digest = hashlib.sha256(text[start:end].encode("utf-8")).hexdigest()
    assert digest == DESIGN_B_SECTIONS_SHA256, (
        "docs/design.md's B1-B10 sections changed — they are a verbatim copy "
        "of the plan; update the pin only when the change is deliberate"
    )


def test_design_decisions_lists_the_five_epic_decisions() -> None:
    text = _read(DESIGN)
    assert "\n## Decisions\n" in text, "design.md has no ## Decisions section"
    decisions = text.split("\n## Decisions\n", 1)[1]
    items = re.findall(r"^(\d+)\. ", decisions, re.MULTILINE)
    assert items == ["1", "2", "3", "4", "5"]
    for phrase in (
        'Was: "The repo stays private under montimage-projects for now."',
        "the repo is public",
        "stay out of git, local only, until they pass a licence and fairness review",
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
