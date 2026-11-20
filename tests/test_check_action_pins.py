"""tools/ci/check_action_pins.py: SHA-pinned GitHub-owned actions pass.

The cases below are common mistakes and the escaped and explicit-key forms the
line scan reports. They are not every YAML spelling of ``uses``: GitHub's own
action policy is the enforcement.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from check_action_pins import DEFAULT_DIR, check_text, main

ROOT = Path(__file__).resolve().parent.parent
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def wf(*uses: str) -> str:
    steps = "\n".join(f"      - uses: {u}" for u in uses)
    return f"jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n{steps}\n"


@pytest.mark.parametrize(
    "ref",
    [
        f"actions/checkout@{SHA}",
        f"actions/checkout@{SHA} # v7.0.1",
        f"'actions/setup-python@{SHA}'",
        f'"actions/cache/restore@{SHA}"',
    ],
)
def test_pinned_github_owned_action_passes(ref: str) -> None:
    assert check_text(wf(ref)) == []


@pytest.mark.parametrize(
    "ref",
    [
        "actions/checkout@v4",  # tag
        "actions/checkout@main",  # branch
        "actions/checkout@3d3c42e",  # short SHA
        f"actions/checkout@{SHA.upper()}",  # not lowercase hex
        f"actions/checkout@{SHA}0",  # 41 hex
        "actions/checkout",  # no ref
        f"astral-sh/setup-uv@{SHA}",  # third-party owner
        f"actions-x/checkout@{SHA}",  # look-alike owner
        f"evil/actions/checkout@{SHA}",  # owner is not actions
        "docker://alpine:3.20",  # container image
        "./.github/actions/local",  # local action
    ],
)
def test_unpinned_or_foreign_action_fails(ref: str) -> None:
    errors = check_text(wf(ref), "ci.yml")
    assert len(errors) == 1
    assert errors[0].startswith("ci.yml:5:")


def test_reusable_workflow_job_is_checked() -> None:
    text = "jobs:\n  call:\n    uses: octo/repo/.github/workflows/x.yml@main\n"
    assert len(check_text(text)) == 1


@pytest.mark.parametrize(
    "line",
    [
        "      - {name: x, uses: foo/bar@main}",  # flow mapping, bad ref
        f"      - {{uses: actions/checkout@{SHA}}}",  # flow mapping, even when pinned
        '      - "uses": foo/bar@main',  # quoted key
        "      - uses : foo/bar@main",  # space before the colon
        "        uses: foo/bar@main",  # key not on the list-item line
    ],
)
def test_unusual_yaml_shapes_are_errors(line: str) -> None:
    assert len(check_text(f"    steps:\n{line}\n")) == 1


@pytest.mark.parametrize(
    "text",
    [
        '      - "\\x75ses": evil/x@main\n',  # escaped double-quoted key spelling uses
        '      - "u\\u0073es": evil/x@main\n',  # \\u escape
        '      - "\\U00000075ses": evil/x@main\n',  # \\U escape
        '      - {"\\x75ses": evil/x@main}\n',  # escaped key in a flow mapping
        "      - ? uses\n        : evil/x@main\n",  # explicit complex key
        "    ? uses\n    : evil/x@main\n",  # explicit key, not a list item
    ],
)
def test_tested_unreadable_key_forms_are_errors(text: str) -> None:
    errors = check_text(text, "ci.yml")
    assert len(errors) == 1
    assert errors[0].startswith("ci.yml:1:")


def test_unreadable_key_fails_main_even_with_no_plain_uses(tmp_path: Path) -> None:
    (tmp_path / "x.yml").write_text('      - "\\x75ses": evil/x@main\n', encoding="utf-8")
    assert main([str(tmp_path)]) == 1


def test_quoted_key_with_pinned_ref_passes() -> None:
    assert check_text(f'      - "uses": actions/checkout@{SHA}\n') == []


def test_comment_lines_are_ignored() -> None:
    assert check_text("      # - uses: actions/checkout@v4\n") == []


def test_every_bad_line_is_reported() -> None:
    errors = check_text(wf("actions/checkout@v4", f"actions/setup-python@{SHA}", "x/y@v1"))
    assert [e.split(":")[1] for e in errors] == ["5", "7"]


def test_main_exit_codes(tmp_path: Path) -> None:
    assert main([str(tmp_path / "missing")]) == 2  # no such directory
    assert main([str(tmp_path)]) == 2  # no workflow files
    (tmp_path / "run-only.yml").write_text("jobs: {}\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 2  # nothing checked: exit 2, not a silent pass
    (tmp_path / "ok.yml").write_text(wf(f"actions/checkout@{SHA}"), encoding="utf-8")
    assert main([str(tmp_path)]) == 0
    (tmp_path / "bad.yaml").write_text(wf("actions/checkout@v4"), encoding="utf-8")
    assert main([str(tmp_path)]) == 1


def test_default_dir_is_found_from_the_script_not_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert DEFAULT_DIR == ROOT / ".github" / "workflows"
    monkeypatch.chdir(tmp_path)
    assert main([]) == 0


def test_repo_workflows_are_pinned() -> None:
    # Regression guard: fails as soon as a workflow gains an unpinned action.
    assert main([str(ROOT / ".github/workflows")]) == 0
