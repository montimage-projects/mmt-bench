"""The CI workflow and its hash-pinned uv requirements file stay consistent."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UV_REQUIREMENTS = ROOT / ".github/uv-requirements.txt"
CI = ROOT / ".github/workflows/ci.yml"


def test_uv_requirements_regenerate_command_matches_its_trailer() -> None:
    # The documented command must be the one that produced the file: the
    # input file it compiles is the one the generated ``# via`` trailer names.
    text = UV_REQUIREMENTS.read_text(encoding="utf-8")
    command = re.search(r"^# Regenerate: .*?uv pip compile (\S+\.in) ", text, re.MULTILINE)
    assert command is not None, "no regenerate command in the header"
    written = re.search(r"> (\S+\.in) &&", command.group(0))
    assert written is not None and written.group(1) == command.group(1)
    assert re.findall(r"^\s+# via -r (\S+)$", text, re.MULTILINE) == [command.group(1)]


def test_ci_has_manual_trigger_and_read_only_token() -> None:
    text = CI.read_text(encoding="utf-8")
    on_block = text.split("\non:\n", 1)[1].split("\n\n", 1)[0]
    triggers = re.findall(r"^  (\w+):", on_block, re.MULTILINE)
    assert triggers == ["push", "pull_request", "workflow_dispatch"]
    assert "\npermissions:\n  contents: read\n\n" in text
