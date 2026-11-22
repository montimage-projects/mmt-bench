"""The R0/R0b/R-all ruleset semantics in the mmt-probe adapter (#10):

``security.enable = false`` for R0 (probe only), ``true`` with an empty
rules dir for R0b (the engine's fixed cost), and the empty-rules guard that
still catches a silently missing extraction for every other ruleset.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from test_mmt_probe import RecordingDocker

from mbench.adapters.base import Ruleset
from mbench.adapters.mmt_probe import MmtProbeAdapter, render_config


def _rules_dir(tmp_path: Path, names: list[str]) -> Path:
    directory = tmp_path / "rules"
    directory.mkdir()
    for name in names:
        (directory / name).write_bytes(b"\x7fELF fake rule")
    return directory


def test_the_config_can_switch_the_engine_off() -> None:
    off = render_config("recommended", security=False)
    on = render_config("recommended", security=True)
    # the security block's own switch, not another block's `enable` line
    assert "enable                  = false" in off
    assert "enable                  = true" in on
    # the rest of the config — the proven mmt-stack settings — is unchanged
    assert "ignore-remain-flow      = false" in off


def test_an_empty_ruleset_is_allowed_only_when_the_ruleset_says_so(
    tmp_path: Path,
) -> None:
    adapter = MmtProbeAdapter(
        "img@example.test/probe@" + "sha256:" + "ab" * 32,
        docker=RecordingDocker(),
    )
    empty = _rules_dir(tmp_path, [])

    r0 = Ruleset("r0", empty, security=False, allow_empty=True)
    written = adapter.prepare(r0, "recommended", tmp_path / "r0")
    conf = tmp_path / "r0" / "mmt-probe.conf"
    assert conf in written
    assert "enable                  = false" in conf.read_text(encoding="utf-8")

    r0b = Ruleset("r0b", empty, security=True, allow_empty=True)
    adapter.prepare(r0b, "recommended", tmp_path / "r0b")
    assert "enable                  = true" in (tmp_path / "r0b" / "mmt-probe.conf").read_text(
        encoding="utf-8"
    )


def test_a_silently_missing_extraction_still_fails(tmp_path: Path) -> None:
    """Planted fault: the rules dir is empty and the ruleset did not ask for it."""
    adapter = MmtProbeAdapter(
        "img@example.test/probe@" + "sha256:" + "ab" * 32,
        docker=RecordingDocker(),
    )
    empty = _rules_dir(tmp_path, [])
    with pytest.raises(FileNotFoundError, match=r"no \.so rule"):
        adapter.prepare(Ruleset("r-all", empty), "recommended", tmp_path / "r-all")


def test_r_all_stages_every_rule_and_keeps_the_engine_on(tmp_path: Path) -> None:
    adapter = MmtProbeAdapter(
        "img@example.test/probe@" + "sha256:" + "ab" * 32,
        docker=RecordingDocker(),
    )
    rules = _rules_dir(tmp_path, [f"rule-{i}.so" for i in range(3)])
    adapter.prepare(Ruleset("r-all", rules), "recommended", tmp_path / "w")
    staged = sorted((tmp_path / "w" / "mmt-rules").glob("*.so"))
    assert [p.name for p in staged] == [f"rule-{i}.so" for i in range(3)]
    assert "enable                  = true" in (tmp_path / "w" / "mmt-probe.conf").read_text(
        encoding="utf-8"
    )
