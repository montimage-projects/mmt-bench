"""The ``rulesets/`` definitions (#10): the schema, matrix resolution, the
expected-rule-count check, and the security.enable/allow_empty flags.

The committed definitions (``r0``, ``r0b``, ``r-all``) are validated
against the schema; a scratch copy with a planted fault (the wrong rule
count, a missing ``kind``) must fail — the negative acceptance criteria.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from campaignfiles import campaign_doc, layout
from fakeadapter import FakeAdapter

from mbench import adapters, matrix, validate

REPO = Path(__file__).resolve().parent.parent
RULESETS = REPO / "rulesets"


@pytest.fixture
def fake_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(adapters.ADAPTERS, "fake", FakeAdapter)


def _ruleset_def(tmp_path: Path, **overrides: Any) -> Path:
    """A ruleset def file in a scratch ``rulesets/`` dir; returns its path."""
    directory = tmp_path / "rulesets"
    directory.mkdir(parents=True, exist_ok=True)
    doc: dict[str, Any] = {
        "schema_version": 1,
        "kind": "ruleset",
        "tool": "mmt-probe",
        "rules": "rulesets/rs.so",
        "security": {"enable": True},
    }
    doc.update(overrides)
    path = directory / "rs.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


# --- the committed definitions ---------------------------------------------------


def test_the_committed_definitions_validate() -> None:
    for name in ("r0", "r0b", "r-all"):
        report = validate.validate_file(RULESETS / f"{name}.yaml")
        assert report.errors == [], f"{name}: {report.errors}"
        assert report.kind == "ruleset"


def test_r0_disables_security_and_r0b_keeps_the_engine() -> None:
    r0 = yaml.safe_load((RULESETS / "r0.yaml").read_text(encoding="utf-8"))
    r0b = yaml.safe_load((RULESETS / "r0b.yaml").read_text(encoding="utf-8"))
    assert r0["security"]["enable"] is False and r0["allow_empty"] is True
    assert r0b["security"]["enable"] is True and r0b["allow_empty"] is True


def test_r_all_expects_94_rules_and_documents_why() -> None:
    text = (RULESETS / "r-all.yaml").read_text(encoding="utf-8")
    definition = yaml.safe_load(text)
    assert definition["provenance"]["expect_rules"] == 94
    assert "206 and 212" in text  # the two rules the pinned fork disabled
    assert "sha256" in definition["provenance"]["source"]


# --- the schema --------------------------------------------------------------------


def test_a_definition_without_kind_fails(tmp_path: Path) -> None:
    path = _ruleset_def(tmp_path)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    del doc["kind"]
    assert validate.ruleset_errors(doc)


def test_an_unknown_field_fails() -> None:
    doc: dict[str, Any] = {
        "schema_version": 1,
        "kind": "ruleset",
        "tool": "mmt-probe",
        "rules": "rulesets/rs.so",
        "security": {"enable": True},
        "bogus": True,
    }
    errors = validate.ruleset_errors(doc)
    assert any("bogus" in e for e in errors)


def test_an_expect_rules_string_fails() -> None:
    doc: dict[str, Any] = {
        "schema_version": 1,
        "kind": "ruleset",
        "tool": "mmt-probe",
        "rules": "rulesets/rs.so",
        "security": {"enable": True},
        "provenance": {"expect_rules": "94"},
    }
    assert validate.ruleset_errors(doc)


# --- matrix.load resolution ------------------------------------------------------


def test_a_definition_resolves_security_and_allow_empty(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}]))
    rules_dir = parts["root"] / "rulesets" / "rs-rules"
    rules_dir.mkdir()
    definition = {
        "schema_version": 1,
        "kind": "ruleset",
        "tool": "fake",
        "rules": "rulesets/rs-rules",
        "security": {"enable": False},
        "allow_empty": True,
        "provenance": {"expect_rules": 0},
    }
    (parts["root"] / "rulesets" / "rs.yaml").write_text(
        yaml.safe_dump(definition), encoding="utf-8"
    )
    campaign = matrix.load(parts["campaign_path"], manifest_path=parts["manifest"])
    ruleset = campaign.cells[0].ruleset
    assert ruleset.security is False and ruleset.allow_empty is True


def test_a_wrong_extracted_count_is_a_campaign_error(tmp_path: Path, fake_tool: None) -> None:
    """Planted fault: the definition says 3 rules, the dir holds 1."""
    parts = layout(tmp_path, campaign_doc([{"label": "x"}]))
    rules_dir = parts["root"] / "rulesets" / "rs-rules"
    rules_dir.mkdir()
    (rules_dir / "only.so").write_bytes(b"\x7fELF")
    definition = {
        "schema_version": 1,
        "kind": "ruleset",
        "tool": "fake",
        "rules": "rulesets/rs-rules",
        "security": {"enable": True},
        "provenance": {"expect_rules": 3},
    }
    (parts["root"] / "rulesets" / "rs.yaml").write_text(
        yaml.safe_dump(definition), encoding="utf-8"
    )
    with pytest.raises(matrix.CampaignError, match=r"1 \.so rules"):
        matrix.load(parts["campaign_path"], manifest_path=parts["manifest"])


def test_a_missing_rules_path_names_the_extract_command(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}]))
    definition = {
        "schema_version": 1,
        "kind": "ruleset",
        "tool": "fake",
        "rules": "rulesets/not-there",
        "security": {"enable": True},
        "provenance": {"extract": "tools/docker/mmt-probe/extract-rules.sh"},
    }
    (parts["root"] / "rulesets" / "rs.yaml").write_text(
        yaml.safe_dump(definition), encoding="utf-8"
    )
    with pytest.raises(matrix.CampaignError, match=r"extract-rules\.sh"):
        matrix.load(parts["campaign_path"], manifest_path=parts["manifest"])


def test_an_invalid_definition_fails_with_its_problems(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}]))
    (parts["root"] / "rulesets" / "rs.yaml").write_text(
        yaml.safe_dump({"kind": "ruleset", "tool": "fake"}), encoding="utf-8"
    )
    with pytest.raises(matrix.CampaignError) as excinfo:
        matrix.load(parts["campaign_path"], manifest_path=parts["manifest"])
    assert excinfo.value.problems  # every schema problem is carried


# --- core: selectors ---------------------------------------------------------------


TOPOLOGY: dict[str, tuple[int, ...]] = {
    "Cortex-A725": (0, 1, 2, 3),
    "Cortex-X925": (4, 5, 6, 7),
}


def test_a_core_selector_resolves_to_a_cpulist(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["core:x925"])
    parts = layout(tmp_path, doc)
    campaign = matrix.load(
        parts["campaign_path"], manifest_path=parts["manifest"], topology=TOPOLOGY
    )
    cell = campaign.cells[0]
    assert cell.cpuset == (4, 5, 6, 7)
    assert cell.cpuset_str == "4-7"


def test_an_unmatched_selector_is_a_campaign_error(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["core:i9"])
    parts = layout(tmp_path, doc)
    with pytest.raises(matrix.CampaignError, match="no core type"):
        matrix.load(parts["campaign_path"], manifest_path=parts["manifest"], topology=TOPOLOGY)


def test_an_ambiguous_selector_is_a_campaign_error(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["core:cortex"])
    parts = layout(tmp_path, doc)
    with pytest.raises(matrix.CampaignError, match="ambiguous"):
        matrix.load(parts["campaign_path"], manifest_path=parts["manifest"], topology=TOPOLOGY)


def test_perf_in_the_campaign_meta(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], perf=True)
    parts = layout(tmp_path, doc)
    campaign = matrix.load(parts["campaign_path"], manifest_path=parts["manifest"])
    assert campaign.perf is True
    assert campaign.meta()["perf"] is True
