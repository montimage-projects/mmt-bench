"""The campaign file and its matrix expansion (#8).

``matrix.load`` reads a campaign YAML, validates it against
``schemas/campaign.schema.json`` (the same check ``mbench validate`` runs),
resolves every reference — rulesets, corpus labels through the manifest,
``{path, sha256}`` entries, ground truth — and expands the cartesian product
of the dimensions into one :class:`Cell` per run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from campaignfiles import campaign_doc, layout, make_pcap, manifest_entry, write_manifest
from fakeadapter import FakeAdapter

from mbench import adapters, matrix, pcap, sut


@pytest.fixture
def fake_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    """Register FakeAdapter as the ``fake`` tool for campaign validation."""
    monkeypatch.setitem(adapters.ADAPTERS, "fake", FakeAdapter)


def _load(
    parts: dict[str, Any], topology: dict[str, tuple[int, ...]] | None = None
) -> matrix.Campaign:
    return matrix.load(parts["campaign_path"], manifest_path=parts["manifest"], topology=topology)


def test_a_valid_campaign_loads(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}]))
    campaign = _load(parts)
    assert campaign.name == "test"  # the file stem when `name` is absent
    assert campaign.question == "does it keep up?"
    assert campaign.mode == "offline"
    assert len(campaign.cells) == 1


def test_the_cartesian_product_expands_in_dimension_order(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc(
        [{"label": "x"}, {"label": "y"}],
        tools=["fake", "fake"],
        rulesets=["rs", "rs2"],
        config_profiles=["recommended", "tuned"],
        threads=[1, 4],
        cpusets=["0-3"],
    )
    parts = layout(tmp_path, doc)
    campaign = _load(parts)
    # 2 tools x 2 rulesets x 2 profiles x 2 corpus x 2 threads x 1 cpuset
    assert len(campaign.cells) == 32
    # deterministic: the same load twice is the same list, and index is stable
    again = _load(parts)
    assert [c.index for c in campaign.cells] == list(range(32))
    assert [
        (c.tool, c.ruleset.id, c.config_profile, c.corpus.label, c.threads) for c in campaign.cells
    ] == [(c.tool, c.ruleset.id, c.config_profile, c.corpus.label, c.threads) for c in again.cells]


def test_cpuset_is_parsed_and_its_string_kept(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["0,2-3"])
    campaign = _load(layout(tmp_path, doc))
    cell = campaign.cells[0]
    assert cell.cpuset == (0, 2, 3)
    assert cell.cpuset_str == "0,2-3"


def test_the_empty_cpuset_is_unpinned(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=[""])
    campaign = _load(layout(tmp_path, doc))
    assert campaign.cells[0].cpuset == ()
    assert campaign.cells[0].cpuset_str == ""


def test_default_config_profile(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}])
    doc.pop("config_profiles", None)
    campaign = _load(layout(tmp_path, doc))
    assert campaign.cells[0].config_profile == "recommended"


def test_name_field_overrides_the_stem(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], name="p0-throughput")
    campaign = _load(layout(tmp_path, doc, name="whatever"))
    assert campaign.name == "p0-throughput"


def test_label_resolves_through_the_manifest(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}]))
    campaign = _load(parts)
    ref = campaign.cells[0].corpus
    path = parts["pcaps"]["x"]
    assert ref.path == path
    assert ref.sha256 == pcap.stats(path).sha256
    assert ref.ref["label"] == "x"
    # a non-local entry shows its public fields — but never a host path
    assert ref.ref["local_only"] is False
    assert str(path) not in repr(ref.ref)


def test_an_unknown_label_is_an_error(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}]))
    # plant the fault in a scratch copy: the label the manifest does not have
    path = Path(parts["campaign_path"])
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["corpus"] = [{"label": "nope"}]
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(matrix.CampaignError) as exc:
        _load(parts)
    assert any("no manifest entry" in p and "nope" in p for p in exc.value.problems)


def test_a_path_corpus_entry_needs_no_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(adapters.ADAPTERS, "fake", FakeAdapter)
    capture = make_pcap(tmp_path, "capture.pcap")
    sha = pcap.stats(capture).sha256
    doc = campaign_doc(
        [{"path": "capture.pcap", "sha256": sha}], rulesets=[{"id": "rs", "path": "rs.so"}]
    )
    root = tmp_path / "root"
    (root / "campaigns").mkdir(parents=True)
    # a {id, path} ruleset resolves its path against the campaign anchor
    (root / "rs.so").write_bytes(b"rules")
    (root / "capture.pcap").write_bytes(capture.read_bytes())
    path = root / "campaigns" / "c.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    # no manifest at all: the default does not exist under cwd here
    campaign = matrix.load(path, manifest_path=root / "corpus" / "manifest.yaml")
    ref = campaign.cells[0].corpus
    assert ref.sha256 == sha
    assert str(root) not in repr(ref.ref)  # the private path stays out of results
    # a path-pinned capture is the private-capture case: label and sha256 only
    assert ref.ref == {"label": "capture", "sha256": sha, "local_only": True}


def test_a_sha_mismatch_is_an_error(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}]))
    capture = Path(parts["pcaps"]["x"])
    # plant the fault: a valid but different pcap under the pinned sha256
    make_pcap(capture.parent, capture.name, packets=64)
    with pytest.raises(matrix.CampaignError) as exc:
        _load(parts)
    assert any("sha256" in p for p in exc.value.problems)


def test_a_missing_ruleset_is_an_error(tmp_path: Path, fake_tool: None) -> None:
    parts = layout(tmp_path, campaign_doc([{"label": "x"}]))
    (parts["root"] / "rulesets" / "rs.so").unlink()
    with pytest.raises(matrix.CampaignError, match="ruleset"):
        _load(parts)


def test_ground_truth_loads_and_is_checked_against_the_pcap(
    tmp_path: Path, fake_tool: None
) -> None:
    root = tmp_path / "root"
    (root / "campaigns").mkdir(parents=True)
    (root / "rulesets").mkdir()
    (root / "corpus" / "data").mkdir(parents=True)
    (root / "rulesets" / "rs.so").write_bytes(b"rules")
    capture = make_pcap(root / "corpus" / "data", "x.pcap")
    sha = pcap.stats(capture).sha256
    truth_file = root / "corpus" / "x.truth.json"
    truth_file.write_text(
        json.dumps({"schema_version": 1, "pcap_sha256": sha, "attacks": []}),
        encoding="utf-8",
    )
    manifest = write_manifest(
        root / "corpus",
        [manifest_entry("x", capture, root / "corpus") | {"ground_truth": "x.truth.json"}],
    )
    doc = campaign_doc([{"label": "x"}])
    path = root / "campaigns" / "c.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    campaign = matrix.load(path, manifest_path=manifest)
    assert campaign.cells[0].corpus.truth is not None
    assert campaign.cells[0].corpus.truth.pcap_sha256 == sha


def test_ground_truth_for_another_pcap_is_an_error(tmp_path: Path, fake_tool: None) -> None:
    root = tmp_path / "root"
    (root / "campaigns").mkdir(parents=True)
    (root / "rulesets").mkdir()
    (root / "corpus" / "data").mkdir(parents=True)
    (root / "rulesets" / "rs.so").write_bytes(b"rules")
    capture = make_pcap(root / "corpus" / "data", "x.pcap")
    truth_file = root / "corpus" / "x.truth.json"
    truth_file.write_text(
        json.dumps({"schema_version": 1, "pcap_sha256": "0" * 64, "attacks": []}),
        encoding="utf-8",
    )
    manifest = write_manifest(
        root / "corpus",
        [manifest_entry("x", capture, root / "corpus") | {"ground_truth": "x.truth.json"}],
    )
    path = root / "campaigns" / "c.yaml"
    path.write_text(yaml.safe_dump(campaign_doc([{"label": "x"}])), encoding="utf-8")
    with pytest.raises(matrix.CampaignError, match="ground truth"):
        matrix.load(path, manifest_path=manifest)


def test_an_invalid_campaign_fails_before_any_resolution(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}])
    del doc["question"]
    parts = layout(tmp_path, doc)
    with pytest.raises(matrix.CampaignError) as exc:
        _load(parts)
    assert any("question" in p for p in exc.value.problems)


def test_an_unknown_tool_is_an_error(tmp_path: Path) -> None:
    doc = campaign_doc([{"label": "x"}], tools=["suricata"])
    parts = layout(tmp_path, doc)
    with pytest.raises(matrix.CampaignError) as exc:
        _load(parts)
    assert any("no adapter" in p for p in exc.value.problems)


def test_cpusets_must_be_valid_cpulists(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["bogus"])
    parts = layout(tmp_path, doc)
    with pytest.raises(matrix.CampaignError):
        _load(parts)


@pytest.mark.parametrize("cpuset", ["5-2", "0,5-2", "9-8"])
def test_a_descending_cpuset_is_an_error(cpuset: str, tmp_path: Path, fake_tool: None) -> None:
    # "5-2" parses to nothing: it would run unpinned while recording a
    # cpuset — a mislabelled measurement, so it is rejected (review L4).
    doc = campaign_doc([{"label": "x"}], cpusets=[cpuset])
    parts = layout(tmp_path, doc)
    with pytest.raises(matrix.CampaignError) as exc:
        _load(parts)
    assert any("cpusets[0]" in p for p in exc.value.problems)


def test_an_edge_cpuset_still_loads(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}], cpusets=["5-5", "0-3,8"])
    campaign = _load(layout(tmp_path, doc))
    assert [c.cpuset for c in campaign.cells] == [(5,), (0, 1, 2, 3, 8)]


def test_parse_cpulist_roundtrip() -> None:
    assert sut.parse_cpulist("0-3,8") == [0, 1, 2, 3, 8]


# --- the verdict cell (review M2) ------------------------------------------------


def test_a_verdict_cell_loads_and_resolves_its_cpuset(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc(
        [{"label": "x"}],
        threads=[1, 8],
        cpusets=["core:x925"],
        verdict_cell={"ruleset": "rs", "corpus": "x", "threads": 1, "cpuset": "core:x925"},
    )
    parts = layout(tmp_path, doc)
    campaign = _load(parts, topology={"Cortex-X925": (5, 6, 7, 8, 9, 15, 16, 17, 18, 19)})
    assert campaign.verdict_cell == {
        "ruleset": "rs",
        "corpus": "x",
        "threads": 1,
        "cpuset": "5-9,15-19",
    }
    assert campaign.meta()["verdict_cell"]["threads"] == 1


def test_a_verdict_cell_naming_no_cell_is_an_error(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc(
        [{"label": "x"}],
        threads=[1],
        verdict_cell={"threads": 4},
    )
    parts = layout(tmp_path, doc)
    with pytest.raises(matrix.CampaignError, match="no matrix cell matches"):
        _load(parts)


def test_no_verdict_cell_means_the_fastest_default(tmp_path: Path, fake_tool: None) -> None:
    doc = campaign_doc([{"label": "x"}])
    parts = layout(tmp_path, doc)
    assert _load(parts).verdict_cell is None


def test_the_committed_p1_synthetic_loads_on_a_two_type_host() -> None:
    # M9: the dry-run campaign loads through matrix.load. Its core:<type>@n
    # selectors resolve against the host at run time — here a stub two-type
    # topology stands in for the SUT.
    topology = {
        "Cortex-A725": tuple(range(0, 10)),
        "Cortex-X925": tuple(range(10, 20)),
    }
    campaign = matrix.load(
        Path(__file__).parent.parent / "campaigns" / "p1-synthetic.yaml",
        topology=topology,
    )
    # r0/r0b at t0 + r-all at t1/t2 on each of 2 corpora and 2 series = 16
    assert len(campaign.cells) == 16
    assert [cell.index for cell in campaign.cells] == list(range(16))
    assert {cell.cpuset for cell in campaign.cells if cell.threads == 1} == {(0,), (10,)}
