"""The committed 10-s smoke campaign ``campaigns/smoke.yaml`` (#9).

It is the CI pipeline check: mmt-probe offline, one question, on the
deterministic ``smoke`` corpus entry (``mbench corpus gen``, seed fixed).
These tests pin the file's shape so a later campaign edit cannot silently
grow it past the budget or reach for a capture that must never be committed;
the smoke CI job runs the campaign itself.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from mbench import corpus, validate

ROOT = Path(__file__).resolve().parent.parent
SMOKE = ROOT / "campaigns" / "smoke.yaml"
MANIFEST = ROOT / "corpus" / "manifest.yaml"


@pytest.fixture
def doc() -> dict[str, Any]:
    data = yaml.safe_load(SMOKE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_the_file_is_a_valid_campaign(doc: dict[str, Any]) -> None:
    assert validate.campaign_errors(doc, manifest_path=MANIFEST) == []


def test_one_question(doc: dict[str, Any]) -> None:
    assert isinstance(doc["question"], str) and doc["question"].strip()


def test_one_offline_mmt_probe_cell(doc: dict[str, Any]) -> None:
    assert doc["mode"] == "offline"
    assert doc["tools"] == ["mmt-probe"]
    # One matrix cell: every dimension has exactly one value.
    for dim in ("tools", "rulesets", "corpus", "threads", "cpusets"):
        assert len(doc[dim]) == 1, dim
    profiles = doc.get("config_profiles") or ["recommended"]
    assert len(profiles) == 1


def test_measured_time_is_capped(doc: dict[str, Any]) -> None:
    assert doc["timeout_s"] <= 10
    # The warm-up is one pass and the measured passes stay few: a smoke run
    # is seconds of measurement, never a benchmark.
    assert doc["repeats"] <= 3


def test_no_quiet_host(doc: dict[str, Any]) -> None:
    assert doc.get("quiet_host") in (None, False)


def test_the_corpus_is_the_generated_smoke_entry(doc: dict[str, Any]) -> None:
    (item,) = doc["corpus"]
    # A label, never a {path, sha256} pair: nothing is fetched and the
    # private capture is never referenced.
    assert item == {"label": "smoke"}
    manifest = corpus.load(MANIFEST)
    entry = corpus.find_entry(manifest, "smoke")
    assert entry is not None
    # Not local_only: the private capture is the local_only kind, and the
    # smoke run must work on a fresh checkout.
    assert entry["local_only"] is False
    # Under the git-ignored corpus/data/: generated on each host, never
    # committed (tools/ci/check_no_captures.py enforces it).
    assert entry["path"] == "data/smoke.pcap"
    assert re.fullmatch(r"[0-9a-f]{64}", str(entry["sha256"]))
    # A generator block means deterministic bytes; the fixed seed is what
    # makes the same pcap on every host.
    assert isinstance(entry["generator"].get("seed"), int)
    # The detection gate's truth: `--data-in-syn` writes the leading TCP
    # SYN-with-payload packets (the rule-13 trigger) and their ground truth
    # data/smoke.truth.json, one attack per packet.
    assert entry["generator"]["data_in_syn"] == 4
    assert entry["ground_truth"] == "data/smoke.truth.json"
    assert "--data-in-syn 4" in str(entry["source"])


def test_the_ruleset_is_one_rule_under_git_ignored_local(doc: dict[str, Any]) -> None:
    (ruleset,) = doc["rulesets"]
    # A {id, path} ruleset: the compiled .so is a build artefact copied out
    # of the pinned image by tools/docker/mmt-probe/extract-rules.sh into
    # the git-ignored local/, so it is never committed. One rule, not the
    # image's whole set: all of them cost more than the 10-s budget.
    assert set(ruleset) == {"id", "path"}
    path = str(ruleset["path"])
    assert path.startswith("local/") and path.endswith(".so")
    # Rule 13 is the one the smoke capture's SYN-with-payload packets and
    # their generated truth file are built for.
    assert path.endswith("datainSYN.so")
