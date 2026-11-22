"""Files a campaign needs in tests: a generated pcap, a ruleset, a manifest.

``layout`` builds a miniature repo tree so campaigns/, rulesets/ and the
corpus manifest resolve the way a real checkout resolves them:

    root/
        campaigns/<name>.yaml
        rulesets/<id>.so
        corpus/manifest.yaml
        corpus/data/<label>.pcap
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import yaml

from mbench import corpus, pcap


def make_pcap(directory: Path, name: str, packets: int = 200) -> Path:
    """A small deterministic synthetic pcap."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    spec = corpus.SETS["c-small"]
    corpus.generate(spec, 0, packets, min(8, packets), path)
    return path


def write_truth(path: Path, pcap_sha256: str, attacks: list[dict[str, Any]] | None = None) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pcap_sha256": pcap_sha256,
                "tolerance_s": 1.0,
                "attacks": attacks or [],
            }
        ),
        encoding="utf-8",
    )
    return path


def write_manifest(directory: Path, entries: list[dict[str, Any]]) -> Path:
    """A corpus manifest inside ``directory`` (e.g. ``root/corpus/``)."""
    directory.mkdir(parents=True, exist_ok=True)
    manifest = directory / "manifest.yaml"
    manifest.write_text(yaml.safe_dump({"schema_version": 1, "entries": entries}), encoding="utf-8")
    return manifest


def manifest_entry(label: str, path: Path, manifest_dir: Path) -> dict[str, Any]:
    """A manifest entry for a real pcap, path relative to the manifest dir."""
    st = pcap.stats(path)
    return {
        "label": label,
        "path": str(path.relative_to(manifest_dir)),
        "sha256": st.sha256,
        "size_bytes": st.size_bytes,
        "packets": st.packets,
        "avg_packet_bytes": st.avg_packet_bytes,
        "source": "synthetic test capture",
        "licence": "CC0-1.0",
        "ground_truth": None,
        "local_only": False,
    }


def layout(tmp_path: Path, campaign: dict[str, Any], name: str = "test") -> dict[str, Any]:
    """Build the mini repo tree and write the campaign; return its parts.

    Returns ``{root, campaign_path, manifest, pcaps}``: ``pcaps`` maps the
    label of every generated capture to its path under ``corpus/data/``.
    """
    root = tmp_path / "root"
    campaigns_dir = root / "campaigns"
    rulesets_dir = root / "rulesets"
    manifest_dir = root / "corpus"
    for d in (campaigns_dir, rulesets_dir, manifest_dir / "data"):
        d.mkdir(parents=True, exist_ok=True)

    entries = []
    pcaps: dict[str, Path] = {}
    for item in campaign.get("corpus", []):
        if "label" not in item:
            continue
        label = item["label"]
        path = pcaps.get(label) or make_pcap(manifest_dir / "data", f"{label}.pcap")
        pcaps[label] = path
        entries.append(manifest_entry(label, path, manifest_dir))
    manifest = write_manifest(manifest_dir, entries)

    for ruleset in campaign.get("rulesets", []):
        ruleset_path = rulesets_dir / f"{ruleset}.so"
        if not ruleset_path.exists():
            ruleset_path.write_bytes(b"\x7fELF fake ruleset " + ruleset.encode())

    campaign_path = campaigns_dir / f"{name}.yaml"
    campaign_path.write_text(yaml.safe_dump(campaign), encoding="utf-8")
    return {"root": root, "campaign_path": campaign_path, "manifest": manifest, "pcaps": pcaps}


def campaign_doc(corpus_items: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    """A minimal valid campaign, overridable field by field."""
    doc: dict[str, Any] = {
        "schema_version": 1,
        "question": "does it keep up?",
        "tools": ["fake"],
        "mode": "offline",
        "rulesets": ["rs"],
        "corpus": corpus_items,
        "threads": [1],
        "cpusets": [""],
        "repeats": 2,
        "timeout_s": 30,
    }
    doc.update(overrides)
    return doc


def copy_fixture_tree(src: Path, dst: Path) -> None:
    """Copy a layout tree for the scratch-copy fault-planting tests."""
    shutil.copytree(src, dst)
