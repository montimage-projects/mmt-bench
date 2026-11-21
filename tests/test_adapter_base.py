"""The Adapter interface, the normalised Alert model and the tools record (#5)."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from fakeadapter import FakeAdapter, FakeProcess
from sutfixtures import GOLDEN

from mbench import sut, validate
from mbench.adapters import base
from mbench.adapters.base import (
    Adapter,
    Alert,
    Counters,
    ImageRef,
    InvalidValue,
    ProcessHandle,
    RuleInfo,
    Ruleset,
    config_record,
    tools_record_errors,
    tree_sha256,
)

#: Plan §B3, plus the tools-under-test record of §B4.
B3_MEMBERS = {
    "name",
    "version",
    "image",
    "prepare",
    "run_offline",
    "run_online",
    "counters",
    "alerts",
    "rule_inventory",
    "tools_record",
}


def _alert(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "ts": 1489508972.695759,
        "rule_id": "10",
        "category": "attack",
        "src": "192.0.2.20",
        "dst": "198.51.100.102",
        "proto": "tcp",
    }
    data.update(overrides)
    return data


@pytest.fixture
def ruleset(tmp_path: Path) -> Ruleset:
    rules = tmp_path / "rulesets" / "r-fake"
    rules.mkdir(parents=True)
    (rules / "a.rules").write_text("rule a\n", encoding="utf-8")
    (rules / "b.rules").write_text("rule b\n", encoding="utf-8")
    return Ruleset("r-fake", rules)


@pytest.fixture
def prepared(tmp_path: Path, ruleset: Ruleset) -> FakeAdapter:
    adapter = FakeAdapter()
    adapter.prepare(ruleset, "recommended", tmp_path / "work")
    return adapter


# --- The interface ------------------------------------------------------------


def test_adapter_declares_every_b3_member_as_abstract() -> None:
    assert set(Adapter.__abstractmethods__) == B3_MEMBERS


@pytest.mark.parametrize("missing", sorted(B3_MEMBERS))
def test_a_subclass_missing_one_member_cannot_be_instantiated(missing: str) -> None:
    namespace = {member: getattr(FakeAdapter, member) for member in B3_MEMBERS if member != missing}
    Partial = type("Partial", (Adapter,), namespace)
    with pytest.raises(TypeError, match=missing):
        Partial()


def test_the_fake_adapter_implements_the_full_interface() -> None:
    adapter = FakeAdapter()
    assert isinstance(adapter, Adapter)
    assert not inspect.isabstract(FakeAdapter)


def test_member_signatures_follow_b3() -> None:
    params = {
        "prepare": ["self", "ruleset", "config_profile", "workdir"],
        "run_offline": ["self", "pcap", "threads", "cpuset"],
        "run_online": ["self", "iface", "threads", "cpuset"],
        "rule_inventory": ["self", "ruleset"],
    }
    for member, expected in params.items():
        assert list(inspect.signature(getattr(Adapter, member)).parameters) == expected


def test_fake_run_offline_returns_a_process_handle(prepared: FakeAdapter, tmp_path: Path) -> None:
    handle = prepared.run_offline(tmp_path / "c-small.pcap", 2, [0, 1])
    assert isinstance(handle, ProcessHandle)
    assert handle.wait(timeout=10) == 0
    assert prepared.calls[0].mode == "offline"
    assert prepared.calls[0].cpuset == (0, 1)


def test_a_popen_is_a_process_handle() -> None:
    proc = subprocess.Popen(["true"])
    try:
        assert isinstance(proc, ProcessHandle)
    finally:
        proc.wait()


def test_fake_handle_times_out_like_popen() -> None:
    handle = FakeProcess(duration_s=30)
    with pytest.raises(subprocess.TimeoutExpired):
        handle.wait(timeout=1)
    handle.kill()
    assert handle.wait(timeout=1) == -9


def test_run_before_prepare_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="prepare"):
        FakeAdapter().run_offline(tmp_path / "x.pcap", 1, [0])


# --- The normalised alert -------------------------------------------------------


def test_a_valid_alert_round_trips() -> None:
    alert = Alert.from_dict(_alert())
    assert alert.to_dict() == _alert()
    assert Alert.from_dict(json.loads(json.dumps(alert.to_dict()))) == alert


def test_alert_values_are_canonicalised() -> None:
    alert = Alert(ts=5, rule_id="sid:1", category="scan", src="2001:DB8::1", dst="::1", proto="TCP")
    assert alert.ts == 5.0
    assert isinstance(alert.ts, float)
    assert alert.src == "2001:db8::1"
    assert alert.proto == "tcp"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ts", -1),
        ("ts", float("nan")),
        ("ts", float("inf")),
        ("ts", "1489508972"),
        ("ts", True),
        ("rule_id", ""),
        ("rule_id", " 10"),
        ("rule_id", 10),
        ("category", ""),
        ("category", None),
        ("src", "192.0.2.300"),
        ("src", "host.example"),
        ("src", "192.0.2.0/24"),
        ("dst", ""),
        ("dst", 3232235622),
        ("proto", ""),
        ("proto", "6"),
        ("proto", "tcp udp"),
        ("proto", None),
    ],
)
def test_an_invalid_alert_value_is_rejected(field: str, value: object) -> None:
    with pytest.raises(InvalidValue, match=f"^{field}:"):
        Alert.from_dict(_alert(**{field: value}))


def test_an_alert_with_a_missing_or_unknown_field_is_rejected() -> None:
    data = _alert()
    del data["proto"]
    with pytest.raises(InvalidValue, match="missing field: proto"):
        Alert.from_dict(data)
    with pytest.raises(InvalidValue, match="unknown field: sport"):
        Alert.from_dict(_alert(sport=80))


def test_an_alert_is_immutable() -> None:
    alert = Alert.from_dict(_alert())
    with pytest.raises(AttributeError):
        alert.ts = 0.0  # type: ignore[misc]


# --- Counters and rules ----------------------------------------------------------


def test_counters_reject_negative_or_non_integer_counts() -> None:
    assert Counters(10, 640, 0, {"flows": 3}).to_dict() == {
        "packets": 10,
        "bytes": 640,
        "drops": 0,
        "flows": 3,
    }
    for bad in (-1, 1.5, True):
        with pytest.raises(InvalidValue):
            Counters(bad, 0, 0)  # type: ignore[arg-type]
    with pytest.raises(InvalidValue, match="shadows"):
        Counters(1, 1, 0, {"drops": 2})


def test_rule_info_lists_the_b3_fields() -> None:
    rule = RuleInfo("10", "attack", "L4", ("IP", "tcp"), stateful=True)
    assert rule.to_dict() == {
        "id": "10",
        "category": "attack",
        "layer": "L4",
        "protocols": ["ip", "tcp"],
        "stateful": True,
    }
    with pytest.raises(InvalidValue, match="protocols"):
        RuleInfo("10", "attack", "L4", "tcp", stateful=False)  # type: ignore[arg-type]
    with pytest.raises(InvalidValue, match="stateful"):
        RuleInfo("10", "attack", "L4", ("tcp",), stateful=1)  # type: ignore[arg-type]


def test_image_ref_needs_a_sha256_digest() -> None:
    assert ImageRef("img:1", "sha256:" + "a" * 64).to_dict()["digest"].startswith("sha256:")
    for digest in ("a" * 64, "sha256:" + "A" * 64, "sha256:abc", "latest"):
        with pytest.raises(InvalidValue, match="digest"):
            ImageRef("img:1", digest)


# --- Hashes ------------------------------------------------------------------------


def test_tree_sha256_of_a_file_is_its_sha256(tmp_path: Path) -> None:
    f = tmp_path / "r.rules"
    f.write_bytes(b"rule\n")
    assert tree_sha256(f) == hashlib.sha256(b"rule\n").hexdigest()


def test_tree_sha256_of_a_directory_changes_on_rename_add_or_edit(ruleset: Ruleset) -> None:
    before = tree_sha256(ruleset.path)
    assert before == ruleset.sha256()
    (ruleset.path / "b.rules").rename(ruleset.path / "c.rules")
    renamed = tree_sha256(ruleset.path)
    (ruleset.path / "d.rules").write_text("rule d\n", encoding="utf-8")
    added = tree_sha256(ruleset.path)
    (ruleset.path / "a.rules").write_text("rule a2\n", encoding="utf-8")
    edited = tree_sha256(ruleset.path)
    assert len({before, renamed, added, edited}) == 4


def test_tree_sha256_of_a_missing_path_fails(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        tree_sha256(tmp_path / "absent")


def test_config_record_holds_every_file_and_hashes_the_content(
    prepared: FakeAdapter, tmp_path: Path
) -> None:
    config = prepared.tools_record()["config"]
    assert "# mbench-config-file: fake.conf\nprofile = recommended\n" in config["content"]
    assert "# mbench-config-file: rules.conf\n" in config["content"]
    assert config["sha256"] == hashlib.sha256(config["content"].encode()).hexdigest()
    # No host path in the record: files are named relative to the workdir.
    assert str(tmp_path) not in config["content"]


def test_config_record_changes_with_the_profile(tmp_path: Path, ruleset: Ruleset) -> None:
    a, b = FakeAdapter(), FakeAdapter()
    a.prepare(ruleset, "recommended", tmp_path / "a")
    b.prepare(ruleset, "tuned", tmp_path / "b")
    assert a.tools_record()["config"]["sha256"] != b.tools_record()["config"]["sha256"]


def test_config_record_needs_a_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no config file"):
        config_record([], tmp_path)


# --- The tools-under-test record ---------------------------------------------------


def test_the_fake_tools_record_validates(prepared: FakeAdapter, ruleset: Ruleset) -> None:
    record = prepared.tools_record()
    assert tools_record_errors(record) == []
    assert record["ruleset"] == {"id": "r-fake", "sha256": ruleset.sha256()}
    assert record["image"] == {
        "ref": "example.invalid/fake-tool:1.2.3",
        "digest": "sha256:" + "0" * 64,
    }


def test_a_tools_record_with_markers_validates(prepared: FakeAdapter) -> None:
    record = prepared.tools_record()
    record["version"] = sut.unavailable("error", "the tool printed no version")
    record["image"] = sut.unavailable("not_applicable", "a local build, no image")
    record["build_flags"] = sut.unavailable("not_supported", "the tool does not report them")
    assert tools_record_errors(record) == []


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda r: r.pop("config"), "missing field: config"),
        (lambda r: r.pop("ruleset"), "missing field: ruleset"),
        (lambda r: r["image"].update(digest="latest"), "image.digest"),
        (lambda r: r["ruleset"].update(sha256="xyz"), "ruleset.sha256"),
        (lambda r: r["config"].update(sha256="nope"), "config.sha256"),
        (lambda r: r.update(extra=1), "Additional properties"),
        (lambda r: r.update(name=None), "name"),
    ],
)
def test_an_incomplete_tools_record_is_rejected_naming_the_field(
    prepared: FakeAdapter, change: Any, expected: str
) -> None:
    record = prepared.tools_record()
    change(record)
    errors = tools_record_errors(record)
    assert errors
    assert any(expected in e for e in errors), errors


def _run_record(tools: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The dgx-spark golden record, embedded as a run with these tools."""
    record: dict[str, Any] = copy.deepcopy(json.loads(GOLDEN.read_text(encoding="utf-8")))
    record["scope"] = "run"
    record["tools"] = list(tools)
    return record


def test_the_tools_record_is_what_the_sut_schema_wants_in_a_run(prepared: FakeAdapter) -> None:
    # Embedded in a run-scope sut.json, the record leaves no tools error.
    errors = validate.sut_errors(_run_record([prepared.tools_record()]))
    assert not [e for e in errors if e.startswith("tools")], errors
    # Without it, the run record names the tools section.
    bad = validate.sut_errors(_run_record([]))
    assert any(e.startswith("tools") for e in bad), bad


def test_the_tools_record_does_not_change_sut_hash(prepared: FakeAdapter) -> None:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert sut.sut_hash(_run_record([prepared.tools_record()])) == golden["sut_hash"]


def test_tools_schema_is_the_committed_one() -> None:
    # tools_record_errors checks the item of the sut.json schema, not a copy.
    root = validate.schema()
    item = base._tools_item_schema()
    assert item["required"] == root["properties"]["tools"]["anyOf"][0]["items"]["required"]
    run_tools = root["allOf"][0]["then"]["properties"]["tools"]["items"]
    assert {k: v for k, v in item.items() if not k.startswith("$")} == run_tools


# --- The fake adapter in a scored run ---------------------------------------------


def test_the_fake_adapter_feeds_truth_scoring(prepared: FakeAdapter, tmp_path: Path) -> None:
    from mbench import truth

    prepared.run_alerts = [Alert.from_dict(_alert()), Alert.from_dict(_alert(src="203.0.113.9"))]
    prepared.run_counters = Counters(packets=56, bytes=4096, drops=0)
    handle = prepared.run_offline(tmp_path / "10.http.port.pcap", 1, [4])
    assert handle.wait(timeout=10) == 0
    gt = truth.parse(
        {
            "schema_version": 1,
            "pcap_sha256": "f" * 64,
            "attacks": [
                {
                    "id": "syn-flood",
                    "start": 1489508972.69,
                    "end": 1489508972.70,
                    "src": "192.0.2.20",
                    "dst": "198.51.100.102",
                    "proto": "tcp",
                    "rule_ids": {prepared.name: ["10"]},
                }
            ],
        }
    )
    result = truth.score(prepared.alerts(), gt, tool=prepared.name)
    assert (result.tp, result.fn, result.fp) == (1, 0, 1)
    assert prepared.counters().packets == 56
