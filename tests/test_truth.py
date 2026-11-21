"""Ground-truth loading and detection scoring (#5)."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

import pytest

from mbench import truth
from mbench.adapters.base import Alert
from mbench.truth import GroundTruth, TruthError

ROOT = Path(__file__).resolve().parent.parent
METHODOLOGY = ROOT / "docs/methodology.md"

T0 = 1_700_000_000.0
ATTACKER = "192.0.2.20"
VICTIM = "198.51.100.102"
OTHER = "203.0.113.9"

#: The scored tool's name; ``score`` requires it (``FakeAdapter.name``).
TOOL = "fake-tool"


def _attack(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "a1",
        "start": T0,
        "end": T0 + 10,
        "src": ATTACKER,
        "dst": VICTIM,
        "proto": "tcp",
        "category": "dos",
    }
    data.update(overrides)
    return data


def _truth(*attacks: dict[str, Any], **top: Any) -> dict[str, Any]:
    return {"schema_version": 1, "pcap_sha256": "ab" * 32, "attacks": list(attacks), **top}


def _gt(*attacks: dict[str, Any], **top: Any) -> GroundTruth:
    return truth.parse(_truth(*attacks, **top))


def _alert(ts: float = T0 + 1, **overrides: Any) -> Alert:
    data: dict[str, Any] = {
        "ts": ts,
        "rule_id": "10",
        "category": "attack",
        "src": ATTACKER,
        "dst": VICTIM,
        "proto": "tcp",
    }
    data.update(overrides)
    return Alert.from_dict(data)


# --- The four cases of the issue ---------------------------------------------------


def test_exact_match() -> None:
    result = truth.score([_alert()], _gt(_attack()), tool=TOOL)
    assert (result.tp, result.fn, result.fp) == (1, 0, 0)
    assert result.detection_rate == 1.0
    assert result.precision == 1.0
    assert result.detected == ["a1"]


def test_missed_attack() -> None:
    result = truth.score([_alert()], _gt(_attack(), _attack(id="a2", dst=OTHER)), tool=TOOL)
    assert (result.tp, result.fn, result.fp) == (1, 1, 0)
    assert result.detection_rate == 0.5
    assert result.missed == ["a2"]


def test_false_positive() -> None:
    fp = _alert(src=OTHER, dst="203.0.113.10")
    result = truth.score([_alert(), fp], _gt(_attack()), tool=TOOL)
    assert (result.tp, result.fn, result.fp) == (1, 0, 1)
    assert result.precision == 0.5
    assert result.false_positives == (fp,)


def test_several_alerts_for_one_attack_are_one_tp_and_no_fp() -> None:
    alerts = [_alert(T0 + i) for i in range(5)]
    result = truth.score(alerts, _gt(_attack()), tool=TOOL)
    assert (result.tp, result.fn, result.fp) == (1, 0, 0)
    assert result.detection_rate == 1.0
    assert result.alerts == 5
    assert result.matched_alerts == 5
    assert result.alerts_per_attack == {"a1": 5}
    assert result.precision == 1.0


def test_the_detection_rate_counts_attacks_not_alerts() -> None:
    # 3 alerts detect 1 of 2 attacks: the rate is over attacks (0.5). A
    # per-alert formula (matched alerts / attacks) would give 1.5.
    gt = _gt(_attack(), _attack(id="a2", dst=OTHER))
    result = truth.score([_alert(T0 + i) for i in range(3)], gt, tool=TOOL)
    assert (result.tp, result.fn) == (1, 1)
    assert result.detection_rate == 0.5


# --- The matching rule --------------------------------------------------------------


@pytest.mark.parametrize(
    ("ts", "hit"),
    [
        (T0 - 1.0, True),  # at the tolerance before the start
        (T0 - 1.001, False),
        (T0 + 10 + 1.0, True),  # at the tolerance after the end
        (T0 + 11.001, False),
    ],
)
def test_the_time_window_is_the_span_widened_by_the_tolerance(ts: float, hit: bool) -> None:
    assert truth.score([_alert(ts)], _gt(_attack()), tool=TOOL).tp == int(hit)


def test_the_tolerance_is_set_per_file() -> None:
    gt = _gt(_attack(), tolerance_s=0)
    assert truth.score([_alert(T0 - 0.5)], gt, tool=TOOL).tp == 0
    assert truth.score([_alert(T0 - 0.5)], _gt(_attack(), tolerance_s=5), tool=TOOL).tp == 1
    assert _gt(_attack()).tolerance_s == truth.DEFAULT_TOLERANCE_S == 1.0


def test_endpoints_match_in_either_direction() -> None:
    reply = _alert(src=VICTIM, dst=ATTACKER)
    assert truth.score([reply], _gt(_attack()), tool=TOOL).tp == 1


def test_one_wrong_endpoint_does_not_match() -> None:
    result = truth.score([_alert(dst=OTHER), _alert(src=OTHER)], _gt(_attack()), tool=TOOL)
    assert (result.tp, result.fp) == (0, 2)


def test_an_endpoint_can_be_a_network() -> None:
    gt = _gt(_attack(dst="198.51.100.0/24"))
    assert truth.score([_alert(dst="198.51.100.7")], gt, tool=TOOL).tp == 1
    assert truth.score([_alert(dst="198.51.101.7")], gt, tool=TOOL).tp == 0


def test_ipv6_endpoints_match_canonically() -> None:
    gt = _gt(_attack(src="2001:db8::1", dst="2001:DB8:0:0::2"))
    alert = _alert(src="2001:db8:0::1", dst="2001:db8::2")
    assert truth.score([alert], gt, tool=TOOL).tp == 1
    # An IPv4 alert never matches an IPv6 attack.
    assert truth.score([_alert()], gt, tool=TOOL).tp == 0


def test_the_protocol_must_match_when_the_attack_names_one() -> None:
    assert truth.score([_alert(proto="udp")], _gt(_attack()), tool=TOOL).tp == 0
    no_proto = _attack()
    del no_proto["proto"]
    assert truth.score([_alert(proto="udp")], _gt(no_proto), tool=TOOL).tp == 1


def test_rule_ids_restrict_only_the_tool_they_name() -> None:
    gt = _gt(_attack(rule_ids={"mmt-probe": ["10", "11"]}))
    assert truth.score([_alert(rule_id="11")], gt, tool="mmt-probe").tp == 1
    # Another tool name: the attack's rule ids do not apply.
    assert truth.score([_alert(rule_id="sid:2001219")], gt, tool="suricata").tp == 1


def test_a_wrong_rule_id_for_the_named_tool_is_no_tp() -> None:
    gt = _gt(_attack(rule_ids={"mmt-probe": ["10", "11"]}))
    result = truth.score([_alert(rule_id="99")], gt, tool="mmt-probe")
    assert (result.tp, result.fn, result.fp) == (0, 1, 1)
    assert result.detection_rate == 0.0


def test_the_tool_name_is_required() -> None:
    gt = _gt(_attack(rule_ids={"mmt-probe": ["10"]}))
    with pytest.raises(TypeError):
        truth.score([_alert()], gt)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        truth.matches(_alert(), gt.attacks[0], gt.tolerance_s)  # type: ignore[call-arg]


def test_one_alert_can_detect_overlapping_attacks() -> None:
    gt = _gt(_attack(), _attack(id="a2", start=T0 + 5, end=T0 + 20))
    result = truth.score([_alert(T0 + 6)], gt, tool=TOOL)
    assert (result.tp, result.fn, result.fp) == (2, 0, 0)
    assert result.matched_alerts == 1


def test_the_category_is_not_matched() -> None:
    gt = _gt(_attack(category="scan"))
    assert truth.score([_alert(category="whatever")], gt, tool=TOOL).tp == 1


# --- Undefined ratios ---------------------------------------------------------------


def test_a_benign_pcap_has_no_detection_rate() -> None:
    result = truth.score([_alert()], _gt(), tool=TOOL)
    assert (result.tp, result.fn, result.fp) == (0, 0, 1)
    assert result.detection_rate is None
    assert result.precision == 0.0


def test_no_alert_has_no_precision() -> None:
    result = truth.score([], _gt(_attack()), tool=TOOL)
    assert (result.tp, result.fn, result.fp) == (0, 1, 0)
    assert result.detection_rate == 0.0
    assert result.precision is None


def test_score_to_dict_is_json() -> None:
    result = truth.score([_alert(), _alert(src=OTHER)], _gt(_attack()), tool=TOOL)
    assert json.loads(json.dumps(result.to_dict())) == {
        "tp": 1,
        "fn": 0,
        "fp": 1,
        "alerts": 2,
        "matched_alerts": 1,
        "detection_rate": 1.0,
        "precision": 0.5,
        "alerts_per_attack": {"a1": 1},
    }


# --- Loading and checking a ground-truth file ---------------------------------------


def test_load_reads_a_file(tmp_path: Path) -> None:
    path = tmp_path / "10.http.port.truth.json"
    data = _truth(_attack(rule_ids={"mmt-probe": ["10"]}), source="mmt-security check/expect")
    path.write_text(json.dumps(data), encoding="utf-8")
    gt = truth.load(path)
    assert gt.pcap_sha256 == "ab" * 32
    assert gt.source == "mmt-security check/expect"
    (attack,) = gt.attacks
    assert attack.src == ipaddress.ip_network(ATTACKER)
    assert attack.rule_ids == {"mmt-probe": frozenset({"10"})}
    assert attack.category == "dos"


def test_load_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.truth.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(TruthError, match="not valid JSON"):
        truth.load(path)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({"schema_version": 1, "attacks": []}, "missing field: pcap_sha256"),
        (_truth(pcap_sha256="xyz"), "pcap_sha256"),
        ({**_truth(), "schema_version": 2}, "schema_version"),
        (_truth(_attack(start=-1)), "attacks[0].start"),
        (
            _truth({k: v for k, v in _attack().items() if k != "dst"}),
            "missing field: attacks[0].dst",
        ),
        (_truth(_attack(proto="TCP")), "attacks[0].proto"),
        (_truth(_attack(colour="red")), "Additional properties"),
        (_truth(_attack(), tolerance_s=-1), "tolerance_s"),
        (_truth(_attack(rule_ids={"mmt-probe": []})), "attacks[0].rule_ids.mmt-probe"),
        (_truth(_attack(end=T0 - 1)), "attacks[0].end: "),
        (_truth(_attack(src="not-an-ip")), "attacks[0].src: not an IP address or network"),
        # A CIDR with host bits set is rejected, not silently widened to
        # its network address: it is a typo in the truth file.
        (
            _truth(_attack(dst="192.0.2.5/24")),
            "attacks[0].dst: a network with host bits set (use 192.0.2.0/24)",
        ),
        (_truth(_attack(src="2001:db8::1/64")), "attacks[0].src: a network with host bits"),
        (_truth(_attack(), _attack()), "attacks[1].id: duplicate attack id"),
        # json.loads accepts NaN and Infinity; the schema's "number" lets them
        # through, and a non-finite span or tolerance would silently mis-score.
        (_truth(_attack(start=float("nan"))), "attacks[0].start: not a finite number"),
        (_truth(_attack(end=float("inf"))), "attacks[0].end: not a finite number"),
        (_truth(_attack(), tolerance_s=float("nan")), "tolerance_s: not a finite number"),
        (_truth(_attack(), tolerance_s=float("inf")), "tolerance_s: not a finite number"),
    ],
)
def test_an_invalid_ground_truth_is_rejected_naming_the_field(
    data: dict[str, Any], expected: str
) -> None:
    with pytest.raises(TruthError) as info:
        truth.parse(data)
    assert any(expected in p for p in info.value.problems), info.value.problems


def test_a_ground_truth_built_by_hand_keeps_the_same_guards() -> None:
    attack = _gt(_attack()).attacks[0]
    twin = truth.Attack(
        id=attack.id,
        start=attack.start,
        end=attack.end,
        src=attack.src,
        dst=attack.dst,
    )
    with pytest.raises(TruthError, match="duplicate attack id"):
        GroundTruth("ab" * 32, (attack, twin))
    for bad in (float("nan"), float("inf"), -1.0):
        with pytest.raises(TruthError, match="tolerance_s"):
            GroundTruth("ab" * 32, (attack,), tolerance_s=bad)


def test_load_rejects_a_non_utf8_file(tmp_path: Path) -> None:
    path = tmp_path / "t.truth.json"
    path.write_bytes(b"\xff\xfe{}")
    with pytest.raises(TruthError, match="not UTF-8"):
        truth.load(path)


def test_load_prefixes_problems_with_the_file(tmp_path: Path) -> None:
    path = tmp_path / "t.truth.json"
    path.write_text(json.dumps(_truth(_attack(end=T0 - 1))), encoding="utf-8")
    with pytest.raises(TruthError, match=re.escape(f"{path}: attacks[0].end")):
        truth.load(path)


# --- The documentation ----------------------------------------------------------------


def test_methodology_documents_the_format_and_the_matching_rule() -> None:
    text = METHODOLOGY.read_text(encoding="utf-8")
    assert "## Ground truth" in text
    section = text.split("## Ground truth", 1)[1].split("\n## ", 1)[0]
    for word in (
        "schema_version",
        "pcap_sha256",
        "tolerance_s",
        "attacks",
        "rule_ids",
        "either direction",
        "detection rate",
        "precision",
        "truth.schema.json",
    ):
        assert word in section, word
    assert "added to this document by #5" not in text


def test_the_documented_example_loads() -> None:
    text = METHODOLOGY.read_text(encoding="utf-8")
    section = text.split("## Ground truth", 1)[1].split("\n## ", 1)[0]
    block = re.search(r"```json\n(.*?)```", section, re.DOTALL)
    assert block is not None
    gt = truth.parse(json.loads(block.group(1)))
    assert gt.attacks
