"""Detection scoring of normalised alerts against a pcap's ground truth.

A ground-truth file lists the attacks a pcap contains (format: the
``truth.schema.json`` schema and docs/methodology.md, *Ground truth*).
:func:`load` reads and checks one; :func:`score` scores a tool's normalised
:class:`~mbench.adapters.base.Alert`\\ s against it the same way for every tool:

- an alert **matches** an attack when it falls inside the attack's time span
  widened by the tolerance, its two addresses are the attack's two endpoints
  (in either direction), its protocol is the attack's (when the attack names
  one), and its rule id is one listed for this tool (when the attack lists
  rule ids for it): :func:`matches`;
- **TP**: the attacks with at least one matching alert. Several alerts for one
  attack make one TP;
- **FN**: the attacks with no matching alert;
- **FP**: the alerts that match no attack;
- **detection rate** = TP / (TP + FN), over attacks;
- **precision** = matched alerts / all alerts, over alerts, so the extra
  alerts of an attack seen several times are neither a TP nor an FP.
"""

from __future__ import annotations

import ipaddress
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from mbench.adapters.base import Alert

Json = Any
Network = ipaddress.IPv4Network | ipaddress.IPv6Network

TRUTH_SCHEMA = "truth.schema.json"

#: Seconds an alert may fall outside an attack's span and still match it.
DEFAULT_TOLERANCE_S = 1.0


class TruthError(ValueError):
    """A ground-truth file that cannot be used, with every problem found."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


def _endpoint(text: str) -> Network:
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"not an IP address or network: {text!r}") from None
    # A CIDR written with host bits set ("192.0.2.5/24") is a typo, not a
    # wider network: reject it instead of silently widening to {network}.
    if "/" in text and text != str(network):
        raise ValueError(f"a network with host bits set (use {network}): {text!r}")
    return network


@dataclass(frozen=True)
class Attack:
    """One attack of the ground truth."""

    id: str
    start: float
    end: float
    src: Network
    dst: Network
    proto: str | None = None
    category: str | None = None
    description: str = ""
    rule_ids: Mapping[str, frozenset[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class GroundTruth:
    """The attacks of one pcap, identified by its sha256.

    Two attacks may not carry one id (the score is kept per id), and the
    tolerance is a finite number of seconds >= 0.
    """

    pcap_sha256: str
    attacks: tuple[Attack, ...]
    tolerance_s: float = DEFAULT_TOLERANCE_S
    source: str | None = None

    def __post_init__(self) -> None:
        if not math.isfinite(self.tolerance_s) or self.tolerance_s < 0:
            raise TruthError([f"tolerance_s: not a finite number >= 0: {self.tolerance_s!r}"])
        ids = [attack.id for attack in self.attacks]
        if len(set(ids)) != len(ids):
            raise TruthError(["attacks: duplicate attack ids"])


def parse(data: Json) -> GroundTruth:
    """A :class:`GroundTruth` from the JSON of a ground-truth file.

    Raises :class:`TruthError` naming every problem: a schema violation, a
    non-finite number (``json.loads`` accepts NaN and Infinity, which the
    schema's ``number`` type lets through), an attack that ends before it
    starts, an endpoint that is not an address or a network, two attacks
    with one id.
    """
    from mbench import validate

    validator = Draft202012Validator(validate.schema(TRUTH_SCHEMA))
    problems = sorted({validate.describe(e) for e in validator.iter_errors(data)})
    if problems:
        raise TruthError(problems)

    attacks: list[Attack] = []
    seen: set[str] = set()
    for i, raw in enumerate(data["attacks"]):
        where = f"attacks[{i}]"
        if raw["id"] in seen:
            problems.append(f"{where}.id: duplicate attack id {raw['id']!r}")
        seen.add(raw["id"])
        for key in ("start", "end"):
            if not math.isfinite(raw[key]):
                problems.append(f"{where}.{key}: not a finite number: {raw[key]!r}")
        if raw["end"] < raw["start"]:
            problems.append(f"{where}.end: {raw['end']} is before start {raw['start']}")
        endpoints: dict[str, Network] = {}
        for key in ("src", "dst"):
            try:
                endpoints[key] = _endpoint(raw[key])
            except ValueError as exc:
                problems.append(f"{where}.{key}: {exc}")
        if len(endpoints) < 2:
            continue
        attacks.append(
            Attack(
                id=raw["id"],
                start=float(raw["start"]),
                end=float(raw["end"]),
                src=endpoints["src"],
                dst=endpoints["dst"],
                proto=raw.get("proto"),
                category=raw.get("category"),
                description=raw.get("description", ""),
                rule_ids={tool: frozenset(ids) for tool, ids in raw.get("rule_ids", {}).items()},
            )
        )
    tolerance_s = float(data.get("tolerance_s", DEFAULT_TOLERANCE_S))
    if not math.isfinite(tolerance_s):
        problems.append(f"tolerance_s: not a finite number: {data['tolerance_s']!r}")
    if problems:
        raise TruthError(problems)
    return GroundTruth(
        pcap_sha256=data["pcap_sha256"],
        attacks=tuple(attacks),
        tolerance_s=tolerance_s,
        source=data.get("source"),
    )


def load(path: str | Path) -> GroundTruth:
    """Read and check a ground-truth file (JSON)."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise TruthError(
            [f"{p}: unreadable: not UTF-8 text ({exc.reason} at byte {exc.start})"]
        ) from None
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise TruthError([f"{p}: not valid JSON: {exc}"]) from None
    try:
        return parse(data)
    except TruthError as exc:
        raise TruthError([f"{p}: {problem}" for problem in exc.problems]) from None


def _in(address: str, network: Network) -> bool:
    return ipaddress.ip_address(address) in network


def matches(alert: Alert, attack: Attack, tolerance_s: float, tool: str) -> bool:
    """Whether ``alert`` (from ``tool``) is a detection of ``attack``."""
    if not attack.start - tolerance_s <= alert.ts <= attack.end + tolerance_s:
        return False
    forward = _in(alert.src, attack.src) and _in(alert.dst, attack.dst)
    reverse = _in(alert.src, attack.dst) and _in(alert.dst, attack.src)
    if not (forward or reverse):
        return False
    if attack.proto is not None and alert.proto != attack.proto:
        return False
    rule_ids = attack.rule_ids.get(tool)
    return rule_ids is None or alert.rule_id in rule_ids


@dataclass(frozen=True)
class Score:
    """The detection score of one run.

    ``detection_rate`` is ``None`` when the pcap has no attack (a benign
    pcap), and ``precision`` is ``None`` when the tool raised no alert: a
    ratio over nothing is undefined, never 0 or 1.
    """

    tp: int
    fn: int
    fp: int
    alerts: int
    matched_alerts: int
    detection_rate: float | None
    precision: float | None
    #: Per attack id, how many alerts matched it (0 for a missed attack).
    alerts_per_attack: Mapping[str, int]
    #: The alerts that matched no attack, in the order given.
    false_positives: tuple[Alert, ...]

    @property
    def detected(self) -> list[str]:
        return [a for a, n in self.alerts_per_attack.items() if n > 0]

    @property
    def missed(self) -> list[str]:
        return [a for a, n in self.alerts_per_attack.items() if n == 0]

    def to_dict(self) -> dict[str, Json]:
        """The score as a run's JSON records it (no alert bodies)."""
        return {
            "tp": self.tp,
            "fn": self.fn,
            "fp": self.fp,
            "alerts": self.alerts,
            "matched_alerts": self.matched_alerts,
            "detection_rate": self.detection_rate,
            "precision": self.precision,
            "alerts_per_attack": dict(self.alerts_per_attack),
        }


def score(alerts: Iterable[Alert], truth: GroundTruth, *, tool: str) -> Score:
    """Score ``alerts`` from ``tool`` against ``truth``.

    ``tool`` is required — it is the adapter's
    :attr:`~mbench.adapters.base.Adapter.name` and selects each attack's
    ``rule_ids`` entry, so a forgotten tool name cannot silently ignore the
    restriction and count wrong rule ids as detections. An alert may match
    several attacks (overlapping attacks on one flow): it then detects each
    of them, and counts once in ``matched_alerts``.
    """
    per_attack = {attack.id: 0 for attack in truth.attacks}
    alert_list = list(alerts)
    unmatched: list[Alert] = []
    for alert in alert_list:
        hit = False
        for attack in truth.attacks:
            if matches(alert, attack, truth.tolerance_s, tool):
                per_attack[attack.id] += 1
                hit = True
        if not hit:
            unmatched.append(alert)
    tp = sum(1 for n in per_attack.values() if n > 0)
    fn = len(per_attack) - tp
    matched = len(alert_list) - len(unmatched)
    return Score(
        tp=tp,
        fn=fn,
        fp=len(unmatched),
        alerts=len(alert_list),
        matched_alerts=matched,
        detection_rate=tp / (tp + fn) if per_attack else None,
        precision=matched / len(alert_list) if alert_list else None,
        alerts_per_attack=per_attack,
        false_positives=tuple(unmatched),
    )
