# Methodology

How mmt-bench measures a network security engine, and what makes a run count.
It is the measurement part of the design: plan §B5 (methodology) and the
fair-comparison rules of §B1, with the decisions of epic #1 applied. See
[design.md](design.md) for the whole design.

## A run without a complete SUT record is invalid

Every run carries the full system-under-test (SUT) record of design §B4:
host, OS, NICs, container runtime, tools under test, background noise and
harness, plus a `sut_hash`. `mbench sut` collects it (#4), and the runner embeds
it in each run (#8).

- A run without a complete record is **invalid**. It is excluded from every
  table, and the report lists it as invalid.
- A field that cannot be read without root is recorded with the reason it is
  unreadable. It is never dropped.
- `sut_hash` covers the hardware and OS parts only. Runs are compared only
  when their `sut_hash` matches, and the report flags any mismatch.

## Fair comparison

These rules apply to every campaign:

- **The same pcaps**, identified by sha256.
- **The same cores, pinned** (see [Pinning](#pinning)).
- **Each tool at two configs**: its documented recommended config and a tuned
  config. Both are recorded, config file included.
- **Rule sets matched by attack coverage**, never by rule count alone. The
  coverage-matched sets map the attacks mmt detects to the equivalent rules of
  each tool (`rulesets/mapping.yaml`).
- **Detection is measured with the throughput every time** (see
  [Correctness gate](#correctness-gate)). A fast run that misses attacks does
  not count.

One campaign answers one question, and its report gives a verdict on it.

## Offline capacity

How fast a tool processes a pcap it reads from memory.

- The pcap lives in a tmpfs bind mount, so disk speed is not measured.
- One warm-up pass, then N = 5 measured passes. The warm-up is never counted.
- Throughput = bytes / processing time. Processing time is measured inside the
  container from the first to the last packet, or taken from the tool's own
  stats. It is cross-checked with the wall time.
- Reported as Gbit/s, Mpps, and cycles per packet (`perf stat` on the pinned
  cores).

Offline capacity is not the line rate. Reports state which mode a number comes
from.

## Online lossless rate (veth only)

The highest replay rate the tool sustains without loss.

- Traffic is replayed by tcpreplay or trafgen, in a container, at a fixed rate
  into a **veth pair**. The veth pair needs no hardware and is the only online
  path for now (epic #1 decision). The ConnectX-7 loop is out of scope until a
  cable is added.
- Each rate step lasts 60 s. A binary search finds the highest rate with drops
  under 0.1 %. Drops are the tool's own drops plus the kernel's `rx_dropped`
  and `rx_missed`.
- `enP7s7`, dgx-spark's 1 GbE Realtek NIC, is never used.
- Reports label online numbers as veth numbers.

## Pinning

dgx-spark has heterogeneous cores (10 Cortex-X925 at 3.9 GHz and 10
Cortex-A725 at 2.8 GHz, one NUMA node), so the core type is a variable that is
pinned and recorded.

- The tool's threads run on X925 cores. A separate A725-only series measures
  the core-type effect.
- The replayer and the harness run on other cores than the tool.
- Each run records its cpuset and the core type.
- The performance governor is used only if Luong sets it, because it needs
  sudo.

## Statistics

- Each cell is reported as the **median and IQR over 5 measured repeats**.
  The p25/p75 quartiles use linear interpolation on the `(n-1)` rank — the
  NumPy default (Hyndman–Fan type 7).
- A cell whose coefficient of variation (CV) is **above 5 %** is flagged for
  a rerun. CV uses the *sample* standard deviation (n−1 denominator).
- Frequency is recorded during the run, so thermal throttling and core-type
  noise show up in the record.

## Correctness gate

Each run's alerts are compared with the pcap's ground truth. Every adapter
normalises its tool's alerts to one format (`ts, rule_id, category, src, dst,
proto`), so `truth.py` scores every tool the same way: true positives, false
negatives, false positives, detection rate and precision. The report shows the
detection rate next to the throughput. The ground-truth file and the matching
rule are in [Ground truth](#ground-truth).

## Ground truth

Each pcap with attacks has a ground-truth file, `<pcap name>.truth.json`,
which the corpus manifest names (#7). It lists the attacks the pcap contains,
in terms every tool can be scored on: when, between which endpoints, over
which protocol. `src/mbench/truth.py` loads it and checks it against
`src/mbench/schemas/truth.schema.json`; `mbench validate` recognises a truth
file by its `<pcap>.truth.json` name or its content and runs the same checks.

```json
{
  "schema_version": 1,
  "pcap_sha256": "0f8a5c6e3b1d2a4f6e8c0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a",
  "source": "mmt-security check/expect/10.http.port.csv",
  "tolerance_s": 1.0,
  "attacks": [
    {
      "id": "syn-flood-1",
      "start": 1489508972.695759,
      "end": 1489508972.698659,
      "src": "192.0.2.20",
      "dst": "198.51.100.0/24",
      "proto": "tcp",
      "category": "dos",
      "description": "Half TCP handshakes without RST",
      "rule_ids": {"mmt-probe": ["10"]}
    }
  ]
}
```

- `schema_version` is 1. `pcap_sha256` is the sha256 of the pcap it
  describes. `source` (optional) says where the labels come from.
- `tolerance_s` (optional, default 1, at least 0): seconds an alert may fall
  before an attack's start or after its end and still match it, because tools
  time-stamp an alert at different packets of the attack.
- Each attack has a unique `id`, a `start` and an `end` (packet time, in
  seconds since the epoch; `end` not before `start`), and two endpoints `src`
  and `dst`, each an IP address or a CIDR network's canonical address (a
  scan of a /24: `192.0.2.0/24`, never `192.0.2.5/24`).
- `proto` (optional, lowercase): when given, only an alert with this protocol
  matches. It is the protocol of the flow the attack runs on — `udp` for a
  UDP scan — not the namespace of a rule's first condition (`ip.proto_id`
  would wrongly say `ip`). For mmt-derived truth (`check/expect` rows),
  take it from the rule's protocol list (`rule_inventory`), the same source
  the adapter uses, or omit it.
- `category` and `description` (optional) are reported, never matched: each
  tool names its categories its own way.
- `rule_ids` (optional): per tool name (the adapter's `name`), the rule ids
  that detect the attack. The score is always computed for one named tool —
  `truth.score` requires it, so a forgotten tool name cannot let the wrong
  rule ids count as detections. When the named tool has an entry, only an
  alert with one of those rule ids matches; any other tool is matched
  without it. This lets a tool's own expected output (mmt-security
  `check/expect`) be the ground truth without making it binding on Suricata
  or Snort.

An alert normalised by the adapter (`ts, rule_id, category, src, dst, proto`)
**matches** an attack when all of these hold:

1. `ts` is within `[start - tolerance_s, end + tolerance_s]`;
2. its `src` and `dst` are the attack's two endpoints, in either direction (a
   tool may report the reply packet), each address within its endpoint's
   network;
3. its `proto` equals the attack's `proto`, when the attack has one;
4. its `rule_id` is in the attack's `rule_ids` for the scored tool, when
   there is such an entry.

Then, for one run:

- **TP** is the number of attacks with at least one matching alert. Several
  alerts for one attack make one TP, and none of them is an FP.
- **FN** is the number of attacks with no matching alert.
- **FP** is the number of alerts that match no attack.
- **Detection rate** = TP / (TP + FN), over attacks.
- **Precision** = matched alerts / all alerts, over alerts. Counting alerts,
  not attacks, keeps both terms in one unit: a tool that raises ten alerts
  for one attack and one stray alert has a precision of 10/11.
- An alert that matches two overlapping attacks detects both, and counts
  once as a matched alert.
- A pcap without attacks has no detection rate, and a run without alerts has
  no precision: both are reported as undefined, never as 0 or 1.

The run's JSON keeps the alert count per attack, so a report can show which
attacks a tool missed.

## Duration and safety

- Each run is capped by a timeout. A run that exceeds it is killed and
  recorded as `timeout`, never as a measurement.
- A run's status is `ok`, `partial` (some measured passes ok), `timeout`,
  `error`, `interrupted` (a Ctrl-C or a caught signal stopped the
  campaign) or `invalid` (incomplete SUT record). A crashed or interrupted
  campaign still writes its report over the runs it recorded.
- Signal coverage: `mbench run` handles SIGINT (a Ctrl-C is already
  `KeyboardInterrupt`) and catches SIGTERM and SIGHUP, raising
  `SystemExit(128 + signum)` so they take the same interrupted path — the
  tool is killed, the cell recorded `interrupted` and the report rendered.
  SIGKILL cannot be caught: a `kill -9` can still leave the tool running
  and the stage dir behind.
- The harness never touches the production mmt-stack containers. It uses its
  own container names and data dirs.
- Results are append-only: `results/<date>-<campaign>/` is never overwritten.
- A tool-comparison report (mmt vs Suricata vs Snort, P5) is not committed
  to `results/`. It stays local, under the git-ignored `local/`, until it
  passes a licence and fairness review (design, decision 1).
- Quiet host: when a campaign needs vLLM stopped, the harness prints the exact
  commands to stop and later restart `vllm-qwen.service` and
  `vllm-health-watchdog.timer`, and Luong runs them. The harness never runs
  sudo itself. The SUT record says whether vLLM was stopped.
