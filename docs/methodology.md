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
- Throughput = bytes / processing time. Processing time is the interval the
  tool's own evidence bounds — for mmt-probe, from the `[1]` version
  report's timestamp (written at the last worker's init, just before the
  packet loop) to the last status line's arrival (every packet then
  counted). The harness records it as `processing_s` and labels the pass
  `timing.basis: tool`. It is cross-checked with `wall_s` (the tool
  process's start-to-exit): a processing interval that does not sit inside
  its wall window (beyond a 50 ms clock-skew tolerance) makes the pass
  `invalid`. When the tool gives no interval, the rates fall back to wall
  time and the pass says so (`basis: wall`) — wall time includes init and
  teardown, so it under-reads throughput; the record's `overhead_s` shows
  how much.
- Bytes are **captured bytes** — the pcap's `incl_len`, Ethernet header
  included, no wire overhead (no preamble, IFG or FCS).
- The tool's packet count answers to the corpus manifest's declared count:
  a mismatch makes the pass `invalid`, as does an abnormal exit the tool
  masked as return code 0 (mmt-probe's signal handlers `_exit(0)` on
  SIGABRT/SIGSEGV — the log's clean-exit markers, not the exit status, say
  a run ended well). A pass reports `drops` only when the tool actually
  emitted a drop counter; otherwise `null` with the reason.
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
- CPU numbers are never committed: campaigns name a core *type*
  (`cpusets: ["core:x925"]`), and `mbench` resolves it from `lscpu -e` at
  run time. A `core:` selector that matches nothing, or more than one core
  type, is a campaign error. `core:<type>@<n>` pins the first n CPUs of
  the type — the form a cell uses when the question is "on n cores"
  (`core:x925@1` for the one-core headline; `@N+2` for tN leaves the
  probe's reader and output threads room beside its N workers: the probe
  pins workers round-robin over the container's allowed set).
- The harness pins itself to the CPUs the cell does not use, and the run
  record carries `harness_cpuset` beside the cell's.
- `perf stat` for cycles/pkt counts the run's own container cgroup
  (`-G <cgroup>`) when the cgroup can be resolved — cycles burned by the
  tool alone — else the pinned cpus (`-a -C <cpuset>`, labelled
  `scope: cpuset` in the pass: every task scheduled on those CPUs,
  including anything the host puts there). `perf_event_paranoid = 4`
  refuses either to an unprivileged user, so the run records the pass's
  perf entry as `unavailable` with the reason — never a fabricated number
  — and prints the root-only fix (`mbench.metrics.perf`). The runbook's
  CAP_PERFMON path needs the container's binary on an `exec`-able mount —
  a `nosuid`/`noexec` home directory or tmpfs makes the capability file
  attribute a no-op, so put it on a root filesystem mount.
- The performance governor is used only if Luong sets it, because it needs
  sudo.

## Statistics

- Each cell is reported as the **median and IQR over 5 measured repeats**.
  The p25/p75 quartiles use linear interpolation on the `(n-1)` rank — the
  NumPy default (Hyndman–Fan type 7).
- A cell whose coefficient of variation (CV) is **above 5 %** is flagged for
  a rerun. CV uses the *sample* standard deviation (n−1 denominator).
- The verdict's interval for the median is the **order-statistic confidence
  interval**: `[x_(k), x_(n−k+1)]` over the cell's measured passes, choosing
  the widest `k` whose exact level reaches 95 %, or `[x_(1), x_(n)]` when
  none does — labelled with its exact level (93.75 % at n = 5; the level
  comes from `1 − 2·P(Bin(n, ½) < k)`, not a rounded "95 %"). With fewer
  than 5 measured passes the verdict prints the **range**, labelled
  `range` — no confidence claim on so few passes
  (`mbench.report.render.median_ci`).
- Frequency is recorded during the run, so thermal throttling and core-type
  noise show up in the record.
- The CI smoke campaign (`campaigns/smoke.yaml`) runs on a shared, noisy
  runner: it checks the pipeline end to end, so its numbers are not results.

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

## The P1 headline (issue #10)

The campaign is `campaigns/p1-headline.yaml`. Its rule sets are defined in
`rulesets/` and its decisions are these:

- **R-all is 94 rules, not 95.** Upstream mmt-security has 95 XML rules, but
  the pinned image builds the fork at commit `defefb7a3f39c70527d3…`, which
  disabled DICOM rules 206 and 212 (`aeacbe0428`, false positives on benign
  traffic). "All 95 rules" in the question means the 94 `.so` files the
  image loads; `expect_rules: 94` in `rulesets/r-all.yaml` makes the harness
  refuse to run if the extracted count differs.
- **R0/R0b/R-all decompose the cost.** R0 = `security.enable = false`
  (probe only), R0b = engine on with zero rules (the engine's fixed cost),
  R-all = all 94 rules. R0 − R0b − R-all separates probe, engine and
  rule-matching cost. `security.thread-nb = 0`: rules are verified inside
  the probe threads. **Blocked on the pinned image:** mmt-probe v1.6.5
  segfaults in `file_output_alloc_init` with `security.enable = false`, and
  with the engine on but zero verified rules (empty rules dir; the same
  crash surfaces mid-packet when all rules are `exclude-rules`-ed or
  `rules-mask`-ed). Upstream bug: the r0/r0b cells record `error` until a
  fixed image ships; r-all runs.
- **C-benign** is a 1-h capture of the host's own traffic, anonymised in the
  pinned `mmt-bench/tcpreplay:local` container with `tcprewrite --seed`
  (deterministic, crypto-PAn-style IP rewriting) plus MAC replacement and
  checksum fix (`tools/capture/c-benign.sh` prints the root-only runbook;
  the capture needs sudo `tcpdump`). IPs, MACs and checksums are covered;
  **payloads are not** — DNS names, HTTP hosts and TLS SNI stay readable.
  Truncating them would hide the names but break the payload rules the
  benchmark exists to measure, so the capture is registered `local_only`
  and only its label and sha256 ever appear in results. That is the decided
  mitigation, pending Luong's confirmation.
- **Public benign mix: unresolved.** CIC-IDS2017's Monday capture fits, its
  terms allow redistribution with citation, but its official download URL
  redirects to a landing page — there is no stable URL + sha256 to pin.
  MAWI traces are payload-stripped, which breaks the payload-reading rules.
  No public mix is added to the manifest until one resolves to a pinned
  URL + sha256 with a clear licence (decision for Luong).
- **Perf access**: `kernel.perf_event_paranoid = 4` on this host, so an
  unprivileged `perf stat` is refused. The narrowest fix is a private perf
  copy with `CAP_PERFMON` (`setcap
  cap_perfmon+ep ~/.local/bin/perf-mbench`), the fallback
  `sysctl kernel.perf_event_paranoid=1`; the harness prints both and Luong
  runs one (perf, `enable_note`).
- **Dry-run output is not a result.** The PR's dry run ran on a noisy host
  (vLLM active, `quiet_host` off) purely to prove the pipeline.

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
  For the campaign's duration the harness owns all three handlers: a
  caller's own handler — `SIG_IGN` included — is overridden, and the
  previous handlers are restored when `mbench run` returns. A signal
  landing inside the final cleanup is deferred — recorded, not
  raised — until the cleanup finishes, then re-raised with the same exit
  status, so the stage removal, the report and the run records always
  complete. SIGKILL cannot be caught: a `kill -9` can still leave the
  tool running and the stage dir behind.
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
