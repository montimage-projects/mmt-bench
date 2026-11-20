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
- A cell whose coefficient of variation (CV) is **above 5 %** is flagged for
  a rerun.
- Frequency is recorded during the run, so thermal throttling and core-type
  noise show up in the record.

## Correctness gate

Each run's alerts are compared with the pcap's ground truth. Every adapter
normalises its tool's alerts to one format (`ts, rule_id, category, src, dst,
proto`), so `truth.py` scores every tool the same way: true positives, false
negatives, false positives, detection rate and precision. The report shows the
detection rate next to the throughput. The ground-truth file format and the
alert-to-attack matching rule are added to this document by #5.

## Duration and safety

- Each run is capped by a timeout. A run that exceeds it is killed and
  recorded as `timeout`, never as a measurement.
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
