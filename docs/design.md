# mmt-bench design

This is Track B (B1–B10) of the plan "rule-build provenance (A) and mmt-bench
(B)", drafted for Luong on 2026-11-19, copied as written. The plan's Track A is
out of scope for this repo (epic #1) and is not copied.

The [Decisions](#decisions) at the end were taken after the plan was written
(epic #1). Where a decision and the plan text below differ, the decision wins.
How each measurement is taken is in [methodology.md](methodology.md).

## B1. Scope and principles

- Systems under test (SUT tools): mmt-probe with mmt-dpi and mmt-security first. Then Suricata and Snort 3, and later Zeek, all through the same adapter interface.
- One question per campaign, and a verdict in the report, the same discipline as m-bench.
- Fair comparison rules:
  - the same pcaps;
  - the same cores, pinned;
  - each tool at its documented recommended config plus a tuned config, both recorded;
  - rule sets matched by attack coverage, never by rule count alone;
  - detection correctness measured with the throughput every time, so a fast run that misses attacks is not counted.
- Full system-under-test record, automatic and mandatory: a run without a complete fingerprint is invalid.
- Append-only results: `results/<date>-<campaign>/`, never overwritten.
- Reproducible:
  - tools in containers pinned by digest;
  - pcaps by sha256;
  - the harness version recorded in every result.

## B2. Repo layout (montimage-projects/mmt-bench (private))

```
mmt-bench/
  README.md  AGENTS.md  CLAUDE.md  docs/{design.md, methodology.md, adding-a-tool.md, sut-fingerprint.md}
  pyproject.toml            # Python 3.12, uv; CLI `mbench`
  src/mbench/
    cli.py                  # mbench sut | corpus | run | sweep | report | validate
    sut.py                  # system-under-test fingerprint collector
    matrix.py               # YAML campaign -> list of runs
    runner.py               # isolation, warm-up, repeats, timeouts
    modes/offline.py        # pcap-from-tmpfs capacity
    modes/online.py         # replay at rate, binary search for lossless
    metrics/{proc.py, perf.py, nic.py}   # pidstat/cgroup, perf stat, NIC counters
    adapters/base.py        # Adapter interface
    adapters/mmt_probe.py
    adapters/suricata.py    # phase P5
    adapters/snort3.py      # phase P5
    truth.py                # expected alerts -> detection scoring
    report/{render.py, charts.py}        # markdown + mermaid/svg, like m-bench
  tools/docker/             # pinned images: mmt-probe, suricata, snort3, tcpreplay/trafgen
  corpus/manifest.yaml      # pcaps by sha256 + source + licence + ground truth; large files not in git
  rulesets/                 # rule-set definitions per tool (ids/categories), mapping tables
  campaigns/*.yaml          # one per question
  results/<date>-<campaign>/{runs/*.json, sut.json, REPORT.md}
  tests/                    # unit tests, and a 10-s smoke campaign in CI
```

## B3. Adapter interface (what each tool implements)

```
name, version(), image digest
prepare(ruleset, config_profile, workdir) -> config files
run_offline(pcap, threads, cpuset) -> process handle
run_online(iface, threads, cpuset) -> process handle
counters() -> {packets, bytes, drops, ...}   # from tool stats output
alerts() -> normalised list {ts, rule_id, category, src, dst, proto}
rule_inventory(ruleset) -> [{id, category, layer, protocols, stateful}]
```

- mmt-probe reads JSON reports, STIX alerts and the status report.
- Suricata reads eve.json, stats and alerts.
- Snort 3 reads alert_json and perf_monitor.

The normalised alert format lets `truth.py` score detection (true positives, false negatives, false positives) the same way for every tool.

## B4. System-under-test fingerprint (`mbench sut`, saved as sut.json in every campaign and every run)

- Host:
  - hostname alias (anonymisable), vendor and model (DMI);
  - CPU model per core type, core count by type, max and min frequency, governor, boost state, SMT;
  - caches (L1, L2, L3), NUMA layout, isolated cores (`isolcpus`, `nohz_full`);
  - memory size and speed (if readable), hugepages, swap.
- OS:
  - distro and version, kernel version and cmdline;
  - mitigations (`/sys/devices/system/cpu/vulnerabilities`);
  - sysctl net.core.* (rmem, netdev_max_backlog, busy_poll).
- NICs:
  - model, driver and driver version, firmware, link speed;
  - queues and RSS, ring sizes, offloads (`ethtool -k`: GRO, LRO, TSO), IRQ affinity.
- Container runtime: Docker version, cgroup version, CPU and memory limits applied.
- Tools under test: image digest, version strings, build flags (for mmt: the DPI, security and probe versions and commits, the STIX and security modules), rule-set id and hash, full config hash, and the config file itself.
- Background noise:
  - load average before and after;
  - top CPU and memory processes during the run;
  - whether vLLM (or other heavy services) were stopped;
  - temperature and throttling if exposed (`/sys/class/thermal`, `perf stat` frequency).
- Harness: mbench version and commit, Python version, pcap sha256 values, the start and end time of the run.
- A `sut_hash`: runs are only compared when their hardware and OS parts match, and the report flags any mismatch.

## B5. Methodology

- Offline capacity:
  - the pcap lives in a tmpfs bind mount;
  - one warm-up pass, then N=5 measured passes;
  - throughput = bytes / (processing time measured inside the container from the first to the last packet, or from the tool's own stats), cross-checked with wall time;
  - report Gbit/s, Mpps, and cycles per packet (`perf stat` on the pinned cores).
- Online lossless rate:
  - replay with tcpreplay or trafgen in a container at a fixed rate into a veth pair (default, needs no hardware), and later into a cabled ConnectX-7 loop (100/200 GbE, needs a cable);
  - 60 s per step, binary search to the highest rate with drops under 0.1 % (tool drops plus kernel `rx_dropped` and `rx_missed`);
  - enP7s7 is never used, and the veth path is labelled as such in the report.
- Pinning:
  - the tool's threads go on X925 cores, with a separate A725-only series to measure the core-type effect;
  - the replayer and harness run on other cores;
  - performance governor, if Luong allows it (it needs sudo).
- Stats: median and IQR over 5 repeats. A rerun is flagged if CV > 5 %.
- Correctness gate: each run's alerts are compared with ground truth; the report shows the detection rate next to throughput.
- Duration and safety: each run is capped. The harness never touches the production mmt-stack containers, and it uses its own container names and data dirs.

## B6. Corpus (`corpus/manifest.yaml`)

- C-benign:
  - an anonymised 1-h capture from dgx-spark, taken with Luong's OK and anonymised by `tcprewrite` / crypto-PAn, kept local and not published;
  - plus a public mix such as the CIC-IDS2017 Monday benign day or the MAWI samplelists, licence permitting.
- C-small (64 B), C-large (1500 B): synthetic, generated by `mbench corpus gen`.
- C-L7: HTTP and FTP, DICOM, 5G NGAP/NAS (from mmt-security `check/pcap`, mmt-test, or a public 5G dataset).
- C-attack: `check/pcap`, with its `check/expect` as ground truth for mmt. A public labelled set (CIC-IDS2017 or 2018 attack days) for cross-tool comparison, where Suricata and Snort have rules.
- C-mix-k: the benign set with attacks injected at 0.1 %, 1 % and 10 %.
- C-flows-n: 1k, 10k, 100k and 1M concurrent flows.

Every pcap carries its sha256, source, licence, size, packet count, average packet size and ground-truth file.

## B7. Rule sets

- mmt:
  - R0: security off;
  - R0b: on, with 0 rules;
  - by layer: L2/3, L4, L7-web, L7-dicom, L7-5g;
  - single-event vs temporal;
  - all 95;
  - N-sweep: 1, 5, 10, 25, 50, 95, then synthetic 1k and 10k (mmt-security `test/gen_xml_HTTP_rules.sh`, `test/complex_rules`);
  - per-rule cost.
  - The classification is generated automatically from XML and `rule_info`, using the layer table from protocols used: `ip` 430 references, `tcp` 128, `dicom` 86, `sctp` 38, and so on.
- Suricata and Snort, phase P5:
  - ET Open and the Snort community rules, pinned by version, by category;
  - a "coverage-matched" set that maps the attacks mmt detects to the equivalent rules of each tool, kept in `rulesets/mapping.yaml`.

## B8. Phases (P0–P6), each its own campaign and report

- P0, repo bootstrap:
  - the skeleton, CLI, `mbench sut` and its tests;
  - the mmt-probe adapter, running offline on one pcap;
  - CI with lint, unit tests and the 10-s smoke run.

  Done when: `mbench sut` produces a complete sut.json on dgx-spark, and `mbench run campaigns/smoke.yaml` writes a valid result and REPORT.md.
- P1, first headline. Question: "How many Gbit/s can mmt-probe with all 95 rules process on one X925 core on a benign mix?"
  - R0, R0b and R-all on C-benign and C-small/C-large, offline;
  - thread-nb 1, 2, 4 and 8, with security in-thread (security.thread-nb = 0).

  Done when: the report has a verdict, a CI-backed table and a full sut.json.
- P2, rule cost: the layer and category sets, the N-sweep, the per-rule cost ranking, and the attack-density effect (C-mix-k).
- P3, scale: the flow-count sweep (memory, throughput), synthetic 1k and 10k rules, and security threads 1/2/4 with the patched ring, labelled "patched, not released" until mmt-security fixes C1.
- P4, online: veth lossless rate. Then ConnectX-7 if a cable is added (decision).
- P5, other tools: Suricata and Snort 3 adapters, the coverage-matched rule sets, and the same campaigns. The report is "mmt vs Suricata vs Snort on the same SUT".
- P6, regression: a weekly small campaign on the dgx (or a self-hosted runner) per DPI, security and probe release, alerting on a slowdown of more than 5 %.

## B9. How the work is run

- Each phase becomes GitHub issues in mmt-bench, through the idd plan-to-issues skill, with one PR per issue.
- Claude Code implements, a separate Claude Code session reviews, and merges happen after PASS and green CI, as with the other repos.
- Benchmark campaigns that need vLLM stopped are announced first. Luong stops `vllm-qwen.service` and its watchdog timer with sudo (I have no sudo), the campaign runs, then he restarts them. A script prints the exact commands.
- Results and reports are committed to `results/`. Large pcaps stay outside git, listed in the manifest. The private capture stays local only.

## B10. Risks

- Big.LITTLE cores and thermal throttling cause noise, handled by pinning, recording frequency, and the CV check.
- Offline capacity is not the line rate: both modes are reported and labelled.
- Rule sets of different tools are not comparable by count, so the coverage-matched mapping is needed. Publishing comparisons may also have licence and fairness implications; review before publishing.
- The security-thread bug (C1) limits the mmt scaling numbers until it is fixed.
- The online path needs packet tools: containers bring their own, so nothing is installed on the host.

## Decisions

Luong's decisions, recorded in epic #1. They override the plan above where
they differ. Decision 1 was replaced on 2026-11-20.

1. **Replaced.** Was: "The repo stays private under montimage-projects for
   now." Replaced by Luong's decision of 2026-11-20: the repo is public, under
   montimage-projects (for free GitHub Actions). Tool-comparison reports (mmt
   vs Suricata vs Snort, the P5 `REPORT.md`) stay out of git, local only, until
   they pass a licence and fairness review; until then only the method and the
   harness are public. This overrides "(private)" in the B2 heading and, for
   comparison reports, "Results and reports are committed to `results/`" in
   B9. It turns B10's "review before publishing" into a rule.
2. An anonymised 1-h capture of dgx-spark's real traffic may be the benign
   corpus, kept local only, never committed or published. (B6 C-benign, B9.)
3. The online mode uses a veth pair only for now (no ConnectX-7 cabling).
   This narrows "later into a cabled ConnectX-7 loop" in B5: the ConnectX-7
   path is out of scope until a cable is added, as B8 P4 already says.
4. vLLM may be stopped for campaigns. Stopping it needs sudo, which agents do
   not have, so the harness prints the commands and Luong runs them. (B9.)
5. Every run must carry the full system-under-test record (B4). A run without
   it is invalid. (B1.)
