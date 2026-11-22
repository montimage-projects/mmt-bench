# campaigns

One YAML file per campaign, each stating one question
([schema](../src/mbench/schemas/campaign.schema.json), checked by
`mbench validate campaigns/<x>.yaml`). `mbench run` expands the campaign's
matrix — tools × rulesets × config profiles × corpus × threads × cpusets —
into one run per cell, writes `results/<date>-<campaign>/` (append-only) and
renders `REPORT.md`. See [docs/design.md](../docs/design.md) §B1 and
[docs/methodology.md](../docs/methodology.md).

```yaml
schema_version: 1
question: does mmt-probe keep line rate on the small-packet set?
tools: [mmt-probe]                # adapter names; >1 tool -> local/results
rulesets: [default]               # rulesets/<id>/, rulesets/<id>.so, or {id, path, threads?}
config_profiles: [recommended]    # default; the fair-comparison rule wants both
corpus: [{label: c-small}]        # a manifest label, or {path, sha256, truth?, name?}
threads: [0, 1, 2]                # 0: the capture thread does the work
cpusets: ["", "0-3"]              # cpulists, core:<type>[@n] selectors, or {cpuset, threads?}
repeats: 5                        # measured passes per cell, after one warm-up
timeout_s: 30                     # a longer pass is killed, recorded timeout
quiet_host: false                 # true: print the vLLM stop/start commands
verdict_cell:                     # optional: which cell the verdict answers on
  ruleset: default                #   (default: the fastest measured cell)
  corpus: c-small
  threads: 1
  cpuset: "core:x925@1"           # selectors resolve like cpusets items
```

A ruleset entry's `threads: [...]` keeps the rule set out of the thread
counts it does not name (P1 runs r0/r0b at `thread-nb 0` only — the
main-thread pipeline). A `cpusets` item's `threads` likewise scopes its
cpuset to those counts (P1 pins `core:x925@1` for t0/t1 and `@N+2` for
tN, leaving the probe's reader and output threads room). `verdict_cell`
names the cell the report's verdict answers on — every field must match
a cell's record, else the campaign fails to load; absent, the verdict
names the fastest measured cell.

A `{path, sha256}` corpus entry pins a local capture — including a private one
— by its hash; results name it only by `name` (or the file's stem) and sha256,
never by its path. A `label` entry resolves through `corpus/manifest.yaml`
(`--manifest` selects another) and checks the file against the manifest's pin.

`quiet_host: true` prints, for Luong to run — the harness never runs them and
never uses sudo:

```sh
systemctl --user stop vllm-qwen.service vllm-health-watchdog.timer
systemctl --user start vllm-qwen.service vllm-health-watchdog.timer
```

`mbench report <results-dir>` re-renders `REPORT.md` (append-only, or `-o -`
to stdout).

## smoke.yaml (#9)

The 10-s smoke campaign: two offline cells, mmt-probe on the generated
`smoke` and `smoke-large` corpus entries — the second keeps the
`snap-len = 65535` fix (review B1) under test on 1500-B frames. It checks
the pipeline end to end — SUT record, ruleset, capture, passes, `REPORT.md`
— on any host, including a CI runner; its numbers are a pipeline check,
not results. On each host:

```sh
docker build -t mmt-bench/mmt-probe:local tools/docker/mmt-probe
uv run mbench corpus gen c-small --seed 0 --packets 20000 --flows 64 --label smoke --data-in-syn 4
uv run mbench corpus gen c-large --seed 0 --packets 500 --flows 8 --label smoke-large --data-in-syn 4
tools/docker/mmt-probe/extract-rules.sh   # the image's rules -> local/rulesets/
uv run mbench run campaigns/smoke.yaml
dir=$(ls -dt results/*-smoke | head -1)   # the newest smoke results dir
uv run mbench validate "$dir"/sut*.json "$dir"/runs/*.json "$dir"/REPORT*.md
python3 tools/ci/check_smoke_result.py "$dir"   # runs ok, truth's alerts, rate 1.0
```

The ruleset is a single `.so` of the image's mmt-security set: the compiled
rules are architecture-specific build artefacts, staged under the
git-ignored `local/` by `extract-rules.sh`, never committed. One rule keeps
a pass under a second; the image's full set costs more than the 10-s budget
of init per pass. The `smoke` corpus entry is deterministic
(`mbench corpus gen`, seed 0): the same bytes on every host, generated into
`corpus/data/` and never committed. Its first 4 packets are TCP SYNs
carrying payload — the trigger of the ruleset's `13.datainSYN.so` — and
`gen` writes their ground truth as `data/smoke.truth.json` (one attack per
packet), so every measured pass must report 4 alerts and detection rate 1.0:
the smoke proves the alert path end to end, not only throughput plumbing.
The smoke CI job (`.github/workflows/ci.yml`) runs the same steps on every
pull request and push to `main` and uploads the results directory as an
artefact — never a commit.
