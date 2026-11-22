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
rulesets: [default]               # rulesets/<id>/, rulesets/<id>.so, or {id, path}
config_profiles: [recommended]    # default; the fair-comparison rule wants both
corpus: [{label: c-small}]        # a manifest label, or {path, sha256, truth?, name?}
threads: [0, 1, 2]                # 0: the capture thread does the work
cpusets: ["", "0-3"]              # cpulists; "" pins nothing
repeats: 5                        # measured passes per cell, after one warm-up
timeout_s: 30                     # a longer pass is killed, recorded timeout
quiet_host: false                 # true: print the vLLM stop/start commands
```

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
to stdout). The 10-s smoke campaign comes with #9.
