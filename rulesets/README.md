# rulesets

Rule-set definitions per tool (#10). A `rulesets/<id>.yaml` file *describes*
a rule set; the rules themselves — the compiled `.so` files — are never
committed. A campaign names them by id:

```yaml
rulesets: [r0, r0b, r-all]
```

| id | rules | `security.enable` | what it measures |
| --- | --- | --- | --- |
| `r0` | none (`rulesets/empty/`) | `false` | mmt-probe without mmt-security |
| `r0b` | none (`rulesets/empty/`) | `true` | the engine's fixed cost, zero rules |
| `r-all` | the pinned image's 94 rules | `true` | the full security workload |

A definition file holds `tool`, `rules` (the `.so` file or directory,
relative to the repo root), `security.enable`, `allow_empty`, and
`provenance` (source, expected rule count, the extraction command). The
schema is `src/mbench/schemas/ruleset.schema.json`; `mbench validate
rulesets/<id>.yaml` checks it.

## The pinned image's snap-len crash

mmt-probe v1.6.5 in the pinned image (sha256 c6311ed3…) **segfaults** when
the generated config sets `snap-len = 0`: `pcap_capture_start` inside
libpcap crashes the worker path on frames of every size (the review saw it
as `worker_on_start → dpi_alloc_init → file_output_alloc_init` on r0/r0b
and as `__fread_chk ← libpcap` on C-large — the same upstream bug at
different unwind points). The main-thread pipeline (`thread-nb = 0`) does
not hit it. The adapter writes `snap-len = 65535`, and r0/r0b then run
cleanly at every thread count; the campaigns keep them at t0 anyway as the
main-thread baselines.

## R-all is 94 `.so` files, and the engine says 95

Upstream mmt-security has 95 XML rules. The pinned image builds the fork
`montimage/mmt-security` at `855931a37bd73bd43b26ff03ea108c6745c11b19`,
which disabled DICOM rules 206 and 212 in `aeacbe0428` ("false positives on
benign traffic"). It ships **94** `.so` files. The engine's log still says
`verifying 95 rules`: its count includes **rule 84** — "SYNful Knock
implant answer" — a builtin compiled into mmt-security, not a `.so`
(`probe rule_info` over the extracted rules lists it among the 95). So the
P1 headline's "all 95 rules" is what the image actually verifies: the 94
extracted `.so` rules plus the engine's builtin.

## Producing the rules

```sh
tools/docker/mmt-probe/extract-rules.sh   # image's rules -> local/rulesets/mmt-security
```

`local/` is git-ignored; a run's tools record pins the staged rule set by
sha256 (`tree_sha256` over the `.so` files). `matrix.load` refuses to run
`r-all` until the extracted dir holds exactly the `expect_rules` count.
