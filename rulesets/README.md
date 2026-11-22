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

## Blocked on the pinned image: r0 and r0b

mmt-probe v1.6.5 in the pinned image (sha256 c6311ed3…) **segfaults** in
both configurations — a dry run reproduced it on every cell:

- `security.enable = false` → SIGSEGV in `file_output_alloc_init` at worker
  start (rules present or not, output-channel variants tried).
- engine on with zero verified rules → SIGSEGV at init (empty rules dir),
  or mid-packet when every rule is `exclude-rules`-ed or `rules-mask`-ed.

These are upstream probe bugs, not harness errors: until a fixed image
ships, the r0/r0b cells of a campaign record `error` — the run documents
the blocker instead of measuring it. The definitions stay: they are
correct, and they start measuring the day the image is fixed.

## R-all is 94 rules, not 95

Upstream mmt-security has 95 XML rules. The pinned image builds the fork
`montimage/mmt-security` at `defefb7a3f39c70527d3e74d8f1150b7392ac050`,
which disabled DICOM rules 206 and 212 in `aeacbe0428` ("false positives on
benign traffic"). It ships **94** `.so` files, so the P1 headline's "all 95
rules" is the 94 rules the image loads.

## Producing the rules

```sh
tools/docker/mmt-probe/extract-rules.sh   # image's rules -> local/rulesets/mmt-security
```

`local/` is git-ignored; a run's tools record pins the staged rule set by
sha256 (`tree_sha256` over the `.so` files). `matrix.load` refuses to run
`r-all` until the extracted dir holds exactly the `expect_rules` count.
