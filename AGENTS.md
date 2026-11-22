# AGENTS.md

mmt-bench is a tool-agnostic benchmark harness for network security engines:
mmt-probe with mmt-dpi and mmt-security first, then Suricata and Snort 3. It
measures throughput and detection together, and records the full
system-under-test with every run.

- Design: [docs/design.md](docs/design.md) (plan Track B, and the decisions
  that override it).
- How runs are measured and when they count:
  [docs/methodology.md](docs/methodology.md).
- Work is tracked in epic #1, with one PR per issue.

## Commands

Python 3.12, managed with [uv](https://docs.astral.sh/uv/). Run from the repo
root. CI runs the same checks (`.github/workflows/ci.yml`). They need a system
Python 3.12; run `export UV_PYTHON_DOWNLOADS=never` first so uv never downloads
an interpreter onto the host (CI sets the same).

```sh
uv sync --locked                       # install: create .venv from uv.lock
uv run ruff check .                    # lint
uv run ruff format --check .           # formatting
uv run mypy                            # types (strict)
python3 tools/ci/check_action_pins.py  # workflows: actions/* only, SHA-pinned
python3 tools/ci/check_no_captures.py  # no packet capture is tracked by git
uv run pytest                          # tests
uv run mbench --help                   # smoke: the CLI lists its subcommands

# The smoke job (#9): the same steps CI runs on every PR and push to main.
docker build -t mmt-bench/mmt-probe:local tools/docker/mmt-probe  # pinned image
tools/docker/mmt-probe/extract-rules.sh  # the image's rules -> local/ (never committed)
uv run mbench corpus gen c-small --seed 0 --packets 20000 --flows 64 --label smoke
uv run mbench run campaigns/smoke.yaml   # the 10-s campaign, a pipeline check
uv run mbench validate                   # the run, its SUT record and REPORT*.md
python3 tools/ci/check_smoke_result.py   # gate: the newest batch's runs all ok
```

`mbench sut`, `mbench validate`, `mbench corpus`, `mbench run` and
`mbench report` are implemented; `mbench sweep` is a stub until its issue
lands: it exits with status 3 and `not implemented yet (#17)`. The 10-s
smoke campaign (#9) — `mbench run campaigns/smoke.yaml` after
`tools/docker/mmt-probe/extract-rules.sh` and `mbench corpus gen … --label
smoke`, see `campaigns/README.md` — runs in CI on every PR and push to
`main` (`smoke` job), as a pipeline check, not a benchmark.

## Operating rules

- **No sudo for agents.** Anything that needs root (stopping
  `vllm-qwen.service` and `vllm-health-watchdog.timer`, setting the performance
  governor) is printed by the harness for Luong to run. Never run sudo, and
  never work around a missing permission.
- **Never touch the production mmt-stack containers.** The harness starts,
  stops and mounts only its own containers, with their own names and data
  dirs.
- **Results are append-only.** Never overwrite or delete anything under
  `results/<date>-<campaign>/`; a new run only adds files.
- **The private dgx-spark capture is never committed or published.** It stays
  local, and results and reports name it only by its label and sha256. No
  packet capture goes into git (`.gitignore` excludes them).
- **The repo is public** (Luong, 2026-11-20). Never commit host identifiers:
  MAC or IP addresses, machine-id, UUIDs, serial numbers, usernames, home
  paths or keys. The private capture stays out of git too (rule above).
- **Tool-comparison reports stay out of git until reviewed.** A report that
  compares tools (mmt vs Suricata vs Snort, the P5 `REPORT.md`) is never
  committed or published until it passes a licence and fairness review. It
  stays local, under `local/`, which `.gitignore` excludes. Until then only the
  method and the harness are public.
- **A run without a complete system-under-test record is invalid**
  ([methodology](docs/methodology.md)).
- **Nothing is installed on the host.** Python dependencies live in the
  uv-managed `.venv`; packet tools and the tools under test come in containers
  pinned by digest.
- **CI uses GitHub-owned actions only** (`actions/*`), each pinned to a full
  commit SHA; `tools/ci/check_action_pins.py` enforces it.

## Conventions

- Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
- Lint, types and tests pass before a PR is opened.
