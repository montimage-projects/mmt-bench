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
root. CI runs the same checks (`.github/workflows/ci.yml`).

```sh
uv sync --locked                       # install: create .venv from uv.lock
uv run ruff check .                    # lint
uv run ruff format --check .           # formatting
uv run mypy                            # types (strict)
python3 tools/ci/check_action_pins.py  # workflows: actions/* only, SHA-pinned
uv run pytest                          # tests
uv run mbench --help                   # smoke: the CLI lists its subcommands
```

The subcommands are stubs until their issue lands: each exits with status 3
and `not implemented yet (#N)`. The 10-s smoke campaign comes with #9, which
adds its command here.

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
- **The repo is private.** Keep it under montimage-projects; do not publish
  its code, results or reports elsewhere.
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
