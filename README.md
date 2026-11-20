# mmt-bench
Tool-agnostic benchmark harness for network security engines (mmt-probe/mmt-security, Suricata, Snort 3): throughput, detection and a full system-under-test record

## Quick start

Python 3.12, managed with [uv](https://docs.astral.sh/uv/).

```sh
uv sync                    # create .venv from uv.lock
uv run mbench --help       # subcommands: sut, corpus, run, sweep, report, validate
uv run ruff check .        # lint
uv run ruff format --check .
uv run mypy                # types (strict)
uv run pytest              # tests
```

The subcommands are stubs for now: each exits with status 3 and
`not implemented yet (#N)`, naming the issue that implements it (epic #1).
