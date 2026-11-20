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

`mbench sut` and `mbench validate` are implemented (#4):

```sh
uv run mbench sut -o sut.json       # system-under-test fingerprint, no sudo
uv run mbench validate sut.json     # exit 0 when the record is complete
```

See [docs/sut-fingerprint.md](docs/sut-fingerprint.md). The other subcommands
are stubs for now: each exits with status 3 and `not implemented yet (#N)`,
naming the issue that implements it (epic #1).
