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

`mbench sut`, `mbench validate` and `mbench corpus` are implemented (#4, #7):

```sh
uv run mbench sut -o sut.json              # system-under-test fingerprint, no sudo
uv run mbench validate sut.json            # exit 0 when the record is complete
uv run mbench validate corpus/manifest.yaml
uv run mbench corpus gen c-small           # synthetic 64 B frames, deterministic
uv run mbench corpus check                 # every capture present vs its sha256
```

See [docs/sut-fingerprint.md](docs/sut-fingerprint.md) and
[corpus/README.md](corpus/README.md). The other subcommands are stubs for now:
each exits with status 3 and `not implemented yet (#N)`, naming the issue that
implements it (epic #1).
