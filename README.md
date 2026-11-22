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

`mbench sut`, `mbench validate`, `mbench corpus`, `mbench run` and
`mbench report` are implemented (#4, #7, #8):

```sh
uv run mbench sut -o sut.json              # system-under-test fingerprint, no sudo
uv run mbench validate sut.json            # exit 0 when the record is complete
uv run mbench validate corpus/manifest.yaml
uv run mbench validate campaigns/x.yaml    # a campaign file (#8)
uv run mbench validate x.truth.json        # a pcap's ground truth
uv run mbench corpus gen c-small           # synthetic 64 B frames, deterministic
uv run mbench corpus check                 # every capture present vs its sha256
uv run mbench run campaigns/x.yaml         # a campaign -> results/<date>-x/
uv run mbench report results/<date>-x/     # re-render REPORT.md (append-only)
```

See [docs/sut-fingerprint.md](docs/sut-fingerprint.md),
[corpus/README.md](corpus/README.md) and
[campaigns/README.md](campaigns/README.md). `mbench sweep` is a stub for now:
it exits with status 3 and `not implemented yet (#17)` (epic #1).
