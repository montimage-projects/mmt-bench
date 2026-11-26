# mmt-bench
Tool-agnostic benchmark harness for network security engines (mmt-probe/mmt-security, Suricata, Snort 3): throughput, detection and a full system-under-test record

## Quick start

Python 3.12, managed with [uv](https://docs.astral.sh/uv/).

```sh
uv sync --locked           # create .venv from uv.lock
uv run mbench --help       # subcommands: sut, corpus, run, sweep, report, validate
uv run ruff check .        # lint
uv run ruff format --check .
uv run mypy                # types (strict)
python3 tools/ci/check_action_pins.py  # every action pinned to a full SHA
uv run pytest              # tests
```

`mbench sut`, `mbench validate`, `mbench corpus`, `mbench run`, `mbench
sweep` and `mbench report` are implemented (#4, #7, #8, #17):

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
uv run mbench validate results/<date>-x/REPORT.md   # the report too (#9)
uv run mbench sweep campaigns/x.yaml --param threads --values 0,1,2,4
uv run mbench sweep campaigns/x.yaml --param rate --search 0:2000 --until loss==0
uv run mbench validate results/<date>-x-sweep-*/SWEEP*  # the summary too (#17)
```

`mbench sweep` runs one dimension of a campaign: a `--values` list sweep
(a one-axis matrix: thread counts, ruleset ids, corpus labels or the
offered rate), or a `--search` binary search over the offered rate for the
highest value satisfying `--until` — a condition like `loss==0` or
`loss<=0.001` over the metrics a run records. Every step is a full run
under `results/<date>-<campaign>-sweep-<param>/`, plus a `SWEEP.json` /
`SWEEP.md` summary `mbench validate` checks.

See [docs/sut-fingerprint.md](docs/sut-fingerprint.md),
[corpus/README.md](corpus/README.md) and
[campaigns/README.md](campaigns/README.md).

[AGENTS.md](AGENTS.md) is the single copy of the commands CI runs — the
checks above, the action-pin check and the 10-s smoke campaign — and of the
repo's operating rules.
