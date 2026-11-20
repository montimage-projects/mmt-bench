# dgx-spark fixtures

Captured on dgx-spark (NVIDIA DGX Spark, 10 Cortex-X925 + 10 Cortex-A725,
Ubuntu 24.04, kernel 6.17.0-1032-nvidia) on 2026-11-20, without sudo.

- `sources.json`: every file, directory, link and command answer one
  `mbench sut` run read, sanitised by `--record-sources` (hostname aliased to
  `dgx-spark`; MAC and IP addresses, UUIDs and RSS keys replaced; only the
  listed processes and the recorded NICs kept; `docker info` trimmed).
- `sut.json`: the record the collector builds when it replays `sources.json`
  (`tests/sutfixtures.py`).

How to recapture and regenerate: `docs/sut-fingerprint.md`, "Test fixtures".
