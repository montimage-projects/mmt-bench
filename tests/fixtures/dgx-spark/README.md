# dgx-spark fixtures

Captured on dgx-spark (NVIDIA DGX Spark, 10 Cortex-X925 + 10 Cortex-A725,
Ubuntu 24.04, kernel 6.17.0-1032-nvidia): `sources.json` on 2026-11-20,
without sudo, and `dmidecode-t17-root.txt` on 2026-11-21, as root.

- `sources.json`: every file, directory, link and command answer one
  `mbench sut` run read, sanitised by `--record-sources` (hostname aliased to
  `dgx-spark`; MAC and IP addresses, UUIDs and RSS keys replaced; only the
  listed processes and the recorded NICs kept; `docker info` trimmed).
- `dmidecode-t17-root.txt`: the `dmidecode -t 17` answer of a
  `--record-sources` run as root on 2026-11-21, as the sanitiser wrote it (only
  the `Memory Device` header and the `Size`, `Type`, `Speed` and
  `Configured Memory Speed` lines).
- `sut.json`: the record the collector builds when it replays `sources.json`
  (`tests/sutfixtures.py`).

How to recapture and regenerate: `docs/sut-fingerprint.md`, "Test fixtures".
