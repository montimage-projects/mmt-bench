# tools/ci

Repository checks run by CI.

- `check_action_pins.py`: every `uses:` in `.github/workflows/` must be an
  `actions/*` action pinned to a 40-hex commit SHA (repo policy).
- `check_no_captures.py`: no file tracked by git may be a packet capture —
  checked by name (the suffixes `.gitignore` excludes) and by the pcap/pcapng
  magic bytes, so a capture renamed past the patterns is still caught
  (AGENTS.md).
- `check_smoke_result.py RESULTS_DIR EXPECTED_ALERTS`: the smoke job's gate —
  every run record of the results directory's newest batch must be `ok`
  (results are append-only, so an older batch's failure is not the gate),
  and every measured pass must report EXPECTED_ALERTS alerts and a
  detection rate of 1.0 against the corpus entry's ground truth, so a broken
  alert path cannot pass as an `alerts: 0` record. The records' schema is
  `mbench validate`'s job.
