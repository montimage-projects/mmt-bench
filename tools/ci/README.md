# tools/ci

Repository checks run by CI.

- `check_action_pins.py`: every `uses:` in `.github/workflows/` must be an
  `actions/*` action pinned to a 40-hex commit SHA (repo policy).
- `check_no_captures.py`: no file tracked by git may be a packet capture —
  checked by name (the suffixes `.gitignore` excludes) and by the pcap/pcapng
  magic bytes, so a capture renamed past the patterns is still caught
  (AGENTS.md).
- `check_smoke_result.py RESULTS_DIR [EXPECTED_ALERTS]`: the smoke job's gate —
  every run record of the results directory's newest batch must be `ok`
  (results are append-only, so an older batch's failure is not the gate),
  and every measured pass must report the expected alert count and a
  detection rate of 1.0, so a broken alert path cannot pass as an `alerts: 0`
  record. With no EXPECTED_ALERTS the count is derived per record from the
  run's own ground truth: `cell.corpus.ground_truth` names the truth file
  under `corpus/`, its `pcap_sha256` must match the record's pcap, and its
  number of attacks is the expectation — the generated `--data-in-syn` truth
  writes one attack per SYN packet, one alert each, so the workflow states
  the count once, in the `corpus gen` flag. A run whose truth is missing,
  unreadable or bound to another pcap fails. EXPECTED_ALERTS is the
  binding-free override for a results dir checked without its corpus (the
  truth file is never committed). The records' schema is `mbench
  validate`'s job.
