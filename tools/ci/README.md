# tools/ci

Repository checks run by CI.

- `check_action_pins.py`: every `uses:` in `.github/workflows/` must be an
  `actions/*` action pinned to a 40-hex commit SHA (repo policy).
- `check_no_captures.py`: no file tracked by git may be a packet capture —
  checked by name (the suffixes `.gitignore` excludes) and by the pcap/pcapng
  magic bytes, so a capture renamed past the patterns is still caught
  (AGENTS.md).
