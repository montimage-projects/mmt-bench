# tools/ci

Repository checks run by CI.

- `check_action_pins.py`: every `uses:` in `.github/workflows/` must be an
  `actions/*` action pinned to a 40-hex commit SHA (repo policy).
