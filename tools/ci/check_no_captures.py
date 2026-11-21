r"""Fail when a packet capture is tracked by git.

Captures never go into git (AGENTS.md): ``.gitignore`` excludes ``*.pcap``,
``*.pcapng``, their compressed forms, ``*.cap`` and ``*.erf``, and the
``corpus/data/`` directory they live in. The manifest names them by sha256
instead. This check enforces the same rule in CI, so a ``git add -f`` or a
capture renamed past the ignore patterns fails the build with the path that
broke it. It looks at every file ``git ls-files`` tracks, two ways:

- by name: the same suffixes ``.gitignore`` covers (case-insensitive);
- by content: the first four bytes of each file, against the pcap and pcapng
  magic numbers (``mbench.pcap.MAGICS`` — a test keeps the two lists equal),
  so a capture renamed ``x.bin`` is still caught.

Usage: ``python tools/ci/check_no_captures.py [REPO_ROOT]`` (default: the repo
root, found from this file's location, not the cwd). Exit 0 when no tracked
file is a capture, 1 when one is, 2 when nothing was checked: no git, or no
tracked files at all, so an empty answer never passes silently.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

#: The capture suffixes ``.gitignore`` excludes, on the basename: ``x.pcap``,
#: ``x.PcapNG``, ``x.pcap.gz``, ``x.cap.xz``, ``x.erf.zst``. ``x.capture`` and
#: ``x.pcapx`` are not captures.
NAME = re.compile(r"\.(pcapng|pcap|cap|erf)(\.[^/]*)?$", re.IGNORECASE)

#: The first four bytes of every capture format the corpus reads, in file
#: order. ``tests/test_check_no_captures.py`` keeps these equal to
#: ``mbench.pcap.MAGICS``.
MAGICS = (
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microseconds
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microseconds
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanoseconds
    b"\x0a\x0d\x0d\x0a",  # pcapng section header block
)

#: The repository root, from this file's location (tools/ci/).
DEFAULT_ROOT = Path(__file__).resolve().parents[2]


def tracked_files(root: Path) -> list[str]:
    """Every path git tracks under ``root``. Raises :class:`RuntimeError`."""
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or f"git ls-files failed ({proc.returncode})")
    return [p for p in proc.stdout.decode("utf-8", errors="surrogateescape").split("\0") if p]


def name_errors(paths: Sequence[str]) -> list[str]:
    """One error per tracked path named like a capture."""
    return [f"{p}: tracked capture name" for p in paths if NAME.search(p)]


def magic_errors(root: Path, paths: Sequence[str]) -> list[str]:
    """One error per tracked file starting with a capture magic."""
    errors = []
    for rel in paths:
        try:
            head = (root / rel).open("rb").read(4)
        except OSError:
            continue  # staged-deleted file, dangling symlink, gitlink
        if head in MAGICS:
            errors.append(f"{rel}: tracked file starts with a capture magic")
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(args[0]) if args else DEFAULT_ROOT
    try:
        paths = tracked_files(root)
    except RuntimeError as exc:
        print(f"check_no_captures: {exc}", file=sys.stderr)
        return 2
    if not paths:
        print(f"check_no_captures: no tracked files in {root}", file=sys.stderr)
        return 2
    errors = [*name_errors(paths), *magic_errors(root, paths)]
    for error in errors:
        print(f"check_no_captures: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"check_no_captures: {len(paths)} tracked files, no packet captures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
