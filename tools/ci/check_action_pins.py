r"""Fail when a GitHub Actions workflow uses an action that is not pinned safely.

Repo policy allows only GitHub-owned actions (``actions/*``), each pinned to a
full 40-hex commit SHA. This check enforces the same rule in CI, so a tag or
branch ref, a short SHA, a third-party action, a ``docker://`` image or a local
``./`` action fails the build with the file and line that broke it.

Usage: ``python tools/ci/check_action_pins.py [WORKFLOW_DIR]`` (default: the
repo's ``.github/workflows``, found from this file's location, not the cwd).
Exit 0 when every ``uses:`` is pinned, 1 when one is not, 2 when nothing was
checked: no workflow file, or no ``uses:`` at all, so an empty run never
passes silently.

What it catches: the common mistakes above, a ``uses:`` line it cannot parse
(a flow mapping, a quoted key, a space before the colon), and the escaped and
explicit-key forms its tests cover: an explicit ``? key``, and a double-quoted
key with a ``\x``/``\u``/``\U`` escape, either of which could spell ``uses``.
It does not decode every YAML spelling of a key (an alias used as a key, for
example, is not caught). The enforcement is GitHub's own action policy for the
repo; this check fails early, in CI, with the file and line.

The scan is line-based on purpose: it needs no YAML library, so it runs before
any dependency is installed, and it sees every ``uses:`` key, in steps and in
reusable-workflow jobs alike.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

#: ``actions/<repo>[/<path>]@<40 lowercase hex>``, nothing else.
PINNED = re.compile(r"actions/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._/-]+)?@[0-9a-f]{40}")

#: A ``uses:`` key, as a mapping key or a list item (``- uses: ...``).
USES = re.compile(r"""^\s*(?:-\s+)?["']?uses["']?\s*:\s*(?P<value>.*)$""")

#: Any ``uses:`` token at all, to catch forms ``USES`` does not parse.
ANY_USES = re.compile(r"""(?<![A-Za-z0-9_-])["']?uses["']?\s*:""")

#: Key spellings a line scan cannot read, so any of them could hide ``uses``:
#: an explicit ``? key`` (the value follows on a ``:`` line) and a double-quoted
#: key with a ``\x``, ``\u`` or ``\U`` escape (``"\x75ses":``).
OPAQUE_KEY = re.compile(
    r"""^\s*(?:-\s+)*\?(?:\s|$)"""
    r"""|"(?:[^"\\]|\\.)*\\[xuU](?:[^"\\]|\\.)*"\s*:"""
)


def _strip_value(raw: str) -> str:
    """The value of a ``uses:`` line, without a trailing comment or quotes."""
    value = raw.strip()
    if value[:1] in {'"', "'"}:
        quote = value[0]
        end = value.find(quote, 1)
        return value[1:end] if end != -1 else value[1:]
    return value.split(" #", 1)[0].split("\t#", 1)[0].strip()


#: The repo's workflow directory, from this file's location (tools/ci/).
DEFAULT_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def count_uses(text: str) -> int:
    """How many non-comment lines of ``text`` carry a ``uses:`` key."""
    return sum(
        1
        for line in text.splitlines()
        if not line.lstrip().startswith("#") and ANY_USES.search(line)
    )


def check_text(text: str, source: str = "<workflow>") -> list[str]:
    """Return one error per ``uses:`` in ``text`` that is not safely pinned."""
    errors: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        if OPAQUE_KEY.search(line):
            # The key on this line may spell ``uses`` in a form the scan
            # cannot decode (one of the tested forms), so it is reported.
            errors.append(
                f"{source}:{lineno}: unreadable key (explicit '?' or escaped quoted key); "
                "write it as a plain key"
            )
            continue
        match = USES.match(line)
        if match is None:
            if ANY_USES.search(line):
                # A ``uses:`` this scanner cannot read (a flow mapping such
                # as ``- {uses: x}``) is reported, not assumed pinned.
                errors.append(f"{source}:{lineno}: unreadable 'uses:' line; write it as a key")
            continue
        ref = _strip_value(match.group("value"))
        if not PINNED.fullmatch(ref):
            errors.append(
                f"{source}:{lineno}: '{ref}' is not an actions/* action pinned to a "
                "40-hex commit SHA"
            )
    return errors


def workflow_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if p.suffix in {".yml", ".yaml"} and p.is_file())


def check_files(paths: Iterable[Path]) -> tuple[list[str], int]:
    """Errors across ``paths``, and the number of ``uses:`` lines seen."""
    errors: list[str] = []
    seen = 0
    for path in paths:
        text = path.read_text(encoding="utf-8")
        errors.extend(check_text(text, str(path)))
        seen += count_uses(text)
    return errors, seen


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    directory = Path(args[0]) if args else DEFAULT_DIR
    files = workflow_files(directory) if directory.is_dir() else []
    if not files:
        print(f"check_action_pins: no workflow files in {directory}", file=sys.stderr)
        return 2
    errors, seen = check_files(files)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    if seen == 0:
        print(f"check_action_pins: no 'uses:' found in {directory}", file=sys.stderr)
        return 2
    print(f"check_action_pins: {seen} action(s) in {len(files)} workflow file(s), all pinned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
