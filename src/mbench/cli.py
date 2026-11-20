"""The ``mbench`` command line.

Each subcommand is filled in by its own issue in the mmt-bench v0 epic (#1).
Until then it is a stub that exits with :data:`EXIT_NOT_IMPLEMENTED` and names
the issue that will implement it, so a script or CI job calling it fails loudly
instead of silently doing nothing.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from mbench import __version__

#: Exit status of a subcommand that is not implemented yet. Distinct from
#: argparse's usage-error status (2) so callers can tell the two apart.
EXIT_NOT_IMPLEMENTED = 3


@dataclass(frozen=True)
class Subcommand:
    """A subcommand, its one-line help, and the issue that implements it."""

    name: str
    help: str
    issue: int


SUBCOMMANDS: tuple[Subcommand, ...] = (
    Subcommand("sut", "collect the system-under-test fingerprint (sut.json)", 4),
    Subcommand("corpus", "manage and generate the pcap corpus", 7),
    Subcommand("run", "run a campaign and write its results", 8),
    Subcommand("sweep", "run a parameter sweep across a campaign matrix", 17),
    Subcommand("report", "render REPORT.md from a results directory", 8),
    Subcommand("validate", "check a record (sut.json, campaign, manifest) for completeness", 4),
)


def not_implemented_message(sub: Subcommand) -> str:
    """The message a stub prints, naming the issue that will implement it."""
    return f"mbench {sub.name}: not implemented yet (#{sub.issue})"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mbench",
        description="Tool-agnostic benchmark harness for network security engines.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for sub in SUBCOMMANDS:
        sp = subparsers.add_parser(
            sub.name,
            help=sub.help,
            description=f"{sub.help} (not implemented yet, see #{sub.issue})",
        )
        sp.set_defaults(subcommand=sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = list(sys.argv[1:] if argv is None else argv)
    # parse_known_args, so a call written for the finished subcommand
    # (``mbench sut -o sut.json``, ``mbench run campaigns/smoke.yaml``) still
    # reaches the stub and gets the not-implemented message, not a usage error.
    ns, extra = parser.parse_known_args(args)
    sub: Subcommand | None = getattr(ns, "subcommand", None)
    if sub is None:
        if extra:
            parser.error(f"unrecognized arguments: {' '.join(extra)}")
        parser.print_help(sys.stderr)
        return 2
    # parse_known_args also swallows an unknown *global* option
    # (``mbench --bogus sut``). The global options take no value, so the first
    # subcommand name ends them: parsing that prefix strictly makes an unknown
    # one a usage error (exit 2), as it is without a subcommand.
    parser.parse_args(args[: args.index(sub.name)])
    print(not_implemented_message(sub), file=sys.stderr)
    return EXIT_NOT_IMPLEMENTED


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
