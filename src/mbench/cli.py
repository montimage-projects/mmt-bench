"""The ``mbench`` command line.

Each subcommand is filled in by its own issue in the mmt-bench v0 epic (#1).
``sut`` and ``validate`` are implemented (#4). The others are still stubs that
exit with :data:`EXIT_NOT_IMPLEMENTED` and name the issue that will implement
them, so a script or CI job calling one fails loudly instead of silently doing
nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from mbench import __version__

#: Exit status of a subcommand that is not implemented yet. Distinct from
#: argparse's usage-error status (2) so callers can tell the two apart.
EXIT_NOT_IMPLEMENTED = 3

#: ``mbench validate``: every record is complete. ``mbench sut``: the record
#: was written and is complete.
EXIT_OK = 0
#: ``mbench validate``: at least one record is incomplete or invalid.
#: ``mbench sut``: the record was written but does not validate.
EXIT_INVALID = 1
#: A file could not be read, or is not a kind of record mbench checks.
EXIT_USAGE = 2

#: The alias ``mbench sut --anonymise`` uses when none is given.
DEFAULT_ALIAS = "sut"


@dataclass(frozen=True)
class Subcommand:
    """A subcommand, its one-line help, and the issue that implements it.

    ``configure`` adds the subcommand's arguments and ``handler`` runs it;
    both are ``None`` while the subcommand is a stub.
    """

    name: str
    help: str
    issue: int
    configure: Callable[[argparse.ArgumentParser], None] | None = None
    handler: Callable[[argparse.Namespace], int] | None = None

    @property
    def implemented(self) -> bool:
        return self.handler is not None


def not_implemented_message(sub: Subcommand) -> str:
    """The message a stub prints, naming the issue that will implement it."""
    return f"mbench {sub.name}: not implemented yet (#{sub.issue})"


# --- mbench sut ----------------------------------------------------------------


def _configure_sut(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-o",
        "--output",
        default="-",
        metavar="PATH",
        help="where to write sut.json (default: standard output)",
    )
    p.add_argument(
        "--anonymise",
        nargs="?",
        const=DEFAULT_ALIAS,
        default=None,
        metavar="ALIAS",
        help=f"record ALIAS instead of the hostname (default alias: {DEFAULT_ALIAS!r})",
    )
    p.add_argument(
        "--nic",
        action="append",
        default=[],
        metavar="IFACE",
        help=(
            "the interface under test: its link state is hashed, and a virtual one "
            "(a veth) is recorded only when named here; repeatable"
        ),
    )
    p.add_argument(
        "--watch",
        action="append",
        default=[],
        metavar="UNIT",
        help="also record this systemd unit's state (the vLLM units always are); repeatable",
    )
    p.add_argument(
        "--sample-seconds",
        type=float,
        default=1.0,
        metavar="S",
        help="window over which the top CPU processes are measured (default: 1)",
    )
    p.add_argument(
        "--top", type=int, default=10, metavar="N", help="processes listed (default: 10)"
    )
    p.add_argument(
        "--record-sources",
        metavar="PATH",
        help="also write every source read, sanitised, as a replayable fixture",
    )


def _run_sut(ns: argparse.Namespace) -> int:
    from mbench import hostsrc, sut, validate

    if ns.sample_seconds <= 0 or ns.top < 1:
        print("mbench sut: --sample-seconds must be > 0 and --top >= 1", file=sys.stderr)
        return EXIT_USAGE
    units = list(dict.fromkeys([*sut.VLLM_UNITS, *ns.watch]))
    options = sut.Options(
        alias=ns.anonymise,
        extra_nics=ns.nic,
        watch_units=units,
        sample_seconds=ns.sample_seconds,
        top_n=ns.top,
    )
    recorder = hostsrc.RecordingSource() if ns.record_sources else None
    source: hostsrc.Source = recorder if recorder is not None else hostsrc.LiveSource()
    try:
        record = sut.collect(source, options)
    except ValueError as exc:
        print(f"mbench sut: {exc}", file=sys.stderr)
        return EXIT_USAGE
    text = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if ns.output == "-":
        sys.stdout.write(text)
    else:
        Path(ns.output).write_text(text, encoding="utf-8")
    if recorder is not None:
        _write_sources(recorder, record, ns.anonymise or DEFAULT_ALIAS, ns.record_sources)

    missing = sut.unavailable_fields(record)
    where = "standard output" if ns.output == "-" else ns.output
    print(
        f"mbench sut: wrote {where}: scope {record['scope']}, "
        f"{sut.field_count(record)} fields, {len(missing)} unavailable, {record['sut_hash']}",
        file=sys.stderr,
    )
    for path, kind, reason in missing:
        print(f"  {kind:<15} {path}: {reason}", file=sys.stderr)
    # The collector checks its own record, so a host it does not handle is
    # never reported as a success.
    problems = validate.sut_errors(record)
    if problems:
        print(f"mbench sut: the record is INVALID ({len(problems)} problems):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return EXIT_INVALID
    return EXIT_OK


def _write_sources(recorder: object, record: dict[str, object], alias: str, out: str) -> None:
    from mbench import hostsrc

    assert isinstance(recorder, hostsrc.RecordingSource)
    snapshot = recorder.snapshot()
    hostname_answers = snapshot["files"].get("/proc/sys/kernel/hostname", [])
    hostname = hostname_answers[0].strip() if hostname_answers else None
    noise = record["noise"]
    assert isinstance(noise, dict)
    keep = {
        int(p["pid"])
        for key in ("top_cpu", "top_memory")
        if isinstance(noise.get(key), list)
        for p in noise[key]
    }
    nics = record["nics"]
    names = {str(n["name"]) for n in nics} if isinstance(nics, list) else set()
    clean = hostsrc.sanitise_snapshot(snapshot, hostname, alias, keep, names)
    Path(out).write_text(json.dumps(clean, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"mbench sut: wrote sanitised sources to {out}", file=sys.stderr)


# --- mbench validate -----------------------------------------------------------


def _configure_validate(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="+", metavar="PATH", help="record to check (sut.json)")
    p.add_argument("-q", "--quiet", action="store_true", help="do not list the unavailable fields")


def _run_validate(ns: argparse.Namespace) -> int:
    from mbench import validate

    status = EXIT_OK
    for path in ns.paths:
        try:
            report = validate.validate_file(path)
        except (OSError, validate.UnsupportedRecord, validate.UnreadableRecord) as exc:
            print(f"mbench validate: {exc}", file=sys.stderr)
            status = max(status, EXIT_USAGE)
            continue
        if report.ok:
            print(
                f"{report.path}: valid {report.kind} record (scope {report.scope}, "
                f"{report.fields} fields, {len(report.unavailable)} unavailable)"
            )
            if not ns.quiet:
                for field_path, kind, reason in report.unavailable:
                    print(f"  unavailable {kind:<15} {field_path}: {reason}")
        else:
            print(f"{report.path}: INVALID ({len(report.errors)} problems)")
            for error in report.errors:
                print(f"  {error}")
            status = max(status, EXIT_INVALID)
    return status


SUBCOMMANDS: tuple[Subcommand, ...] = (
    Subcommand(
        "sut",
        "collect the system-under-test fingerprint (sut.json)",
        4,
        _configure_sut,
        _run_sut,
    ),
    Subcommand("corpus", "manage and generate the pcap corpus", 7),
    Subcommand("run", "run a campaign and write its results", 8),
    Subcommand("sweep", "run a parameter sweep across a campaign matrix", 17),
    Subcommand("report", "render REPORT.md from a results directory", 8),
    Subcommand(
        "validate",
        "check a record (sut.json, campaign, manifest) for completeness",
        4,
        _configure_validate,
        _run_validate,
    ),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mbench",
        description="Tool-agnostic benchmark harness for network security engines.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for sub in SUBCOMMANDS:
        description = (
            sub.help if sub.implemented else f"{sub.help} (not implemented yet, see #{sub.issue})"
        )
        sp = subparsers.add_parser(sub.name, help=sub.help, description=description)
        if sub.configure is not None:
            sub.configure(sp)
        sp.set_defaults(subcommand=sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = list(sys.argv[1:] if argv is None else argv)
    # parse_known_args, so a call written for a finished stub subcommand
    # (``mbench run campaigns/smoke.yaml``) still reaches the stub and gets the
    # not-implemented message, not a usage error.
    ns, extra = parser.parse_known_args(args)
    sub: Subcommand | None = getattr(ns, "subcommand", None)
    if sub is None:
        if extra:
            parser.error(f"unrecognized arguments: {' '.join(extra)}")
        parser.print_help(sys.stderr)
        return 2
    if sub.handler is not None:
        # An implemented subcommand parses its arguments strictly.
        return sub.handler(parser.parse_args(args))
    # parse_known_args also swallows an unknown *global* option
    # (``mbench --bogus run``). The global options take no value, so the first
    # subcommand name ends them: parsing that prefix strictly makes an unknown
    # one a usage error (exit 2), as it is without a subcommand.
    parser.parse_args(args[: args.index(sub.name)])
    print(not_implemented_message(sub), file=sys.stderr)
    return EXIT_NOT_IMPLEMENTED


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
