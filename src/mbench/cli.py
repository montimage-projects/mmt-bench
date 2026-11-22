"""The ``mbench`` command line.

Each subcommand is filled in by its own issue in the mmt-bench v0 epic (#1).
``sut`` and ``validate`` are implemented (#4), ``corpus`` too (#7), and
``run`` and ``report`` (#8). ``sweep`` is still a stub that exits with
:data:`EXIT_NOT_IMPLEMENTED` and names the issue that implements it, so a
script or CI job calling one fails loudly instead of silently doing nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    p.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="record to check (sut.json, corpus/manifest.yaml, <pcap>.truth.json)",
    )
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
        if report.ok and report.kind != "sut":
            print(f"{report.path}: valid {report.kind} ({report.summary})")
        elif report.ok:
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


# --- mbench corpus -------------------------------------------------------------


def _configure_corpus(p: argparse.ArgumentParser) -> None:
    from mbench import corpus

    actions = p.add_subparsers(dest="action", metavar="<action>")
    gen = actions.add_parser(
        "gen",
        help="generate a synthetic set and add it to the manifest",
        description="Generate a synthetic pcap in pure Python under corpus/data/ "
        "and add its entry to the manifest. Byte-for-byte deterministic: the same "
        "set, seed, packet and flow counts always give the same file.",
    )
    gen.add_argument("set", choices=sorted(corpus.SETS), help="the synthetic set")
    gen.add_argument("--seed", type=int, default=0, metavar="N", help="default: 0")
    gen.add_argument(
        "--packets",
        type=int,
        default=None,
        metavar="N",
        help="packet count (default: the set's own)",
    )
    gen.add_argument(
        "--flows",
        type=int,
        default=None,
        metavar="N",
        help="distinct 5-tuples, round-robin (default: the set's own)",
    )
    gen.add_argument(
        "--label", default=None, metavar="NAME", help="manifest label (default: the set name)"
    )
    gen.add_argument(
        "--manifest",
        type=Path,
        default=corpus.DEFAULT_MANIFEST,
        metavar="PATH",
        help=f"default: {corpus.DEFAULT_MANIFEST}",
    )
    add = actions.add_parser(
        "add",
        help="register a local capture in the manifest",
        description="Register a pcap or pcapng that lives under the manifest's "
        "git-ignored data/ directory: every computed field comes from the file.",
    )
    add.add_argument("file", type=Path, metavar="PCAP", help="capture under corpus/data/")
    add.add_argument("--label", default=None, metavar="NAME", help="default: the file stem")
    add.add_argument("--source", required=True, metavar="TEXT", help="where it comes from")
    add.add_argument("--licence", required=True, metavar="ID", help="SPDX id or licence name")
    add.add_argument(
        "--ground-truth",
        default=None,
        metavar="PATH",
        help="expected-alerts file, relative to corpus/ (default: none)",
    )
    add.add_argument(
        "--local-only",
        action="store_true",
        help="never committed or published: shown only by label and sha256",
    )
    add.add_argument("--description", default=None, metavar="TEXT")
    add.add_argument(
        "--manifest",
        type=Path,
        default=corpus.DEFAULT_MANIFEST,
        metavar="PATH",
        help=f"default: {corpus.DEFAULT_MANIFEST}",
    )
    check = actions.add_parser(
        "check",
        help="compare each capture present with its manifest sha256",
        description="Verify every manifest entry whose file is present: sha256, "
        "then size, packet count and average packet size. A missing file is "
        "reported, never an error (captures are not committed); a mismatch or an "
        "unreadable file exits non-zero.",
    )
    check.add_argument(
        "labels", nargs="*", metavar="LABEL", help="check only these entries (default: all)"
    )
    check.add_argument(
        "--manifest",
        type=Path,
        default=corpus.DEFAULT_MANIFEST,
        metavar="PATH",
        help=f"default: {corpus.DEFAULT_MANIFEST}",
    )
    p.set_defaults(corpus_help=p.format_help)


def _load_manifest(path: Path, command: str) -> tuple[dict[str, Any] | None, int]:
    """Load and validate the manifest for a corpus action; print why not."""
    from mbench import corpus

    try:
        return corpus.load(path), EXIT_OK
    except corpus.ManifestError as exc:
        print(f"mbench corpus {command}: {exc}", file=sys.stderr)
        for problem in exc.problems:
            print(f"  {problem}", file=sys.stderr)
        return None, EXIT_INVALID if exc.problems else EXIT_USAGE
    except OSError as exc:
        print(f"mbench corpus {command}: {exc}", file=sys.stderr)
        return None, EXIT_USAGE


def _corpus_gen(ns: argparse.Namespace) -> int:
    from mbench import corpus

    spec = corpus.SETS[ns.set]
    label = ns.label or spec.name
    packets = spec.packets if ns.packets is None else ns.packets
    # The set's own flow count is clamped to what ``packets`` allows; an
    # explicit --flows too large is an error.
    flows = min(spec.flows, corpus.max_flows(spec, packets)) if ns.flows is None else ns.flows
    manifest, status = _load_manifest(ns.manifest, "gen")
    if manifest is None:
        return status
    try:
        entry, outcome = corpus.gen_entry(
            ns.manifest, spec, ns.seed, packets, flows, label, manifest
        )
    except corpus.ManifestError as exc:
        print(f"mbench corpus gen: {exc}", file=sys.stderr)
        for problem in exc.problems:
            print(f"  {problem}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, ValueError) as exc:
        print(f"mbench corpus gen: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(
        f"{entry['path']}: {outcome} ({entry['packets']} packets of "
        f"{entry['avg_packet_bytes']:g} B, sha256 {entry['sha256']})"
    )
    return EXIT_OK


def _corpus_add(ns: argparse.Namespace) -> int:
    from mbench import corpus

    manifest, status = _load_manifest(ns.manifest, "add")
    if manifest is None:
        return status
    try:
        entry = corpus.entry_from_file(
            ns.manifest,
            ns.file,
            label=ns.label or ns.file.stem,
            source=ns.source,
            licence=ns.licence,
            ground_truth=ns.ground_truth,
            local_only=ns.local_only,
            description=ns.description,
        )
    except (OSError, ValueError) as exc:
        print(f"mbench corpus add: {exc}", file=sys.stderr)
        return EXIT_USAGE
    outcome = corpus.upsert(manifest, entry)
    if outcome != "unchanged":
        try:
            corpus.checked_save(ns.manifest, manifest)
        except corpus.ManifestError as exc:
            print(f"mbench corpus add: {exc}", file=sys.stderr)
            for problem in exc.problems:
                print(f"  {problem}", file=sys.stderr)
            return EXIT_USAGE
    print(
        f"{entry['path']}: entry {outcome} (sha256 {entry['sha256']}, "
        f"{entry['packets']} packets of {entry['avg_packet_bytes']:g} B"
        f"{', local-only' if entry['local_only'] else ''})"
    )
    return EXIT_OK


def _corpus_check(ns: argparse.Namespace) -> int:
    from mbench import corpus

    manifest, status = _load_manifest(ns.manifest, "check")
    if manifest is None:
        return status
    unknown = [label for label in ns.labels if corpus.find_entry(manifest, label) is None]
    if unknown:
        print(f"mbench corpus check: no manifest entry for {', '.join(unknown)}", file=sys.stderr)
        return EXIT_USAGE
    entries = (
        [corpus.find_entry(manifest, label) for label in ns.labels]
        if ns.labels
        else manifest["entries"]
    )
    checks = [corpus.check_entry(ns.manifest, e) for e in entries if e is not None]
    bad = 0
    for check in checks:
        if check.status == "ok":
            print(f"{check.label}: ok")
        else:
            print(f"{check.label}: {check.status.upper()}")
            for problem in check.problems:
                print(f"  {problem}")
            if check.status != "missing":
                bad += 1
    counts = {s: sum(1 for c in checks if c.status == s) for s in ("ok", "missing")}
    print(f"{len(checks)} checked: {counts['ok']} ok, {counts['missing']} missing, {bad} failed")
    return EXIT_INVALID if bad else EXIT_OK


def _run_corpus(ns: argparse.Namespace) -> int:
    if ns.action == "gen":
        return _corpus_gen(ns)
    if ns.action == "add":
        return _corpus_add(ns)
    if ns.action == "check":
        return _corpus_check(ns)
    print(ns.corpus_help(), file=sys.stderr)
    return EXIT_USAGE


# --- mbench run ----------------------------------------------------------------


def _configure_run(p: argparse.ArgumentParser) -> None:
    from mbench import corpus, runner

    p.add_argument(
        "campaign",
        type=Path,
        metavar="CAMPAIGN",
        help="the campaign file (campaigns/<x>.yaml)",
    )
    p.add_argument(
        "--results",
        type=Path,
        default=runner.DEFAULT_RESULTS,
        metavar="DIR",
        help=f"results root (default: {runner.DEFAULT_RESULTS}); "
        "a tool-comparison campaign goes under local/ instead",
    )
    p.add_argument(
        "--manifest",
        type=Path,
        default=corpus.DEFAULT_MANIFEST,
        metavar="PATH",
        help=f"corpus manifest (default: {corpus.DEFAULT_MANIFEST})",
    )


def _run_run(ns: argparse.Namespace) -> int:
    from mbench import matrix, runner

    try:
        campaign = matrix.load(ns.campaign, manifest_path=ns.manifest)
    except matrix.CampaignError as exc:
        print(f"mbench run: {exc}", file=sys.stderr)
        for problem in exc.problems:
            print(f"  {problem}", file=sys.stderr)
        # Invalid record -> EXIT_INVALID; unresolved reference -> EXIT_USAGE.
        return EXIT_INVALID if exc.problems else EXIT_USAGE
    except (OSError, ValueError) as exc:
        print(f"mbench run: {exc}", file=sys.stderr)
        return EXIT_USAGE

    tools = {cell.tool for cell in campaign.cells}
    results_dir = ns.results
    if len(tools) > 1:
        # A tool-comparison report stays out of git until the licence and
        # fairness review: the whole results dir goes under local/.
        results_dir = Path("local") / "results"
        print(
            f"mbench run: {len(tools)} tools compared — results go under "
            f"{results_dir}/ (tool-comparison reports are not committed)",
            file=sys.stderr,
        )
    outcome = runner.run_campaign(campaign, results_dir=results_dir)
    print(
        f"mbench run: {outcome.directory}: {len(outcome.run_files)} runs "
        f"({outcome.valid} valid, {outcome.invalid} invalid, {outcome.failed} failed); "
        f"report: {outcome.report_file}"
    )
    return EXIT_OK if outcome.valid else EXIT_INVALID


# --- mbench report -------------------------------------------------------------


def _configure_report(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "directory",
        type=Path,
        metavar="DIR",
        help="a results directory (results/<date>-<campaign>/)",
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="PATH",
        help="where to write REPORT.md (default: inside DIR, append-only; "
        "'-' writes to standard output)",
    )


def _run_report(ns: argparse.Namespace) -> int:
    from mbench import runner
    from mbench.report import render

    directory = ns.directory
    if not directory.is_dir():
        print(f"mbench report: no such directory: {directory}", file=sys.stderr)
        return EXIT_USAGE
    _, runs = render.load_dir(directory)
    text = render.render_dir(directory)
    tools = {
        str(r.record.get("cell", {}).get("tool"))
        for r in runs
        if isinstance(r.record.get("cell"), dict)
    }
    local = "local" in directory.resolve().parts
    if ns.output == "-" or (ns.output is None and len(tools) > 1 and not local):
        if len(tools) > 1 and not local and ns.output is None:
            print(
                "mbench report: this report compares tools — writing it under "
                "this directory would commit it; it is printed instead "
                "(keep it under local/)",
                file=sys.stderr,
            )
        sys.stdout.write(text)
        return EXIT_OK
    out = Path(ns.output) if ns.output is not None else directory / "REPORT.md"
    try:
        runner.write(out, text)
    except FileExistsError:
        print(f"mbench report: {out} exists — results are append-only", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"mbench report: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(f"mbench report: wrote {out}")
    return EXIT_OK


SUBCOMMANDS: tuple[Subcommand, ...] = (
    Subcommand(
        "sut",
        "collect the system-under-test fingerprint (sut.json)",
        4,
        _configure_sut,
        _run_sut,
    ),
    Subcommand(
        "corpus",
        "manage and generate the pcap corpus",
        7,
        _configure_corpus,
        _run_corpus,
    ),
    Subcommand(
        "run",
        "run a campaign and write its results",
        8,
        _configure_run,
        _run_run,
    ),
    Subcommand("sweep", "run a parameter sweep across a campaign matrix", 17),
    Subcommand(
        "report",
        "render REPORT.md from a results directory",
        8,
        _configure_report,
        _run_report,
    ),
    Subcommand(
        "validate",
        "check a record (sut.json, campaign, manifest, truth) for completeness",
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
