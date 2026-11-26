"""The campaign runner (#8): isolation, warm-up, repeats, pinning, timeouts.

``mbench run campaigns/<x>.yaml`` expands the campaign's matrix
(:mod:`mbench.matrix`), runs each cell as one warm-up pass plus ``repeats``
measured passes in offline mode (:mod:`mbench.modes.offline`), and writes:

.. code-block:: text

    results/<date>-<campaign>/
        sut.json                    the campaign's host-scope SUT record
        runs/<batch>-<NN>-<slug>.json   one run per matrix cell
        REPORT.md                   rendered over every run file in the dir

Everything under a results directory is **append-only**: :func:`write` opens
files ``O_EXCL``, so an existing file is never overwritten and a re-run of
the same campaign on the same date only adds a new ``<batch>-*.json`` per
cell (and ``sut-<batch>.json`` / ``REPORT-<batch>.md`` when the plain names
are taken).

Each run embeds its full SUT record — the campaign's host-scope record with
``scope`` flipped to ``run``, the adapter's ``tools`` item, the run's times,
the pcap sha256 and the run container's cgroup limits. A record that fails
``mbench validate``'s check marks the run ``invalid``; it is written but
excluded from every report table. A pass that exceeds ``timeout_s`` is
killed and recorded ``timeout``; it never counts as a measurement.

A cell that raises is a run record too — ``error``, or ``interrupted`` on
``KeyboardInterrupt``/``SystemExit`` — with the exception in ``problems``;
the campaign continues after an error and stops after an interrupt.
``REPORT.md`` is always rendered over whatever run files exist, and the
tmpfs staging dir is removed on every exit path. ``mbench run`` also
catches SIGTERM and SIGHUP, raising :class:`SignalExit` so the default
kill signal takes the same interrupted path; SIGKILL cannot be caught.
A signal landing inside the final cleanup or the interrupted-record
write is deferred — recorded, not raised — until the section finishes,
then re-raised, so the cleanup always completes (review N3).

For a ``quiet_host`` campaign the runner only **prints** the commands that
stop and restart ``vllm-qwen.service`` and ``vllm-health-watchdog.timer``
(``systemctl --user``, user units — the decision of 2026-11-21); it never
runs them and never uses sudo.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import shutil
import signal
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from types import FrameType

from mbench import hostsrc, sut, truth, validate
from mbench.adapters import ADAPTERS
from mbench.adapters.base import Adapter, Json
from mbench.matrix import Campaign, Cell
from mbench.metrics import perf
from mbench.modes import offline

#: Where results go, relative to the working directory.
DEFAULT_RESULTS = Path("results")

#: The vLLM units a quiet-host campaign needs stopped/started, and the
#: commands printed for Luong (user units: `systemctl --user`, never sudo).
QUIET_STOP = "systemctl --user stop vllm-qwen.service vllm-health-watchdog.timer"
QUIET_START = "systemctl --user start vllm-qwen.service vllm-health-watchdog.timer"


def utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _batch_id(ts: datetime) -> str:
    return ts.strftime("%Y%m%dT%H%M%SZ")


def write(path: Path, text: str) -> None:
    """Write ``text`` to ``path``, failing when the file already exists.

    Results are append-only (AGENTS.md): every result file goes through this
    ``O_EXCL`` open, so nothing under ``results/<date>-<campaign>/`` is ever
    overwritten or replaced.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _unique(path: Path, batch: str, ext: str) -> Path:
    """``name.ext``, else ``name-<batch>.ext``, then ``name-<batch>-N.ext``.

    A taken name gets the batch suffix — the same scheme ``_free_batch``
    gives a repeated batch — and a name taken inside the same second keeps
    counting up (``-2``, ``-3`` …), like the ``batch-N`` run files, so
    ``mbench report`` re-renders never fail with "exists".
    """
    if not path.exists():
        return path
    candidate = path.with_name(f"{path.stem}-{batch}{ext}")
    n = 1
    while candidate.exists():
        n += 1
        candidate = path.with_name(f"{path.stem}-{batch}-{n}{ext}")
    return candidate


def _free_batch(directory: Path, batch: str) -> str:
    """A batch id ``directory`` has not seen: ``batch``, else ``batch-2``, ...

    Every file of one batch carries the id (``runs/<batch>-*.json``,
    ``sut-<batch>.json``, ``REPORT-<batch>.md``), so checking for any of
    them — plus the first batch's plain ``sut.json`` and ``REPORT.md`` —
    keeps a repeat run under the same clock from reusing names.
    """
    runs = directory / "runs"
    candidate = batch
    n = 1
    while True:
        taken = (
            any(runs.glob(f"{candidate}-*.json"))
            or (directory / f"sut-{candidate}.json").exists()
            or (directory / f"REPORT-{candidate}.md").exists()
        )
        if n == 1:
            taken = taken or (directory / "sut.json").exists() or (directory / "REPORT.md").exists()
        if not taken:
            return candidate
        n += 1
        candidate = f"{batch}-{n}"


def core_type(record: dict[str, Json], cpuset: Sequence[int]) -> Json:
    """The model name of the core type covering ``cpuset``, from the SUT record.

    ``"unpinned"`` when the run was not pinned, the model name when every cpu
    is of one type, ``"mixed: A+B"`` across types, and an unavailable marker
    when the record cannot say.
    """
    if not cpuset:
        return "unpinned"
    cpu = record.get("host", {}).get("cpu", {})
    core_types = cpu.get("core_types") if isinstance(cpu, dict) else None
    if not isinstance(core_types, list) or not core_types:
        return sut.unavailable("error", "the SUT record has no cpu.core_types")
    types: dict[str, list[int]] = {}
    unknown: list[int] = []
    for cpu_id in cpuset:
        name = next(
            (
                ct["model_name"]
                for ct in core_types
                if isinstance(ct, dict)
                and isinstance(ct.get("cpus"), str)
                and cpu_id in sut.parse_cpulist(ct["cpus"])
                and isinstance(ct.get("model_name"), str)
            ),
            None,
        )
        if name is None:
            unknown.append(cpu_id)
        else:
            types.setdefault(name, []).append(cpu_id)
    if len(types) == 1 and not unknown:
        return next(iter(types))
    covered = "+".join(sorted(types))
    if types:
        return f"mixed: {covered}" + (
            f" (+unknown: {sut.format_cpulist(unknown)})" if unknown else ""
        )
    return sut.unavailable("error", f"no core type covers cpus {sut.format_cpulist(cpuset)}")


def run_scope_sut(
    host_record: dict[str, Json],
    tools: list[dict[str, Json]],
    per_run: dict[str, Json],
    run_times: tuple[datetime, datetime],
    pcaps: Sequence[dict[str, str]],
) -> dict[str, Json]:
    """The run-scope SUT record: the host record plus the run's own fields.

    ``sut_hash`` is recomputed — it covers only the hardware and OS sections,
    so it equals the host record's — and the record must validate under the
    schema's run scope (``tools`` a real array, ``harness.run`` and
    ``harness.pcaps`` objects, ``container_runtime.limits.per_run`` a
    cgroup-limits object).
    """
    record = copy.deepcopy(host_record)
    start, end = run_times
    record["scope"] = "run"
    record["tools"] = tools
    runtime = record.get("container_runtime")
    if isinstance(runtime, dict) and isinstance(runtime.get("limits"), dict):
        runtime["limits"]["per_run"] = per_run
    # A missing or marker container_runtime/harness stays untouched: the
    # schema check below then marks the run invalid rather than crashing.
    harness = record.get("harness")
    if isinstance(harness, dict):
        harness["run"] = {"start": _iso(start), "end": _iso(end)}
        harness["pcaps"] = list(pcaps)
    # An unhashable record is an invalid one; validate reports why.
    with contextlib.suppress(KeyError, TypeError):
        record["sut_hash"] = sut.sut_hash(record)
    return record


def _slug(cell: Cell) -> str:
    """A short filename-safe summary of the cell."""
    extra = "".join(
        f"-{k}{v:g}" if isinstance(v, float) else f"-{k}{v}" for k, v in sorted(cell.extra.items())
    )
    raw = (
        f"{cell.tool}-{cell.corpus.label}-{cell.ruleset.id}-"
        f"{cell.config_profile}-t{cell.threads}-c{cell.cpuset_str or 'all'}{extra}"
    )
    return re.sub(r"[^a-z0-9._-]+", "_", raw.lower())[:80]


def _failed_cell_record(
    campaign: Campaign,
    cell: Cell,
    exc: BaseException,
    *,
    batch: str,
    tmpfs: bool,
    at: datetime,
    what: str,
) -> dict[str, Json]:
    """The run record of a cell that never measured: what failed and why.

    ``error`` for an exception — a failed adapter build, a stage or prepare
    error, a crashed pass — and ``interrupted`` for
    ``KeyboardInterrupt``/``SystemExit``. What raised, in ``what``, and the
    exception itself go to ``problems``.
    """
    status = "interrupted" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "error"
    return {
        "schema_version": 1,
        "batch": batch,
        "campaign": campaign.meta(),
        "cell": {"index": cell.index, "tool": cell.tool},
        "status": status,
        "problems": [f"{what}: {type(exc).__name__}: {exc}"],
        "started_at": _iso(at),
        "ended_at": _iso(at),
        "mode": {"name": campaign.mode, "tmpfs": tmpfs},
        "passes": [],
    }


def _pass_record(
    kind: str, n: int, outcome: offline.Outcome, gt: truth.GroundTruth | None, tool: str
) -> dict[str, Json]:
    """One pass of a run as the run's JSON records it.

    Throughput uses the tool's own processing interval when the pass
    carries one (``timing.basis == "tool"``), else wall time — the
    methodology's basis, with the fallback labelled. ``expected_packets``
    records the corpus count the tool's counters were checked against.
    """
    record: dict[str, Json] = {
        "kind": kind,
        "n": n,
        "status": outcome.status,
        "wall_s": round(outcome.wall_s, 6),
        "returncode": outcome.returncode,
    }
    if outcome.timing is not None:
        record["timing"] = outcome.timing
    if outcome.expected_packets is not None:
        record["expected_packets"] = outcome.expected_packets
    if outcome.perf is not None:
        record["perf"] = outcome.perf
    if outcome.status != "ok":
        record["detail"] = outcome.detail
        return record
    assert outcome.counters is not None and outcome.alerts is not None
    counters = outcome.counters
    basis = outcome.timing["processing_s"] if outcome.timing else None
    seconds = basis if isinstance(basis, int | float) and basis > 0 else outcome.wall_s
    record.update(
        {
            "packets": counters.packets,
            "bytes": counters.bytes,
            "drops": counters.drops,
            "gbps": round(counters.bytes * 8 / seconds / 1e9, 4) if seconds > 0 else None,
            "mpps": round(counters.packets / seconds / 1e6, 4) if seconds > 0 else None,
            "alerts": len(outcome.alerts),
            "extra": dict(counters.extra),
        }
    )
    if gt is not None:
        record["detection"] = truth.score(outcome.alerts, gt, tool=tool).to_dict()
    return record


def run_cell(
    adapter: Adapter,
    campaign: Campaign,
    cell: Cell,
    *,
    workdir: Path,
    stage_dir: Path,
    tmpfs: bool,
    host_record: dict[str, Json],
    batch: str,
    clock: Callable[[], datetime] = utcnow,
    monotonic: Callable[[], float] = time.monotonic,
    perf_probe: perf.Probe | None = None,
    harness_cpuset: Sequence[int] = (),
) -> dict[str, Json]:
    """Run one matrix cell: one warm-up pass, then ``repeats`` measured ones.

    Returns the run record, which the caller writes under ``runs/``. The
    record embeds the run-scope SUT; when that record does not validate, the
    run is ``invalid``. ``harness_cpuset`` is the cpuset the harness pinned
    itself to for this cell (the cores the tool does not use), recorded so a
    run proves the measurement was not self-disturbed.
    """
    started = clock()
    staged = offline.stage_pcap(cell.corpus.path, cell.corpus.sha256, stage_dir)

    passes: list[dict[str, Json]] = []
    plan = [("warmup", 0), *[("measured", n) for n in range(1, campaign.repeats + 1)]]
    problems: list[str] = []
    for kind, n in plan:
        outcome = offline.run_pass(
            adapter,
            cell.ruleset,
            cell.config_profile,
            workdir / ("warmup" if kind == "warmup" else f"pass-{n}"),
            staged,
            cell.threads,
            cell.cpuset,
            campaign.timeout_s,
            clock=monotonic,
            # The corpus's declared packet count is what the tool's
            # counters must equal — a mismatch invalidates the pass (B2).
            expected_packets=cell.corpus.packets,
            # The warm-up warms caches; cycles/pkt belongs to the measured
            # passes only.
            perf_probe=perf_probe if kind == "measured" else None,
        )
        passes.append(_pass_record(kind, n, outcome, cell.corpus.truth, adapter.name))
        if outcome.status == "invalid":
            problems.append(f"{kind} pass {n}: {outcome.detail}")
    ended = clock()

    try:
        tools = [adapter.tools_record()]
    except Exception as exc:
        tools = []
        problems.append(f"tools record: {type(exc).__name__}: {exc}")
    try:
        per_run = adapter.container_limits(cell.cpuset)
    except Exception as exc:
        marker = sut.unavailable("error", f"the run's container limits: {exc}")
        per_run = {"cpu_max": marker, "memory_max": marker, "cpuset_cpus": marker}

    run_sut = run_scope_sut(
        host_record,
        tools,
        per_run,
        (started, ended),
        [{"name": cell.corpus.label, "sha256": cell.corpus.sha256}],
    )
    problems.extend(validate.sut_errors(run_sut))

    measured = [p for p in passes if p["kind"] == "measured"]
    ok = sum(1 for p in measured if p["status"] == "ok")
    if problems:
        status = "invalid"
    elif ok == 0:
        status = "timeout" if any(p["status"] == "timeout" for p in measured) else "error"
    elif ok < len(measured):
        status = "partial"
    else:
        status = "ok"

    cell_desc: dict[str, Json] = {
        "index": cell.index,
        "tool": cell.tool,
        "ruleset": {"id": cell.ruleset.id, "sha256": cell.ruleset.sha256()},
        "config_profile": cell.config_profile,
        "corpus": cell.corpus.ref,
        "threads": cell.threads,
        "cpuset": cell.cpuset_str,
        "core_type": core_type(host_record, cell.cpuset),
        # the cores the harness pinned itself to while the cell ran ("" =
        # not pinned): the "harness on other cores" half of the pinning rule
        "harness_cpuset": sut.format_cpulist(harness_cpuset) if harness_cpuset else "",
    }
    # Mode-specific dimensions a sweep pinned on the cell (``rate`` for the
    # online mode, #13) are recorded beside the campaign dimensions.
    for key in cell.extra:
        if key in cell_desc:
            raise ValueError(f"cell extra key {key!r} shadows a cell field")
    cell_desc.update(dict(cell.extra))
    return {
        "schema_version": 1,
        "batch": batch,
        "campaign": campaign.meta(),
        "cell": cell_desc,
        "status": status,
        "problems": problems,
        "started_at": _iso(started),
        "ended_at": _iso(ended),
        "mode": {"name": "offline", "pcap_staged": staged.name, "tmpfs": tmpfs},
        "passes": passes,
        "sut": run_sut,
    }


@dataclass
class CampaignOutcome:
    """What ``run_campaign`` left on disk."""

    directory: Path
    sut_file: Path | None
    run_files: list[Path] = field(default_factory=list)
    report_file: Path | None = None
    runs: list[dict[str, Json]] = field(default_factory=list)

    @property
    def valid(self) -> int:
        return sum(1 for r in self.runs if r["status"] in ("ok", "partial"))

    @property
    def invalid(self) -> int:
        return sum(1 for r in self.runs if r["status"] == "invalid")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.runs if r["status"] in ("timeout", "error", "interrupted"))


def _collect_sut() -> dict[str, Json]:
    """The campaign's host-scope record, collected as the invoking user.

    The hostname is anonymised to ``sut`` (results are committed to a public
    repository); the collector never uses sudo.
    """
    return sut.collect(hostsrc.LiveSource(), sut.Options(alias="sut"))


#: The signals ``mbench run`` turns into :class:`SignalExit`. The
#: interpreter's default for both kills it outright — no ``finally``, no
#: run record, a live container left behind — so SIGTERM (the default
#: ``kill``, ``timeout``, CI cancellation, ``systemctl stop``) and SIGHUP
#: (a hung-up terminal) are routed through the interrupted path. SIGINT
#: needs no handler — it is already ``KeyboardInterrupt`` — and SIGKILL
#: cannot be caught.
SIGNALS_CAUGHT = (signal.SIGTERM, signal.SIGHUP)


class SignalExit(SystemExit):
    """``SystemExit`` raised by the ``mbench run`` signal handlers.

    The exit code is ``128 + signum``, the shell convention for a death by
    that signal, so an interrupted ``mbench run`` exits with the same
    status as an uncaught one; ``str`` names the signal, so the
    ``interrupted`` run record can say ``received SIGTERM`` instead of
    only ``143``.
    """

    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__(128 + signum)

    def __str__(self) -> str:
        return f"received {signal.Signals(self.signum).name}"


class _SignalState:
    """The shared state of a campaign's signal handlers.

    ``pending`` is ``None`` while a caught signal raises the interrupt
    right away, and a list while a section defers them
    (:func:`_defer_signals`): the handler then appends the interrupt to
    the list instead of raising it. One slot keeps the defer windows
    atomic — entering or leaving one is a single store, with no moment
    where a signal could still raise inside the protected section.
    """

    __slots__ = ("pending",)

    def __init__(self) -> None:
        self.pending: list[BaseException] | None = None


@contextlib.contextmanager
def _signal_handlers() -> Iterator[_SignalState]:
    """Catch :data:`SIGNALS_CAUGHT` and raise :class:`SignalExit` instead.

    Raising routes the default kill signals through the same
    ``BaseException`` paths as a Ctrl-C: the pass kills its container, the
    cell records ``interrupted`` with the signal named, ``REPORT.md`` is
    rendered and the stage dir removed. SIGINT is dispatched too, so a
    deferred section (:func:`_defer_signals`) can also hold a Ctrl-C —
    outside one it raises ``KeyboardInterrupt``, exactly like the
    default handler. Signal handlers are process-global, so they are
    installed only in the main thread (``signal`` requires it) and only
    for the campaign's duration; the previous handlers are restored on
    the way out.
    """
    state = _SignalState()
    if threading.current_thread() is not threading.main_thread():
        yield state
        return
    previous = {sig: signal.getsignal(sig) for sig in (*SIGNALS_CAUGHT, signal.SIGINT)}

    def dispatch(signum: int, _frame: FrameType | None) -> None:
        exc: BaseException = KeyboardInterrupt() if signum == signal.SIGINT else SignalExit(signum)
        if state.pending is not None:
            state.pending.append(exc)
        else:
            raise exc

    for sig in previous:
        signal.signal(sig, dispatch)
    try:
        yield state
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


#: The process-affinity syscalls, module-level so a test can substitute them.
_getaffinity: Callable[[int], set[int]] | None = getattr(os, "sched_getaffinity", None)
_setaffinity: Callable[[int, set[int]], None] | None = getattr(os, "sched_setaffinity", None)


def _harness_cpus(cell: Cell, online: set[int]) -> tuple[int, ...] | None:
    """The cpus the harness pins itself to while ``cell`` runs.

    The tool owns ``cell.cpuset``; the harness (replayer, docker clients,
    the mbench process itself) stays on the other online cores — the
    "harness on other cores" half of the pinning rule (plan §B5). ``None``
    when pinning is impossible (the tool takes every online cpu) or
    unavailable (no ``sched_setaffinity``, empty cpuset).
    """
    if not cell.cpuset or _setaffinity is None:
        return None
    rest = sorted(online - set(cell.cpuset))
    return tuple(rest) if rest else None


@contextlib.contextmanager
def _defer_signals(state: _SignalState, pending: list[BaseException]) -> Iterator[None]:
    """Record a caught signal in ``pending`` instead of raising it.

    The end-of-campaign cleanup and the interrupted-record write must
    finish even when a second signal lands inside them (review N3):
    under this context the handler records a :class:`SignalExit` or a
    ``KeyboardInterrupt`` in ``pending`` and the interrupted work
    continues; the caller re-raises the first pending interrupt once
    the protected section is done. A worker thread installs no
    handlers, so its signals can never land there — the slot is simply
    set and unset.
    """
    previous = state.pending
    state.pending = pending
    try:
        yield
    finally:
        state.pending = previous


def _retry_on_interrupt[T](step: Callable[[], T], pending: list[BaseException]) -> T | None:
    """Run ``step`` to completion; an interrupt raised inside is retried once.

    A real signal cannot raise inside ``step`` under
    :func:`_defer_signals` — it is recorded, never raised — but an
    interrupt raised another way (a monkeypatched fault, an outside
    handler) is appended to ``pending`` and the step retried. Cleanup
    steps are idempotent, so finishing them is always safe. A step that
    interrupts a second time is not facing a transient condition (review
    L1): it is given up on — the interrupts stay in ``pending`` for the
    caller to re-raise — and the remaining steps still run. ``None``
    marks the give-up; a step whose result is used must be skipped then.
    """
    for _ in range(2):
        try:
            return step()
        except (KeyboardInterrupt, SystemExit) as exc:
            pending.append(exc)
    return None


def run_campaign(
    campaign: Campaign,
    *,
    results_dir: Path = DEFAULT_RESULTS,
    directory: Path | None = None,
    adapters: Mapping[str, Callable[[], Adapter]] | None = None,
    collect: Callable[[], dict[str, Json]] | None = None,
    batch: str | None = None,
    clock: Callable[[], datetime] = utcnow,
    monotonic: Callable[[], float] = time.monotonic,
    tmpfs: Path | bool | None = None,
    work_root: Path | None = None,
    perf_probe: perf.Probe | None = None,
    pin_harness: bool = False,
    out: Callable[[str], None] = print,
    err: Callable[[str], None] = lambda line: print(line, file=sys.stderr),
) -> CampaignOutcome:
    """Run ``campaign`` and write its results directory.

    ``collect`` returns the campaign's host-scope SUT record (default: a live
    collection as the invoking user, anonymised). ``directory`` overrides
    where results go (default: ``results_dir/<date>-<campaign.name>`` —
    ``mbench sweep`` pins it so every step of one sweep lands in the same
    directory even across a date change). ``adapters`` maps tool
    names to adapter factories (default: ``mbench.adapters.ADAPTERS``).
    ``tmpfs`` selects the staging directory: ``None`` or ``True``
    auto-detects, a :class:`Path` forces one, ``False`` disables tmpfs
    staging (recorded as ``tmpfs: false``). ``perf_probe`` wraps each pass
    in ``perf stat`` (the default probes this host once when the campaign
    asks ``perf: true``; nothing is recorded otherwise). ``pin_harness``
    pins the harness process to the cpus the cell's tool does not use,
    restored when the campaign ends.

    For the campaign's duration the harness owns SIGINT, SIGTERM and
    SIGHUP: a caller's own handler — ``SIG_IGN`` included — is overridden
    so each signal takes the interrupted path (``KeyboardInterrupt`` or
    :class:`SignalExit`), and the previous handlers are restored on the
    way out (decision 2). Handlers are process-global, so they are only
    installed in the main thread; a worker-thread call installs none.
    """
    factories = dict(ADAPTERS) if adapters is None else dict(adapters)
    collect_sut = _collect_sut if collect is None else collect
    now = clock()
    if directory is None:
        directory = results_dir / f"{now.strftime('%Y-%m-%d')}-{campaign.name}"
    batch_id = _free_batch(directory, batch or _batch_id(now))
    runs_dir = directory / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    outcome = CampaignOutcome(directory, None)

    if campaign.quiet_host:
        out("mbench run: this campaign asks for a quiet host — run this first:")
        out(f"    {QUIET_STOP}")
        out("mbench run: and when it finishes:")
        out(f"    {QUIET_START}")
        err("mbench run: the harness does not run these itself (no sudo).")

    probe = perf_probe or (perf.Probe() if campaign.perf else None)
    if campaign.perf and probe is not None and probe.unavailable is not None:
        for line in perf.enable_note(probe.unavailable, probe.paranoid):
            out(line)

    if tmpfs is None or tmpfs is True:
        stage_dir_root = offline.tmpfs_dir()
    elif tmpfs is False:
        stage_dir_root = None
    else:
        stage_dir_root = tmpfs
    if stage_dir_root is None:
        err("mbench run: no tmpfs mount found: captures are staged on the regular filesystem")

    online: set[int] = set()
    saved_affinity: set[int] | None = None
    if pin_harness and _getaffinity is not None and _setaffinity is not None:
        saved_affinity = set(_getaffinity(0))
        online = set(_getaffinity(0))

    # From here on SIGTERM and SIGHUP raise SignalExit, so the default
    # kill signal takes the same interrupted path as a Ctrl-C (review N1):
    # the pass's own handling kills its container, the cell records
    # ``interrupted``, and the finally still runs on every exit.
    with _signal_handlers() as sigstate:
        propagating: BaseException | None = None
        try:
            host_record = collect_sut()
            sut_file = _unique(directory / "sut.json", batch_id, ".json")
            write(sut_file, json.dumps(host_record, indent=2, ensure_ascii=False) + "\n")
            outcome.sut_file = sut_file
            with tempfile.TemporaryDirectory(prefix="mbench-run-", dir=work_root) as work_root_dir:
                work = Path(work_root_dir)
                on_tmpfs = stage_dir_root is not None
                stage_dir = work / "staged"
                if stage_dir_root is not None:
                    stage_dir = stage_dir_root / f"mbench-{batch_id}"
                for cell in campaign.cells:
                    interrupt: BaseException | None = None
                    try:
                        adapter = factories[cell.tool]()
                    except Exception as exc:
                        err(f"cell {cell.index} ({cell.tool}): adapter failed: {exc}")
                        record = _failed_cell_record(
                            campaign,
                            cell,
                            exc,
                            batch=batch_id,
                            tmpfs=on_tmpfs,
                            at=now,
                            what=f"adapter {cell.tool}",
                        )
                    else:
                        harness_cpus: tuple[int, ...] = ()
                        if saved_affinity is not None:
                            candidate = _harness_cpus(cell, online)
                            if candidate is None:
                                if cell.cpuset:
                                    err(
                                        f"cell {cell.index}: the tool pins every online "
                                        "cpu; the harness stays unpinned"
                                    )
                            else:
                                try:
                                    assert _setaffinity is not None
                                    _setaffinity(0, set(candidate))
                                    harness_cpus = candidate
                                except OSError as exc:
                                    err(
                                        f"cell {cell.index}: cannot pin the harness "
                                        f"({exc}); running unpinned"
                                    )
                        try:
                            record = run_cell(
                                adapter,
                                campaign,
                                cell,
                                workdir=work / f"cell-{cell.index:03d}",
                                stage_dir=stage_dir,
                                tmpfs=on_tmpfs,
                                host_record=host_record,
                                batch=batch_id,
                                clock=clock,
                                monotonic=monotonic,
                                perf_probe=probe,
                                harness_cpuset=harness_cpus,
                            )
                        except BaseException as exc:
                            # A crashed cell is a run record, not a lost campaign:
                            # ``error`` — the campaign continues; ``interrupted``
                            # (Ctrl-C, SystemExit) — it is recorded, then re-raised.
                            record = _failed_cell_record(
                                campaign,
                                cell,
                                exc,
                                batch=batch_id,
                                tmpfs=on_tmpfs,
                                at=clock(),
                                what="the run",
                            )
                            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                                interrupt = exc
                            else:
                                err(f"cell {cell.index} ({cell.tool}): run failed: {exc}")
                    outcome.runs.append(record)
                    path = runs_dir / f"{batch_id}-{cell.index:03d}-{_slug(cell)}.json"
                    # The record write runs under the same deferral as the
                    # cleanup below (review N3): a second signal mid-write is
                    # recorded in ``pending``, not raised, so an interrupted
                    # record is never lost to a partial write; a deferred
                    # interrupt is raised once the record is on disk.
                    pending: list[BaseException] = []

                    def _write_record(run_file: Path, text: str) -> None:
                        write(run_file, text)
                        outcome.run_files.append(run_file)

                    with _defer_signals(sigstate, pending):
                        _retry_on_interrupt(
                            partial(
                                _write_record,
                                path,
                                json.dumps(record, indent=2, ensure_ascii=False) + "\n",
                            ),
                            pending,
                        )
                    err(
                        f"cell {cell.index + 1}/{len(campaign.cells)} "
                        f"({_slug(cell)}): {record['status']}"
                    )
                    if interrupt is None and pending:
                        interrupt = pending[0]
                    if interrupt is not None:
                        raise interrupt
        except BaseException as exc:
            # What is already propagating outlives a signal deferred by the
            # cleanup below: the first interrupt keeps the exit status.
            propagating = exc
            raise
        finally:
            # The cleanup finishes even when a signal lands inside it
            # (review N3): while it runs a caught signal or Ctrl-C is
            # recorded in ``pending`` instead of raising, and a step that
            # still gets an interrupt through is retried once — each step
            # is idempotent — then given up on so the rest of the cleanup
            # still runs (review L1). The first deferred interrupt is
            # re-raised once the cleanup is done, unless one is already
            # propagating.
            pending = []
            with _defer_signals(sigstate, pending):
                # The harness's own affinity is restored on every exit path.
                if saved_affinity is not None:

                    def _restore_affinity() -> None:
                        with contextlib.suppress(OSError):
                            assert _setaffinity is not None
                            _setaffinity(0, saved_affinity)

                    _retry_on_interrupt(_restore_affinity, pending)
                # The tmpfs staging dir never outlives the campaign — clean
                # exit, failed cell or Ctrl-C alike (B1).
                if stage_dir_root is not None:
                    _retry_on_interrupt(
                        partial(
                            shutil.rmtree,
                            stage_dir_root / f"mbench-{batch_id}",
                            ignore_errors=True,
                        ),
                        pending,
                    )
                # And a partial campaign still leaves its report: it renders
                # over whatever run files exist, failed cells listed. A
                # render given up on leaves no report to write.
                from mbench.report import render

                report = _retry_on_interrupt(partial(render.render_dir, directory), pending)

                def _write_report(text: str) -> None:
                    report_file = _unique(directory / "REPORT.md", batch_id, ".md")
                    write(report_file, text)
                    outcome.report_file = report_file

                if report is not None:
                    _retry_on_interrupt(partial(_write_report, report), pending)
            if pending and propagating is None:
                raise pending[0]
    return outcome
