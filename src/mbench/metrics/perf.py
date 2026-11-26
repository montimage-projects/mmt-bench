"""Cycles and instructions per packet from ``perf stat`` (issue #10, plan §B6).

A measured pass is wrapped in ``perf stat``: the cycles and instructions
burned while the tool processed the capture. The scope is the tool's
container cgroup when the adapter can name one (``perf stat -e … -a -G
system.slice/docker-<id>.scope`` — the cycles the pass's own container
burned, nothing else's), else the cell's pinned cores (``perf stat -a -C
<cpuset>`` — every cycle the cpuset burned, including whatever else ran on
it; the record's ``scope`` field says which). Dividing by the pass's
packet count gives cycles per packet, the efficiency number the P1 report
carries next to Gbit/s and Mpps.

``perf_event_paranoid`` 4 (dgx-spark's Ubuntu default) refuses unprivileged
perf entirely, and a machine without perf cannot fake the metric: a
:class:`Probe` detects availability once per campaign, records the reason as
an unavailable marker on every pass, and prints the exact root commands that
enable it (``AGENTS.md``: root steps are printed for Luong, never run).

The binary is found in this order (issue #50): the ``MBENCH_PERF``
environment variable, then ``~/.local/bin/perf-mbench`` — the private copy
of the running kernel's perf carrying ``cap_perfmon=ep``, which survives
``perf_event_paranoid = 4`` — then ``perf`` on ``PATH``. Each discovered
binary is verified before use: it must match the running kernel's perf
(byte-identical to ``/usr/lib/linux-tools/$(uname -r)/perf``, the copy
``install -Dm700`` produced — ``perf --version`` reports the package
version, not ``uname -r``, so it cannot spot a stale copy), and, when the
paranoid level demands it, carry ``cap_perfmon`` (read with ``getcap``
when present; without it the one-event ``perf stat`` canary is the
check). A stale or uncapped binary is skipped for the next candidate;
when nothing works the marker names every binary tried, and the printed
runbook gives the exact ``install``/``setcap`` lines for Luong — the
harness never runs them.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mbench import sut

if TYPE_CHECKING:
    from mbench.hostsrc import Source

#: The hardware events counted over each pass.
EVENTS = ("cycles", "instructions")

#: ``perf stat`` is stopped with SIGINT — sent to the session's whole
#: process group, as a terminal Ctrl-C would — which perf handles by
#: finalising and printing its counts.
_STOP_SIGNAL = signal.SIGINT

#: How long the ``sleep`` under ``perf stat`` may run; the session is always
#: stopped when the pass ends, so this only caps a forgotten session.
_SESSION_CAP_S = "86400"

#: Where ``kernel.perf_event_paranoid`` lives.
PARANOID_PATH = "/proc/sys/kernel/perf_event_paranoid"

#: Environment variable naming the perf binary — first in the lookup order.
ENV_BINARY = "MBENCH_PERF"

#: The private perf copy's home-relative path — second in the lookup order:
#: a byte copy of the running kernel's perf carrying ``cap_perfmon=ep``.
DEFAULT_BINARY = ".local/bin/perf-mbench"

#: Where the kernel's own perf binaries live; the reference a private copy
#: must match is ``<KERNEL_TOOLS_DIR>/<uname -r>/perf``.
KERNEL_TOOLS_DIR = Path("/usr/lib/linux-tools")

Completed = subprocess.CompletedProcess[bytes]


def _default_run(argv: Sequence[str]) -> Completed:
    """Run ``argv`` to completion (the canary probe's runner)."""
    return subprocess.run(argv, capture_output=True, timeout=60, check=False)


def _default_spawn(argv: Sequence[str]) -> subprocess.Popen[bytes]:
    """Start ``argv`` as a session leader without waiting.

    ``start_new_session`` gives perf and its ``sleep`` workload their own
    process group — the contract ``spawn`` must keep for
    :meth:`Probe.stop`: its SIGINT reaches both, exactly what a terminal
    Ctrl-C delivers and what makes every perf build finalise its counts
    (a lone SIGINT to the perf process alone does not always do it),
    while never touching the caller's own group.
    """
    return subprocess.Popen(
        argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
    )


@dataclass
class _Session:
    """One running ``perf stat``; ``stop`` reads the counts from ``out``.

    ``scope`` is what the session counts: ``cgroup`` (the run's own
    container, ``perf stat -G``) or ``cpuset`` (the whole pinned cpuset,
    ``perf stat -a -C``) — recorded on the pass so a cycles/pkt column
    never silently mixes the two.
    """

    proc: subprocess.Popen[bytes]
    out: Path
    scope: str = "cpuset"


def _event_of(field: str) -> str | None:
    """The :data:`EVENTS` member a CSV field names, or ``None``.

    ``cycles`` matches itself; ``<pmu>/cycles/`` — the name perf prints
    where several PMUs own disjoint CPUs, like the mixed X925/A725
    clusters — matches too. ``cpu-cycles`` is its own event, never
    ``cycles``; deeper namespaced forms are not matched.
    """
    parts = field.split("/")
    if len(parts) == 3 and parts[0] and parts[2] == "":
        field = parts[1]
    elif len(parts) != 1:
        return None
    return field if field in EVENTS else None


def parse_stat_csv(text: str) -> dict[str, float]:
    """A ``perf stat -x ,`` output as ``{event: count}``.

    Each row is ``<value>,<unit>,<event>[,<more fields>]``; the event name
    is matched on the event itself, so a ``cpu-cycles`` unit column never
    shadows it and a ``<pmu>/<event>/`` namespaced name still resolves.
    ``<not counted>`` and ``<not supported>`` rows and ``#`` comments are
    skipped — a PMU that did not count never erases the one that did.
    """
    counts: dict[str, float] = {}
    for line in text.splitlines():
        fields = [f.strip() for f in line.split(",")]
        if len(fields) < 3 or line.lstrip().startswith("#"):
            continue
        event = next((event for f in fields[1:] if (event := _event_of(f)) is not None), None)
        if event is None:
            continue
        try:
            counts[event] = counts.get(event, 0.0) + float(fields[0])
        except ValueError:
            continue  # "<not counted>"
    return counts


def enable_note(marker: dict[str, Any] | None, paranoid: int | None = None) -> list[str]:
    """The root commands that enable perf for a campaign, printed for Luong.

    Option A is the narrowest: ``CAP_PERFMON`` on a private copy of the
    running kernel's perf — ``/usr/bin/perf`` is a shell wrapper, so the
    capability must go on a real binary copied from
    ``/usr/lib/linux-tools/$(uname -r)`` — executable only by the bench
    user and removed afterwards, no host-wide change at all. The copy is
    the binary the probe finds second (``perf-mbench``), and a kernel
    update invalidates it, so these lines reappear then. Option B lowers
    ``kernel.perf_event_paranoid`` to 0 — ``>= 1`` refuses CPU events to
    users without CAP_PERFMON, so 0 is the least permissive value that
    still counts CPU-wide — for every user of the host, restored to its
    recorded value after the campaign.
    """
    reason = (marker or {}).get("reason", "perf is unavailable")
    restore = str(paranoid if paranoid is not None else "<current value>")
    return [
        f"mbench run: perf unavailable — cycles per packet not measured ({reason}).",
        "mbench run: to enable it (root, narrowest first — the harness never runs these):",
        "  # option A (recommended): CAP_PERFMON on a private copy of the running",
        "  # kernel's perf (/usr/bin/perf is a shell wrapper — the capability",
        "  # must go on a real binary copied from /usr/lib/linux-tools/$(uname -r)):",
        "  install -Dm700 /usr/lib/linux-tools/$(uname -r)/perf ~/.local/bin/perf-mbench",
        "  sudo setcap 'cap_perfmon=ep' ~/.local/bin/perf-mbench"
        "   # restore: rm ~/.local/bin/perf-mbench",
        "  # caveat: a nosuid/noexec home mount drops the capability — put the",
        "  # copy somewhere executables keep file caps (e.g. /usr/local/bin)",
        "  # option B (broader, host-wide — CPU events need <= 0):",
        "  sudo sysctl kernel.perf_event_paranoid=0",
        f"  sudo sysctl kernel.perf_event_paranoid={restore}   # restore",
    ]


class Probe:
    """perf availability and ``perf stat`` sessions, detected once.

    ``run`` executes a command to completion (the ``getcap`` check and the
    canary), ``spawn`` starts a long-running one (the session); both
    default to subprocesses. The ``spawn`` contract: the returned process
    must lead its own process group, like the default's
    ``start_new_session`` — :meth:`stop` signals that whole group, and a
    ``spawn`` that left perf in the caller's group would interrupt mbench
    itself (``stop`` refuses to signal the caller's group either way).
    Tests inject fakes so nothing touches the host's perf. ``binary``
    pins the binary by hand — the test seam: a pinned binary skips only
    the kernel-match check because the caller asserted it; the capability
    check and the canary still run, so a pinned binary the kernel would
    refuse is marked like a discovered one. Without ``binary`` the binary
    is discovered in the module docstring's order, and each candidate is
    verified against the running kernel and the paranoid level; ``env``,
    ``home``, ``release``, ``tools_dir`` and ``which`` parameterise those
    lookups for the tests. ``paranoid`` is read from
    :data:`PARANOID_PATH` by :meth:`_detect` to name the reason and the
    value to restore.
    """

    def __init__(
        self,
        *,
        run: Callable[[Sequence[str]], Completed] = _default_run,
        spawn: Callable[[Sequence[str]], subprocess.Popen[bytes]] = _default_spawn,
        binary: str | None = None,
        paranoid_path: Path | str = PARANOID_PATH,
        env: Mapping[str, str] | None = None,
        home: Path | str | None = None,
        release: str | None = None,
        tools_dir: Path | str = KERNEL_TOOLS_DIR,
        which: Callable[[str], str | None] | None = None,
    ) -> None:
        self._run = run
        self._spawn = spawn
        self._binary = binary or None
        self._env = os.environ if env is None else env
        self._home = Path.home() if home is None else Path(home)
        self._release = os.uname().release if release is None else release
        self._reference = Path(tools_dir) / self._release / "perf"
        self._which = shutil.which if which is None else which
        self._paranoid_path = Path(paranoid_path)
        self._marker: dict[str, Any] | None = None
        self._probed = False
        self._paranoid: int | None = None

    @classmethod
    def disabled(cls, reason: str = "perf not requested") -> Probe:
        """A probe that is always unavailable — campaigns without ``perf: true``."""
        probe = cls(binary="perf")
        probe._marker = {"unavailable": "not_applicable", "reason": reason}
        probe._probed = True
        return probe

    def _paranoid_level(self) -> int | None:
        try:
            return int(self._paranoid_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None

    def _detect(self) -> None:
        """The once-per-probe availability check."""
        self._paranoid = self._paranoid_level()
        if self._binary is not None:
            self._detect_pinned(self._binary)
        else:
            self._detect_found()
        self._probed = True

    def _detect_pinned(self, binary: str) -> None:
        """Availability of a caller-pinned binary: the access checks.

        The caller asserted the binary, so the kernel-match check is
        skipped — the rest is the discovered path's: a readable binary,
        ``cap_perfmon`` when the paranoid level demands it, then the
        canary. The knob alone is never the verdict: CAP_PERFMON lifts
        it, so a working capped copy must not be rejected at paranoid 4.
        """
        try:
            Path(binary).read_bytes()
        except OSError as exc:
            self._marker = sut.unavailable(
                "missing_tool", f"{self._name(binary)}: not readable ({exc.strerror or exc})"
            )
            return
        failure = self._cap_check(binary) or self._canary(binary)
        if failure is not None:
            self._marker = sut.unavailable(*failure)

    def _detect_found(self) -> None:
        """Availability of the discovered binaries: the first passing wins."""
        failures: list[tuple[str, str]] = []
        for binary in self._candidates():
            failure = self._verify(binary)
            if failure is None:
                self._binary = binary
                return
            failures.append(failure)
        if not failures:
            self._marker = sut.unavailable(
                "missing_tool",
                f"no perf binary: ${ENV_BINARY} unset, no ~/{DEFAULT_BINARY}, no perf on PATH",
            )
            return
        kind = "needs_root" if any(k == "needs_root" for k, _ in failures) else failures[0][0]
        self._marker = sut.unavailable(kind, "; ".join(reason for _, reason in failures))

    def _candidates(self) -> list[str]:
        """The discovered binaries in lookup order (issue #50), deduplicated.

        ``$MBENCH_PERF`` is included even when its file is missing — the
        override was asked for explicitly, so the marker should say why it
        failed; the default copy and the PATH binary qualify by existing.
        """
        found: list[str] = []
        env_binary = self._env.get(ENV_BINARY)
        if env_binary:
            found.append(env_binary)
        default_binary = self._home / DEFAULT_BINARY
        if str(default_binary) not in found and default_binary.exists():
            found.append(str(default_binary))
        path_binary = self._which("perf")
        if path_binary and path_binary not in found:
            found.append(path_binary)
        return found

    def _verify(self, binary: str) -> tuple[str, str] | None:
        """The discovered-binary checks: kernel match, capability, canary."""
        try:
            blob = Path(binary).read_bytes()
        except OSError as exc:
            return "missing_tool", (f"{self._name(binary)}: not readable ({exc.strerror or exc})")
        return self._kernel_check(binary, blob) or self._cap_check(binary) or self._canary(binary)

    def _kernel_check(self, binary: str, blob: bytes) -> tuple[str, str] | None:
        """``binary`` must match the running kernel's own perf.

        A private copy is only valid while it is byte-identical to
        ``/usr/lib/linux-tools/<release>/perf``: a kernel update replaces
        the reference, so the sha256 catches the staleness ``perf
        --version`` cannot (it prints the package version). A ``#!``
        wrapper script defers the check — it resolves the kernel's binary
        at exec — and no reference (a host without linux-tools) means
        nothing to compare against.
        """
        reference = self._reference
        if not reference.is_file():
            return None
        try:
            if Path(binary).resolve() == reference.resolve():
                return None
        except OSError:
            pass
        if blob.startswith(b"#!"):
            return None
        try:
            identical = (
                hashlib.sha256(blob).digest() == hashlib.sha256(reference.read_bytes()).digest()
            )
        except OSError as exc:
            return "error", f"{self._name(binary)}: {reference} unreadable ({exc})"
        if identical:
            return None
        return (
            "needs_root",
            f"{self._name(binary)} is stale: sha256 differs from the running "
            f"kernel's {reference} — recopy it with the commands below",
        )

    def _cap_check(self, binary: str) -> tuple[str, str] | None:
        """``cap_perfmon`` on the binary when the paranoid level needs it.

        CPU-wide counting (``perf stat -a``) is refused to an unprivileged
        user at ``kernel.perf_event_paranoid >= 1``; only CAP_PERFMON lifts
        that. ``getcap`` reads the file's capabilities — absent or failing,
        the check defers to the canary, which is itself the real one-event
        stat probe the capability would exist to pass.
        """
        if self._paranoid is None or self._paranoid < 1:
            return None
        getcap = self._which("getcap")
        if getcap is None:
            return None
        try:
            proc = self._run([getcap, binary])
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None  # getcap could not assess it — the canary decides
        if "cap_perfmon" in proc.stdout.decode("utf-8", "replace"):
            return None
        return (
            "needs_root",
            f"{self._name(binary)} lacks cap_perfmon and "
            f"kernel.perf_event_paranoid={self._paranoid} needs <= 0 or "
            "CAP_PERFMON — setcap it with the commands below",
        )

    def _canary(self, binary: str) -> tuple[str, str] | None:
        """The one-event ``perf stat`` probe; ``None`` when it counted."""
        try:
            proc = self._run(
                [
                    binary,
                    "stat",
                    "-a",
                    "-e",
                    "cycles",
                    "-x",
                    ",",
                    "--",
                    "sleep",
                    "0.05",
                ]
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return "error", f"{self._name(binary)}: the perf canary failed: {exc}"
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            kind = "needs_root" if (self._paranoid or 0) >= 1 else "error"
            hint = (
                f" — kernel.perf_event_paranoid={self._paranoid} refuses "
                "CPU-wide counting without CAP_PERFMON"
                if kind == "needs_root"
                else ""
            )
            return (
                kind,
                f"{self._name(binary)}: perf stat refused (rc={proc.returncode}): "
                f"{detail[0] if detail else 'no stderr'}{hint}",
            )
        return None

    def _name(self, binary: str) -> str:
        """``binary`` as records and markers name it.

        ``~``-relative under the home directory — an absolute home path is
        a host identifier the public repo never records (AGENTS.md) —
        else the path as found (``/usr/bin/perf``) or the bare name.
        """
        try:
            rel = Path(binary).resolve().relative_to(self._home.resolve())
        except (OSError, ValueError):
            return binary
        return "~/" + str(rel)

    @property
    def unavailable(self) -> dict[str, Any] | None:
        """The marker recorded when perf cannot be used; ``None`` when it can."""
        if not self._probed:
            self._detect()
        return self._marker

    @property
    def paranoid(self) -> int | None:
        """The host's ``kernel.perf_event_paranoid`` once probed (for the note)."""
        if not self._probed:
            self._detect()
        return self._paranoid

    def start(self, cpuset: Sequence[int], cgroup: str | None = None) -> _Session | None:
        """``perf stat`` counting until :meth:`stop`, scoped as tightly as possible.

        ``cgroup`` — the run container's cgroup (a name relative to
        ``/sys/fs/cgroup``, ``system.slice/docker-<id>.scope``) — counts
        only the pass's own container: ``perf stat -e … -a -G <cgroup>``.
        Without it, ``perf stat -e … -a -C <cpuset>`` counts every cycle
        the pinned cores burn, including anything else scheduled on them.
        ``None`` when perf is unavailable (the marker is recorded by
        :meth:`record`) or when neither scope can be named: ``-C`` needs a
        cpuset, and all-CPU counting on a run pinned nowhere would mislabel
        the metric.
        """
        if self.unavailable is not None or not (cgroup or cpuset):
            return None
        if self._binary is None:
            return None
        fd, name = tempfile.mkstemp(
            prefix="mbench-perf-", suffix=".csv", dir=os.environ.get("TMPDIR")
        )
        os.close(fd)
        out = Path(name)
        # Events precede any -G: this perf build refuses them after
        # ("must define events before cgroups"), and the cgroup scope
        # needs system-wide -a — the container's cpuset already confines
        # its cycles, so all-CPU counting still counts only the pass's
        # own container.
        argv = [
            self._binary,
            "stat",
            "-e",
            "cycles",
            "-e",
            "instructions",
            "-a",
        ]
        scope = "cpuset"
        if cgroup:
            argv += ["-G", cgroup]
            scope = "cgroup"
        else:
            argv += ["-C", sut.format_cpulist(cpuset)]
        argv += [
            "-x",
            ",",
            "-o",
            str(out),
            "--",
            "sleep",
            _SESSION_CAP_S,
        ]
        try:
            return _Session(self._spawn(argv), out, scope)
        except (OSError, subprocess.SubprocessError):
            out.unlink(missing_ok=True)
            return None

    def stop(self, session: _Session) -> dict[str, Any]:
        """Stop a session and return its ``{cycles, instructions}`` counts."""
        # Ctrl-C on the whole session's process group: perf and its
        # workload share one (the spawn contract, like the default's
        # start_new_session), so both take the signal — the semantics a
        # terminal Ctrl-C has, which a lone SIGINT to the perf process
        # does not always reproduce. The group signal is used only when
        # the session's pgid is not this process's own — a spawn that did
        # not detach perf would put it in our group, and signalling that
        # group would interrupt mbench itself. A session without a real
        # pid (the tests' fake) or a detached-group failure gets the
        # per-process send.
        pid = getattr(session.proc, "pid", None)
        pgid: int | None = None
        if pid is not None:
            with _suppress():
                pgid = os.getpgid(pid)
            if pgid == os.getpgid(0):
                pgid = None
        if pgid is not None:
            with _suppress():
                os.killpg(pgid, _STOP_SIGNAL)
        else:
            with _suppress():
                session.proc.send_signal(_STOP_SIGNAL)
        try:
            session.proc.wait(timeout=10)
        except (OSError, subprocess.SubprocessError):
            if pgid is not None:
                with _suppress():
                    os.killpg(pgid, signal.SIGKILL)
            with _suppress():
                session.proc.kill()
        try:
            counts = parse_stat_csv(session.out.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            return sut.unavailable("error", f"perf stat output unreadable: {exc}")
        finally:
            session.out.unlink(missing_ok=True)
        if not counts:
            return sut.unavailable("error", "perf stat counted nothing on the cpuset")
        return counts

    def record(self, session: _Session | None, packets: int | None) -> dict[str, Any]:
        """The pass's ``perf`` field: counts plus derived rates, or a marker."""
        if self.unavailable is not None:
            return self.unavailable
        if session is None:
            return sut.unavailable(
                "not_applicable", "the pass is unpinned: perf stat -C needs a cpuset"
            )
        counts = self.stop(session)
        if "unavailable" in counts:
            return counts
        record: dict[str, Any] = dict(counts)
        record["scope"] = session.scope
        if self._binary is not None:
            record["binary"] = self._name(self._binary)
        cycles = counts.get("cycles")
        instructions = counts.get("instructions")
        if packets and cycles is not None:
            record["cycles_per_packet"] = round(cycles / packets, 4)
        if cycles and instructions is not None:
            record["instructions_per_cycle"] = round(instructions / cycles, 4)
        return record


def _suppress() -> Any:
    import contextlib

    return contextlib.suppress(OSError, subprocess.SubprocessError)


def topology_probe(source: Source) -> Probe:
    """A probe bound to a hostsrc Source's runner (recording-friendly)."""

    def run(argv: Sequence[str]) -> Completed:
        result = source.run(argv)
        return Completed(
            list(argv), result.returncode, result.stdout.encode(), result.stderr.encode()
        )

    return Probe(run=run)
