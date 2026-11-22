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
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mbench import sut

if TYPE_CHECKING:
    from mbench.hostsrc import Source

#: The hardware events counted over each pass.
EVENTS = ("cycles", "instructions")

#: ``perf stat`` is stopped with SIGINT: the signal a Ctrl-C sends, which
#: perf handles by finalising and printing its counts.
_STOP_SIGNAL = signal.SIGINT

#: How long the ``sleep`` under ``perf stat`` may run; the session is always
#: stopped when the pass ends, so this only caps a forgotten session.
_SESSION_CAP_S = "86400"

#: Where ``kernel.perf_event_paranoid`` lives.
PARANOID_PATH = "/proc/sys/kernel/perf_event_paranoid"

Completed = subprocess.CompletedProcess[bytes]


def _default_run(argv: Sequence[str]) -> Completed:
    """Run ``argv`` to completion (the canary probe's runner)."""
    return subprocess.run(argv, capture_output=True, timeout=60, check=False)


def _default_spawn(argv: Sequence[str]) -> subprocess.Popen[bytes]:
    """Start ``argv`` without waiting (the ``perf stat`` session)."""
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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


def parse_stat_csv(text: str) -> dict[str, float]:
    """A ``perf stat -x ,`` output as ``{event: count}``.

    Each row is ``<value>,<unit>,<event>[,<more fields>]``; the event name
    is matched exactly (``cycles``, ``instructions``), so a ``cpu-cycles``
    unit column never shadows it. ``<not counted>`` and ``<not supported>``
    rows and ``#`` comments are skipped.
    """
    counts: dict[str, float] = {}
    for line in text.splitlines():
        fields = [f.strip() for f in line.split(",")]
        if len(fields) < 3 or line.lstrip().startswith("#"):
            continue
        event = next((f for f in fields[1:] if f in EVENTS), None)
        if event is None:
            continue
        try:
            counts[event] = float(fields[0])
        except ValueError:
            continue  # "<not counted>"
    return counts


def enable_note(marker: dict[str, Any] | None, paranoid: int | None = None) -> list[str]:
    """The root commands that enable perf for a campaign, printed for Luong.

    Option A is the narrowest: ``CAP_PERFMON`` on a private copy of the real
    perf binary (``/usr/bin/perf`` is a shell wrapper, so the capability must
    go on ``/usr/lib/linux-tools/$(uname -r)/perf``), executable only by the
    bench user and removed afterwards — no host-wide change at all. Option B
    lowers ``kernel.perf_event_paranoid`` to 1 (CPU-wide counting) for every
    user of the host, restored to its recorded value after the campaign.
    """
    reason = (marker or {}).get("reason", "perf is unavailable")
    restore = str(paranoid if paranoid is not None else "<current value>")
    return [
        f"mbench run: perf unavailable — cycles per packet not measured ({reason}).",
        "mbench run: to enable it (root, narrowest first — the harness never runs these):",
        "  # option A (recommended): CAP_PERFMON on a private copy of the real perf binary",
        "  install -Dm700 /usr/lib/linux-tools/$(uname -r)/perf ~/.local/bin/perf",
        "  sudo setcap 'cap_perfmon=ep' ~/.local/bin/perf   # restore: rm ~/.local/bin/perf",
        "  # caveat: a nosuid/noexec home mount drops the capability — put the",
        "  # copy somewhere executables keep file caps (e.g. /usr/local/bin)",
        "  # option B (broader, host-wide):",
        "  sudo sysctl kernel.perf_event_paranoid=1",
        f"  sudo sysctl kernel.perf_event_paranoid={restore}   # restore",
    ]


class Probe:
    """perf availability and ``perf stat`` sessions, detected once.

    ``run`` executes a command to completion (the canary), ``spawn`` starts
    a long-running one (the session); both default to subprocesses. Tests
    inject fakes so nothing touches the host's perf. ``paranoid`` is read
    from :data:`PARANOID_PATH` by :meth:`_detect` to name the reason and the
    value to restore.
    """

    def __init__(
        self,
        *,
        run: Callable[[Sequence[str]], Completed] = _default_run,
        spawn: Callable[[Sequence[str]], subprocess.Popen[bytes]] = _default_spawn,
        binary: str | None = None,
        paranoid_path: Path | str = PARANOID_PATH,
    ) -> None:
        self._run = run
        self._spawn = spawn
        self._binary = binary or shutil.which("perf")
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
        """The once-per-probe availability check: binary present, canary passes."""
        self._paranoid = self._paranoid_level()
        if self._binary is None:
            self._marker = sut.unavailable("missing_tool", "no perf binary on PATH")
        elif self._paranoid is not None and self._paranoid >= 4:
            self._marker = sut.unavailable(
                "needs_root",
                f"kernel.perf_event_paranoid={self._paranoid} refuses unprivileged perf "
                "(CPU-wide counting needs <= 1 or CAP_PERFMON)",
            )
        else:
            try:
                proc = self._run(
                    [
                        self._binary,
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
                self._marker = sut.unavailable("error", f"the perf canary failed: {exc}")
            else:
                if proc.returncode != 0:
                    detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
                    kind = "needs_root" if (self._paranoid or 0) > 1 else "error"
                    self._marker = sut.unavailable(
                        kind,
                        f"perf stat refused (rc={proc.returncode}): "
                        f"{detail[0] if detail else 'no stderr'}",
                    )
        self._probed = True

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
            str(self._binary),
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
        try:
            session.proc.send_signal(_STOP_SIGNAL)
            session.proc.wait(timeout=10)
        except (OSError, subprocess.SubprocessError):
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
