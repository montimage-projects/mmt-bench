"""Offline capacity mode (#8): the pcap is read from a tmpfs mount.

The methodology's offline mode: the pcap lives on a tmpfs so disk I/O never
bounds the measurement, the tool's threads are pinned to the campaign's
cores, and a pass is ``prepare`` then ``run_offline``, waited on under the
campaign's timeout, then the tool's counters and alerts are read.
:func:`tmpfs_dir` finds the mount; :func:`stage_pcap` copies the capture
onto it under its sha256, so the file's own name — which a local-only
capture must not show — never reaches a container or a result.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from mbench.adapters.base import Adapter, Alert, Counters, ProcessHandle, Ruleset
from mbench.metrics import perf


def tmpfs_mounts(mounts_text: str | None = None) -> list[Path]:
    """Every tmpfs mount point, preferred first (``/dev/shm``)."""
    if mounts_text is None:
        mounts_text = Path("/proc/mounts").read_text(encoding="utf-8")
    points = [
        Path(line.split()[1])
        for line in mounts_text.splitlines()
        if len(line.split()) >= 3 and line.split()[2] == "tmpfs"
    ]
    return sorted(points, key=lambda p: (p != Path("/dev/shm"), str(p)))


def tmpfs_dir(mounts_text: str | None = None) -> Path | None:
    """The tmpfs the harness stages captures on, or None when there is none."""
    points = tmpfs_mounts(mounts_text)
    return points[0] if points else None


def stage_pcap(pcap: Path, sha256: str, directory: Path) -> Path:
    """Copy ``pcap`` into ``directory`` as ``<sha256>.pcap``; returns the copy.

    Staging names the file by its hash, never by its own name: a local-only
    capture's filename stays out of the container mount and of results.
    """
    directory.mkdir(parents=True, exist_ok=True)
    staged = directory / f"{sha256}.pcap"
    if not staged.exists():
        shutil.copyfile(pcap, staged)
    return staged


@dataclass(frozen=True)
class Outcome:
    """One offline pass: what happened and what the tool reported."""

    status: str  # "ok" | "timeout" | "error"
    wall_s: float  # tool process start to exit (also on timeout: until killed)
    returncode: int | None = None
    counters: Counters | None = None
    alerts: list[Alert] | None = None
    detail: str = ""  # why a non-ok pass failed
    perf: dict[str, object] | None = None  # the pass's perf stat record (#10)


def run_pass(
    adapter: Adapter,
    ruleset: Ruleset,
    config_profile: str,
    workdir: Path,
    pcap: Path,
    threads: int,
    cpuset: Sequence[int],
    timeout_s: float,
    *,
    clock: Callable[[], float] = time.monotonic,
    perf_probe: perf.Probe | None = None,
) -> Outcome:
    """One measured pass: prepare, run under the timeout, read the outputs.

    A pass that exceeds ``timeout_s`` is killed and comes back ``timeout``;
    a non-zero exit, or unreadable counters, comes back ``error``. Only the
    tool's own process is timed: ``prepare`` is harness work. With
    ``perf_probe`` the tool's runtime is wrapped in a ``perf stat`` session
    on the pass's cores: cycles and instructions burned over exactly the
    measured window, or the probe's unavailable marker.
    """
    adapter.prepare(ruleset, config_profile, workdir)
    start = clock()
    handle: ProcessHandle | None = None
    session: perf._Session | None = None
    perf_record: dict[str, object] | None = (
        perf_probe.unavailable if perf_probe is not None else None
    )
    exited = False
    try:
        handle = adapter.run_offline(pcap, threads, cpuset)
        if perf_probe is not None:
            session = perf_probe.start(cpuset)
        returncode = handle.wait(timeout_s)
        exited = True
    except subprocess.TimeoutExpired:
        detail = f"killed after {timeout_s:g} s"
        try:
            if handle is not None:
                handle.kill()
                handle = None
        except Exception as exc:
            detail += f" (kill failed: {type(exc).__name__}: {exc})"
        if perf_probe is not None and session is not None:
            perf_record = perf_probe.record(session, None)
        return Outcome("timeout", clock() - start, detail=detail, perf=perf_record)
    except BaseException as exc:
        detail = f"{type(exc).__name__}: {exc}"
        try:
            if handle is not None:
                handle.kill()
                handle = None
        except Exception as kill_exc:
            detail += f" (kill failed: {type(kill_exc).__name__}: {kill_exc})"
        if perf_probe is not None and session is not None:
            perf_record = perf_probe.record(session, None)
        if isinstance(exc, Exception):
            return Outcome("error", clock() - start, detail=detail, perf=perf_record)
        raise
    finally:
        # A started tool is dead on every non-normal exit — a failed kill
        # above, a Ctrl-C escaping the except block; for Docker this kills
        # the container, not only the client process.
        if handle is not None and not exited:
            with contextlib.suppress(Exception):
                handle.kill()
        # A still-running session never outlives its pass (e.g. the tool
        # died before wait): the counts are discarded with the pass.
        if session is not None and perf_probe is not None and not exited:
            with contextlib.suppress(Exception):
                perf_probe.record(session, None)
    wall_s = clock() - start
    if returncode != 0:
        if perf_probe is not None and session is not None:
            perf_record = perf_probe.record(session, None)
        return Outcome(
            "error", wall_s, returncode, detail=f"exit status {returncode}", perf=perf_record
        )
    try:
        counters = adapter.counters()
        alerts = adapter.alerts()
    except Exception as exc:
        if perf_probe is not None and session is not None:
            perf_record = perf_probe.record(session, None)
        return Outcome(
            "error",
            wall_s,
            returncode,
            detail=f"outputs unreadable: {type(exc).__name__}: {exc}",
            perf=perf_record,
        )
    if perf_probe is not None:
        perf_record = perf_probe.record(session, counters.packets)
    return Outcome("ok", wall_s, returncode, counters, alerts, perf=perf_record)
