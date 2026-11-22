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

import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from mbench.adapters.base import Adapter, Alert, Counters, Ruleset


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
) -> Outcome:
    """One measured pass: prepare, run under the timeout, read the outputs.

    A pass that exceeds ``timeout_s`` is killed and comes back ``timeout``;
    a non-zero exit, or unreadable counters, comes back ``error``. Only the
    tool's own process is timed: ``prepare`` is harness work.
    """
    adapter.prepare(ruleset, config_profile, workdir)
    start = clock()
    try:
        handle = adapter.run_offline(pcap, threads, cpuset)
        returncode = handle.wait(timeout_s)
    except subprocess.TimeoutExpired:
        detail = f"killed after {timeout_s:g} s"
        try:
            handle.kill()
        except Exception as exc:
            detail += f" (kill failed: {type(exc).__name__}: {exc})"
        return Outcome("timeout", clock() - start, detail=detail)
    except Exception as exc:
        return Outcome("error", clock() - start, detail=f"{type(exc).__name__}: {exc}")
    wall_s = clock() - start
    if returncode != 0:
        return Outcome("error", wall_s, returncode, detail=f"exit status {returncode}")
    try:
        counters = adapter.counters()
        alerts = adapter.alerts()
    except Exception as exc:
        return Outcome(
            "error", wall_s, returncode, detail=f"outputs unreadable: {type(exc).__name__}: {exc}"
        )
    return Outcome("ok", wall_s, returncode, counters, alerts)
