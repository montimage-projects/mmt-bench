"""Core-type topology: which CPUs are which core type (issue #10, plan §B5).

dgx-spark is heterogeneous — 10 Cortex-X925 and 10 Cortex-A725. A committed
campaign file never names CPU numbers: a ``core:<fragment>`` cpuset item is
resolved at load time against the host's own topology, derived from the same
``lscpu -p=CPU,MODELNAME`` the SUT collector reads, so the pinning the run
records is the pinning the record documents. The core *type* is safe to
commit; the numbers are a property of the host the campaign runs on.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from mbench import hostsrc, sut

#: A symbolic cpuset item: ``core:x925`` selects every CPU of the one core
#: type whose model name contains the fragment (case-insensitive).
SELECTOR = re.compile(r"^core:([a-z0-9][a-z0-9._-]*)$")


def by_model(models: Mapping[int, str]) -> dict[str, tuple[int, ...]]:
    """``{model name: its sorted cpus}``, the inverse of :func:`sut.parse_lscpu_models`."""
    grouped: dict[str, list[int]] = {}
    for cpu, name in models.items():
        grouped.setdefault(name, []).append(cpu)
    return {name: tuple(sorted(cpus)) for name, cpus in grouped.items()}


def live(source: hostsrc.Source | None = None) -> dict[str, tuple[int, ...]]:
    """The host's ``{model: cpus}``, from ``lscpu -p=CPU,MODELNAME``."""
    src = source if source is not None else hostsrc.LiveSource()
    result = src.run(["lscpu", "-p=CPU,MODELNAME"])
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise RuntimeError(f"lscpu -p=CPU,MODELNAME failed: {detail}")
    return by_model(sut.parse_lscpu_models(result.stdout))


def selector(item: str) -> str | None:
    """The fragment of a ``core:<fragment>`` cpuset item, else ``None``."""
    match = SELECTOR.match(item)
    return match.group(1) if match else None


def resolve(item: str, topology: Mapping[str, tuple[int, ...]]) -> tuple[int, ...]:
    """The cpus a ``core:<fragment>`` cpuset selects.

    The fragment matches a core type as a case-insensitive substring of its
    model name (``x925`` → ``Cortex-X925``). Raises :class:`LookupError` when
    no type matches, or several do — a cpuset that might pin the wrong cores
    is never guessed.
    """
    fragment = selector(item)
    assert fragment is not None, f"not a core: selector: {item!r}"
    matches = [(name, cpus) for name, cpus in topology.items() if fragment.lower() in name.lower()]
    if not matches:
        known = ", ".join(sorted(topology)) or "(none)"
        raise LookupError(f"cpusets: {item!r}: no core type matches (known: {known})")
    if len(matches) > 1:
        names = ", ".join(sorted(n for n, _ in matches))
        raise LookupError(f"cpusets: {item!r}: ambiguous core type ({names})")
    return matches[0][1]
