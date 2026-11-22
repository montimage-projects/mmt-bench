"""Adapters: one per tool under test, behind one interface.

``ADAPTERS`` maps the tool name a campaign lists (``tools: [mmt-probe]``) to
its adapter class; the runner (#8) instantiates one per run cell. Suricata
and Snort 3 come with P5 (#14); a test registers its fake here.
"""

from __future__ import annotations

from mbench.adapters.base import Adapter
from mbench.adapters.mmt_probe import MmtProbeAdapter

#: Tool name -> adapter class, resolved by ``mbench run``.
ADAPTERS: dict[str, type[Adapter]] = {
    "mmt-probe": MmtProbeAdapter,
}
