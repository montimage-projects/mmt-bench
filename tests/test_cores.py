"""``mbench.cores`` (#10): ``core:<fragment>`` cpusets resolved from lscpu.

The topology is the sanitised dgx-spark snapshot (Cortex-A725 on the even
cluster, Cortex-X925 on the odd): a committed campaign names the core
*type*, and the resolution — and the recorded cpulist — is derived on the
host the campaign runs on.
"""

from __future__ import annotations

import pytest
from sutfixtures import command_stdout, source

from mbench import cores, sut

MODELS = sut.parse_lscpu_models(command_stdout("lscpu", "-p=CPU,MODELNAME"))
TOPOLOGY = cores.by_model(MODELS)


def test_the_fixture_topology_is_the_two_core_types() -> None:
    assert TOPOLOGY == {
        "Cortex-A725": (0, 1, 2, 3, 4, 10, 11, 12, 13, 14),
        "Cortex-X925": (5, 6, 7, 8, 9, 15, 16, 17, 18, 19),
    }


def test_live_reads_the_same_lscpu_the_sut_reads() -> None:
    assert cores.live(source()) == TOPOLOGY


def test_a_fragment_picks_its_core_type() -> None:
    assert cores.resolve("core:x925", TOPOLOGY) == TOPOLOGY["Cortex-X925"]
    # the fragment is lower-case; matching the model name is case-insensitive
    assert cores.resolve("core:a725", TOPOLOGY) == TOPOLOGY["Cortex-A725"]
    assert cores.resolve("core:cortex-a", TOPOLOGY) == TOPOLOGY["Cortex-A725"]


def test_a_plain_cpulist_is_not_a_selector() -> None:
    assert cores.selector("0-3") is None
    assert cores.selector("") is None
    assert cores.selector("core:x925") == "x925"


def test_a_fragment_matching_nothing_is_an_error() -> None:
    with pytest.raises(LookupError, match="no core type matches"):
        cores.resolve("core:i9", TOPOLOGY)


def test_an_ambiguous_fragment_is_an_error() -> None:
    # "cortex" names both types: never guess which cores a campaign pins.
    with pytest.raises(LookupError, match="ambiguous"):
        cores.resolve("core:cortex", TOPOLOGY)


def test_a_fragment_needs_a_topology() -> None:
    with pytest.raises(LookupError):
        cores.resolve("core:x925", {})
