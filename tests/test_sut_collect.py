"""The collector on the replayed dgx-spark snapshot: sections, markers, sut_hash."""

from __future__ import annotations

import copy
import json
import os
from typing import Any

import pytest
from sutfixtures import ALIAS, GOLDEN, SOURCES, replay, snapshot

from mbench import hostsrc, sut, validate

#: The §B4 sections a record must carry.
SECTIONS = ("host", "os", "nics", "container_runtime", "tools", "noise", "harness", "sut_hash")


@pytest.fixture(scope="module")
def record() -> dict[str, Any]:
    return replay()


def test_golden_record_matches_replay(record: dict[str, Any]) -> None:
    text = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if os.environ.get("MBENCH_REGEN_FIXTURES") == "1":
        GOLDEN.write_text(text, encoding="utf-8")
    assert GOLDEN.read_text(encoding="utf-8") == text


def test_record_is_complete_and_valid(record: dict[str, Any]) -> None:
    for section in SECTIONS:
        assert section in record
    assert validate.sut_errors(record) == []


def test_heterogeneous_cpu_by_core_type(record: dict[str, Any]) -> None:
    cpu = record["host"]["cpu"]
    assert cpu["logical_cpus"] == 20
    types = {t["model_name"]: t for t in cpu["core_types"]}
    assert set(types) == {"Cortex-X925", "Cortex-A725"}
    x925, a725 = types["Cortex-X925"], types["Cortex-A725"]
    assert (x925["count"], x925["cpus"]) == (10, "5-9,15-19")
    assert (a725["count"], a725["cpus"]) == (10, "0-4,10-14")
    assert (x925["cpuinfo_max_mhz"], x925["cpuinfo_min_mhz"]) == (3900, 1378)
    assert (a725["cpuinfo_max_mhz"], a725["cpuinfo_min_mhz"]) == (2808, 338)
    assert x925["midr"].endswith("410fd851") and a725["midr"].endswith("410fd871")
    l2 = {name: next(c for c in t["caches"] if c["level"] == 2) for name, t in types.items()}
    assert l2["Cortex-X925"]["size_kib"] == 2048
    assert l2["Cortex-A725"]["size_kib"] == 512
    assert x925["governor"] == "performance"
    assert cpu["boost"] is False
    assert cpu["smt"] == {"control": "notsupported", "active": False}
    assert cpu["isolated"] == "" and cpu["nohz_full"] == ""


def test_l3_differs_per_cluster_and_is_listed(record: dict[str, Any]) -> None:
    # dgx-spark: the L3 is 8 MiB on CPUs 0-9 and 16 MiB on 10-19, within each type.
    x925 = next(t for t in record["host"]["cpu"]["core_types"] if t["model_name"] == "Cortex-X925")
    assert x925["nonuniform_fields"] == ["caches"]
    l3 = {
        v["cpus"]: next(c["size_kib"] for c in v["value"] if c["level"] == 3)
        for v in x925["variants"]["caches"]
    }
    assert l3 == {"5-9": 8192, "15-19": 16384}
    assert record["host"]["cpu"]["cache_totals"]["L3"] == {"instances": 2, "total_kib": 24576}


def test_host_memory_numa_dmi(record: dict[str, Any]) -> None:
    host = record["host"]
    assert host["architecture"] == "aarch64"
    assert host["dmi"]["product_name"] == "NVIDIA_DGX_Spark"
    assert host["dmi"]["sys_vendor"] == "NVIDIA"
    assert not any("serial" in key or "uuid" in key for key in host["dmi"])
    assert host["numa"]["nodes"] == [{"node": 0, "cpus": "0-19", "mem_total_kib": 125507832}]
    memory = host["memory"]
    assert memory["total_kib"] == 125507832
    assert memory["transparent_hugepage"] == {"enabled": "madvise", "defrag": "madvise"}
    assert memory["hugepages"]["default_size_kib"] == 2048
    assert {p["size_kib"] for p in memory["hugepages"]["pools"]} == {64, 2048, 32768, 1048576}
    assert memory["swap"]["total_kib"] == 16777212


def test_root_only_fields_are_markers_with_reasons(record: dict[str, Any]) -> None:
    missing = {path: (kind, reason) for path, kind, reason in sut.unavailable_fields(record)}
    for path in (
        "host.memory.speed",
        "host.memory.type",
        "os.sysctl_net_core.bpf_jit_harden",
        "noise.cpu_frequency[0].cpuinfo_cur_mhz",
    ):
        kind, reason = missing[path]
        assert kind == "needs_root"
        assert "root" in reason
    assert missing["os.sysctl_net_core.netdev_rss_key"][0] == "redacted"
    assert record["os"]["sysctl_net_core"]["netdev_max_backlog"] == "1000"
    assert record["os"]["sysctl_net_core"]["rmem_max"] == "212992"
    assert record["os"]["sysctl_net_core"]["busy_poll"] == "0"


def test_os_section(record: dict[str, Any]) -> None:
    os_ = record["os"]
    assert os_["distro"]["id"] == "ubuntu"
    assert os_["kernel"]["release"] == "6.17.0-1032-nvidia"
    assert "<uuid>" in os_["cmdline"]
    assert os_["mitigations"]["spectre_v2"] == "Mitigation: CSV2, BHB"


def test_nics(record: dict[str, Any]) -> None:
    nics = {n["name"]: n for n in record["nics"]}
    assert all(n["kind"] == "physical" for n in nics.values())
    realtek = nics["enP7s7"]
    assert realtek["driver"]["name"] == "r8127"
    assert realtek["driver"]["firmware"]["unavailable"] == "not_supported"
    assert realtek["link"]["speed_mbps"] == 1000
    assert realtek["pci"]["vendor_id"] == "0x10ec"
    assert realtek["offloads"]["gro"] is True and realtek["offloads"]["lro"] is False
    assert realtek["rss"]["unavailable"] == "not_supported"
    assert realtek["irqs"][0]["names"] == ["enP7s7-0"]
    assert realtek["irqs"][0]["affinity"] == "0-19"
    cx7 = nics["enp1s0f0np0"]
    assert "ConnectX-7" in cx7["pci"]["description"]
    assert cx7["link"]["speed_mbps"]["unavailable"] == "not_applicable"  # no cable
    assert cx7["queues"]["rx"] == 20
    assert cx7["rings"]["current"]["rx"] == 1024


def test_no_mac_or_ip_addresses_anywhere(record: dict[str, Any]) -> None:
    text = json.dumps(record) + json.dumps(snapshot())
    assert hostsrc._MAC.search(text.replace(hostsrc.DOC_MAC, "")) is None
    assert hostsrc._IPV4.search(text.replace(hostsrc.DOC_IPV4, "")) is None


def test_container_runtime(record: dict[str, Any]) -> None:
    runtime = record["container_runtime"]
    assert runtime["docker"]["server_version"] == "29.2.1"
    assert runtime["docker"]["cgroup_version"] == "2"
    assert runtime["cgroup"]["version"] == 2
    assert "cpuset" in runtime["cgroup"]["controllers"]
    assert runtime["limits"]["harness"]["memory_max"] == "max"
    assert runtime["limits"]["per_run"]["unavailable"] == "not_applicable"


def test_vllm_state_and_top_processes(record: dict[str, Any]) -> None:
    noise = record["noise"]
    services = {s["unit"]: s for s in noise["services"]}
    assert services["vllm-qwen.service"]["scope"] == "user"
    assert services["vllm-qwen.service"]["active_state"] == "active"
    assert services["vllm-health-watchdog.timer"]["active_state"] == "active"
    assert noise["vllm_stopped"] is False
    assert 1 <= len(noise["top_cpu"]) <= 10 and 1 <= len(noise["top_memory"]) <= 10
    cpu = [p["cpu_percent"] for p in noise["top_cpu"]]
    assert cpu == sorted(cpu, reverse=True)
    rss = [p["rss_kib"] for p in noise["top_memory"]]
    assert rss == sorted(rss, reverse=True)
    assert set(noise["load_average"]) == {"before", "after"}
    assert noise["thermal"]["zones"][0]["type"] == "acpitz"


def test_vllm_stopped_when_units_inactive() -> None:
    data = copy.deepcopy(snapshot())
    for key, answers in data["commands"].items():
        if "--user" in key and "show" in key:
            for answer in answers:
                answer["stdout"] = answer["stdout"].replace(
                    "ActiveState=active", "ActiveState=inactive"
                )
    record = sut.collect(hostsrc.SnapshotSource(data), _options())
    assert record["noise"]["vllm_stopped"] is True


PROPS = "--property=Id,LoadState,ActiveState,SubState,UnitFileState"


def test_unit_not_found_anywhere_is_recorded() -> None:
    data = copy.deepcopy(snapshot())
    unit = "nonexistent.service"
    answer = {"returncode": 0, "stdout": f"Id={unit}\nLoadState=not-found\n", "stderr": ""}
    for scope in ([], ["--user"]):
        key = hostsrc.command_key(["systemctl", *scope, "show", unit, PROPS, "--no-pager"])
        data["commands"][key] = [answer]
    record = sut.collect(hostsrc.SnapshotSource(data), _options(watch_units=(unit,)))
    (service,) = record["noise"]["services"]
    assert service["load_state"] == "not-found"
    assert service["scope"]["unavailable"] == "not_applicable"
    assert record["noise"]["vllm_stopped"]["unavailable"] == "not_applicable"


def test_user_bus_unreachable_is_unknown_not_stopped() -> None:
    # cron, sudo or a service has no user bus: `systemctl --user` fails, the
    # system scope says not-found. vLLM must not be recorded as stopped.
    data = copy.deepcopy(snapshot())
    for key, answers in data["commands"].items():
        if '"--user"' in key:
            data["commands"][key] = [
                {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "Failed to connect to bus: No medium found",
                }
                for _ in answers
            ]
    record = sut.collect(hostsrc.SnapshotSource(data), _options())
    for service in record["noise"]["services"]:
        assert service["active_state"]["unavailable"] == "error"
        assert "Failed to connect to bus" in service["active_state"]["reason"]
    assert record["noise"]["vllm_stopped"]["unavailable"] == "error"
    assert validate.sut_errors(record) == []


def test_unit_state_unreadable_without_systemctl() -> None:
    record = replay(watch_units=("other.service",))  # never recorded: systemctl "absent"
    (service,) = record["noise"]["services"]
    assert service["active_state"]["unavailable"] == "missing_tool"


def _options(**kw: Any) -> sut.Options:
    from sutfixtures import replay_options

    return replay_options(**kw)


def test_anonymise_replaces_the_hostname() -> None:
    record = replay(alias="bench-host-1")
    assert record["host"]["hostname"] == "bench-host-1"
    assert record["host"]["hostname_anonymised"] is True
    plain = replay(alias=None)
    assert plain["host"]["hostname"] == ALIAS  # the snapshot holds the alias already
    assert plain["host"]["hostname_anonymised"] is False


def test_host_scope_markers(record: dict[str, Any]) -> None:
    assert record["scope"] == "host"
    assert record["tools"]["unavailable"] == "not_applicable"
    assert record["harness"]["run"]["unavailable"] == "not_applicable"
    assert record["harness"]["pcaps"]["unavailable"] == "not_applicable"
    assert record["harness"]["collection"] == {
        "start": "2026-11-20T22:00:00Z",
        "end": "2026-11-20T22:00:00Z",
    }


def test_unknown_extra_nic_is_an_error() -> None:
    with pytest.raises(ValueError, match="no such network interface: veth-missing"):
        replay(extra_nics=("veth-missing",))


def test_field_count_and_markers_counted_once(record: dict[str, Any]) -> None:
    assert sut.field_count(record) > 1000
    assert sut.field_count({"a": sut.unavailable("error", "x"), "b": [1, 2], "c": {"d": 1}}) == 3


def test_unknown_marker_kind_rejected() -> None:
    with pytest.raises(ValueError):
        sut.unavailable("broken", "x")


# --- sut_hash -------------------------------------------------------------------


def test_sut_hash_is_stable_on_replay(record: dict[str, Any]) -> None:
    assert record["sut_hash"] == sut.sut_hash(record)
    assert replay()["sut_hash"] == record["sut_hash"]


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r["noise"]["load_average"].update(
            before={"load1": 99.0, "load5": 1, "load15": 1}
        ),
        lambda r: r.update(tools=[{"name": "mmt-probe"}]),
        lambda r: r["noise"]["top_cpu"].clear(),
        lambda r: r["host"].update(hostname="other", hostname_anonymised=True),
        lambda r: r["container_runtime"]["docker"].update(server_version="30.0.0"),
        lambda r: r["harness"].update(mbench_version="9.9.9"),
        lambda r: r["nics"][0]["irqs"][0].update(effective_affinity="7"),
        lambda r: r["nics"][0]["irqs"][0].update(affinity="3"),
        lambda r: r["nics"].append({"name": "veth0", "kind": "virtual"}),
        lambda r: r["nics"][5]["link"].update(operstate="up", duplex="full"),
        lambda r: r["host"]["cpu"]["core_types"][0].update(scaling_max_mhz=1500),
    ],
    ids=[
        "load-average",
        "tools",
        "top-processes",
        "hostname",
        "container-runtime",
        "harness",
        "irq-effective-affinity",
        "irq-affinity",
        "virtual-nic",
        "wifi-link-up",
        "scaling-max-lowered",
    ],
)
def test_sut_hash_ignores_noise_tools_and_harness(record: dict[str, Any], change: Any) -> None:
    changed = copy.deepcopy(record)
    change(changed)
    assert sut.sut_hash(changed) == record["sut_hash"]


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r["os"]["kernel"].update(release="6.18.0-1-nvidia"),
        lambda r: r["os"]["sysctl_net_core"].update(netdev_max_backlog="250000"),
        lambda r: r["host"]["cpu"]["core_types"][0].update(governor="powersave"),
        lambda r: r["host"]["memory"].update(total_kib=1),
        lambda r: r["nics"][0]["offloads"].update(gro=False),
        lambda r: r["nics"][0]["link"].update(mtu=9000),
        lambda r: r["host"]["cpu"]["core_types"][0].update(cpuinfo_max_mhz=3000),
    ],
    ids=["kernel", "sysctl", "governor", "memory", "nic-offload", "nic-mtu", "cpuinfo-max"],
)
def test_sut_hash_changes_with_hardware_or_os(record: dict[str, Any], change: Any) -> None:
    changed = copy.deepcopy(record)
    change(changed)
    assert sut.sut_hash(changed) != record["sut_hash"]


WIFI = "wlP9s9"
CX7 = "enP2p1s0f0np0"


def _collect(data: dict[str, Any], **kw: Any) -> dict[str, Any]:
    return sut.collect(hostsrc.SnapshotSource(data), _options(**kw))


def _with_files(**files: str) -> dict[str, Any]:
    data = copy.deepcopy(snapshot())
    for path, text in files.items():
        data["files"][path] = [text]
    return data


def test_sut_hash_unchanged_when_the_wifi_link_comes_up(record: dict[str, Any]) -> None:
    up = _collect(_with_files(**{f"/sys/class/net/{WIFI}/operstate": "up\n"}))
    (wifi,) = [n for n in up["nics"] if n["name"] == WIFI]
    assert wifi["link"]["operstate"] == "up"
    assert up["sut_hash"] == record["sut_hash"]
    assert validate.sut_errors(up) == []


def test_sut_hash_unchanged_when_an_unused_port_gets_a_cable(record: dict[str, Any]) -> None:
    net = f"/sys/class/net/{CX7}"
    data = _with_files(
        **{f"{net}/operstate": "up\n", f"{net}/speed": "200000\n", f"{net}/duplex": "full\n"}
    )
    assert _collect(data)["sut_hash"] == record["sut_hash"]


def test_link_state_is_hashed_for_the_nic_under_test() -> None:
    net = f"/sys/class/net/{CX7}"
    down = _collect(copy.deepcopy(snapshot()), extra_nics=(CX7,))
    up = _collect(
        _with_files(**{f"{net}/operstate": "up\n", f"{net}/speed": "200000\n"}),
        extra_nics=(CX7,),
    )
    (nic,) = [n for n in up["nics"] if n["name"] == CX7]
    assert nic["under_test"] is True and nic["link"]["speed_mbps"] == 200000
    assert up["sut_hash"] != down["sut_hash"]
    assert [n["name"] for n in up["nics"] if n["under_test"]] == [CX7]


def test_sut_hash_unchanged_when_irqbalance_moves_an_interrupt(record: dict[str, Any]) -> None:
    irq = record["nics"][0]["irqs"][1]["irq"]
    moved = _collect(_with_files(**{f"/proc/irq/{irq}/smp_affinity_list": "3\n"}))
    assert moved["nics"][0]["irqs"][1]["affinity"] == "3"
    assert moved["sut_hash"] == record["sut_hash"]


def test_sut_hash_uses_the_hardware_maximum_frequency(record: dict[str, Any]) -> None:
    cpufreq = "/sys/devices/system/cpu/cpu5/cpufreq"
    throttled = _collect(_with_files(**{f"{cpufreq}/scaling_max_freq": "1500000\n"}))
    x925 = throttled["host"]["cpu"]["core_types"][1]
    assert "scaling_max_mhz" in x925["nonuniform_fields"]  # recorded, not hashed
    assert throttled["sut_hash"] == record["sut_hash"]
    slower = _collect(_with_files(**{f"{cpufreq}/cpuinfo_max_freq": "1500000\n"}))
    assert slower["sut_hash"] != record["sut_hash"]


# --- No physical NIC -------------------------------------------------------------


def _without_physical_nics() -> dict[str, Any]:
    data = copy.deepcopy(snapshot())
    data["dirs"]["/sys/class/net"] = [["eth0", "lo"]]  # a container: a veth and lo
    data["links"] = {k: v for k, v in data["links"].items() if not k.startswith("/sys/class/net/")}
    return data


def test_no_physical_nic_is_a_marker_that_points_to_nic() -> None:
    record = _collect(_without_physical_nics())
    assert record["nics"]["unavailable"] == "not_supported"
    assert "--nic" in record["nics"]["reason"]
    assert validate.sut_errors(record) == []


def test_no_physical_nic_but_the_veth_under_test_is_recorded() -> None:
    record = _collect(_without_physical_nics(), extra_nics=("eth0",))
    (nic,) = record["nics"]
    assert (nic["name"], nic["kind"], nic["under_test"]) == ("eth0", "virtual", True)
    assert validate.sut_errors(record) == []


def test_unreadable_sys_class_net_is_a_marker_not_an_empty_list() -> None:
    data = copy.deepcopy(snapshot())
    data["dirs"]["/sys/class/net"] = [{"errno": 13, "error": "Permission denied"}]
    record = _collect(data)
    assert record["nics"]["unavailable"] == "needs_root"
    assert validate.sut_errors(record) == []
    with pytest.raises(ValueError, match="cannot find veth0"):
        _collect(data, extra_nics=("veth0",))


# --- Kernel command line -----------------------------------------------------------


def _netbooted(hostname: str) -> dict[str, Any]:
    data = copy.deepcopy(snapshot())
    data["files"]["/proc/sys/kernel/hostname"] = [f"{hostname}\n"]
    data["files"]["/proc/cmdline"] = [
        "BOOT_IMAGE=/vmlinuz ro ip=192.0.2.10::192.0.2.1:255.255.255.0:bench-host:eth0:off "
        f"BOOTIF=01-02-00-00-00-00-02 systemd.hostname={hostname} quiet\n"
    ]
    return data


def test_anonymise_replaces_the_hostname_in_the_cmdline() -> None:
    record = _collect(_netbooted("bench-host"), alias="sut")
    assert record["os"]["cmdline"] == (
        "BOOT_IMAGE=/vmlinuz ro ip=<redacted> BOOTIF=<redacted> systemd.hostname=sut quiet"
    )
    assert "bench-host" not in json.dumps(record)
    plain = _collect(_netbooted("bench-host"), alias=None)
    assert "systemd.hostname=bench-host" in plain["os"]["cmdline"]
    # The hostname is not hashed, inside the command line either.
    assert plain["sut_hash"] == record["sut_hash"]
    assert _collect(_netbooted("other-host"), alias=None)["sut_hash"] == record["sut_hash"]


# --- Recording and sanitising ---------------------------------------------------


def test_recording_a_replay_reproduces_the_snapshot() -> None:
    recorder = hostsrc.RecordingSource(hostsrc.SnapshotSource(snapshot()))
    first = sut.collect(recorder, _options())
    again = sut.collect(hostsrc.SnapshotSource(recorder.snapshot()), _options())
    assert again == first


def test_sanitise_text() -> None:
    # Synthetic inputs from the documentation ranges, unlike the outputs, so
    # the test shows each one is replaced. No real host value appears here.
    raw = (
        "host bench-host mac 02:00:00:00:00:02 ip 192.0.2.77 ip6 2001:db8::42 "
        "dash 02-00-00-00-00-03 bootif 01-02-00-00-00-00-04 "
        "full 2001:0db8:0000:0000:0000:0000:0000:0002 "
        "uuid 12345678-1234-5678-1234-567812345678 key 0a:0b:0c:0d:0e:0f:10:11:12"
        " version 6.17.0 fw 28.45.4028"
    )
    clean = hostsrc.sanitise_text(raw, "bench-host", "sut")
    assert clean == (
        f"host sut mac {hostsrc.DOC_MAC} ip {hostsrc.DOC_IPV4} ip6 {hostsrc.DOC_IPV6} "
        f"dash {hostsrc.DOC_DASH_MAC} bootif 00-00-00-00-00-00-00 "
        f"full {hostsrc.DOC_IPV6} uuid {hostsrc.ZERO_UUID} "
        "key 00:00:00:00:00:00:00:00:00 version 6.17.0 fw 28.45.4028"
    )


@pytest.mark.parametrize(
    "text",
    [
        "0::/user.slice/user-1000.slice\n",  # cgroup v2 line
        "bus-info: 0000:01:00.0",  # PCI address
        "Wed Aug 19 17:40:46 UTC 2026",  # time of day
        "dmi:bvnAmericanMegatrendsInternational,LLC.:bvr5.36",
    ],
)
def test_sanitise_text_leaves_non_addresses_alone(text: str) -> None:
    assert hostsrc.sanitise_text(text, None, "sut") == text


def test_fixtures_are_already_sanitised() -> None:
    # Re-sanitising the committed fixtures changes nothing: no MAC, IP, UUID
    # or RSS key is left in them.
    for path in (GOLDEN, SOURCES):
        text = path.read_text(encoding="utf-8")
        assert hostsrc.sanitise_text(text, None, ALIAS) == text, path
        assert "/home/" not in text, path  # no home directory, so no username


def test_sanitise_snapshot_prunes_processes_and_interfaces() -> None:
    data = {
        "snapshot_version": 1,
        "constants": {"euid": 1000, "page_size": 4096, "clock_ticks": 100},
        "files": {
            "/proc/1/stat": ["1 (init) S"],
            "/proc/2/stat": ["2 (secret) S"],
            "/sys/class/net/eth0/mtu": ["1500"],
            "/sys/class/net/br-client/mtu": ["1500"],
            "/proc/sys/kernel/hostname": ["realname\n"],
        },
        "dirs": {"/proc": [["1", "2", "cpuinfo"]], "/sys/class/net": [["br-client", "eth0"]]},
        "links": {
            "/sys/class/net/br-client/device": {"errno": 2, "error": "x"},
            "/srv/checkout/src/mbench": "/srv/checkout/src/mbench",
        },
        "commands": {
            '["ethtool", "-i", "br-client"]': [{"returncode": 0, "stdout": "", "stderr": ""}],
            '["git", "--no-optional-locks", "-C", "/srv/checkout/src/mbench", "rev-parse"]': [
                {"returncode": 0, "stdout": "/srv/checkout\n", "stderr": ""}
            ],
            '["docker", "info", "--format", "{{json .}}"]': [
                {
                    "returncode": 0,
                    "stdout": '{"ID": "abc", "Name": "realname", "NCPU": 4}',
                    "stderr": "",
                }
            ],
        },
    }
    clean = hostsrc.sanitise_snapshot(data, "realname", "sut", {1}, {"eth0"})
    assert set(clean["files"]) == {
        "/proc/1/stat",
        "/sys/class/net/eth0/mtu",
        "/proc/sys/kernel/hostname",
    }
    assert clean["files"]["/proc/sys/kernel/hostname"] == ["sut\n"]
    assert clean["dirs"]["/proc"] == [["1", "cpuinfo"]]
    assert clean["dirs"]["/sys/class/net"] == [["eth0"]]
    assert clean["links"] == {}
    assert list(clean["commands"]) == ['["docker", "info", "--format", "{{json .}}"]']
    docker = json.loads(
        clean["commands"]['["docker", "info", "--format", "{{json .}}"]'][0]["stdout"]
    )
    assert docker == {"NCPU": 4}


def test_sanitised_root_recording_keeps_no_dimm_or_board_serial() -> None:
    from test_sut_parsers import DMIDECODE_AS_ROOT, DMIDECODE_SECRETS

    data = copy.deepcopy(snapshot())
    data["constants"]["euid"] = 0  # recorded as root: the SMBIOS table is readable
    data["files"]["/sys/firmware/dmi/tables/smbios_entry_point"] = ["_SM3_"]
    data["commands"][hostsrc.command_key(["dmidecode", "-t", "17"])] = [
        {"returncode": 0, "stdout": DMIDECODE_AS_ROOT, "stderr": ""}
    ]
    serial = "Serial\t\t: 00000000c0ffee01\n"
    data["files"]["/proc/cpuinfo"] = [data["files"]["/proc/cpuinfo"][0] + serial]
    recorder = hostsrc.RecordingSource(hostsrc.SnapshotSource(data))
    live = sut.collect(recorder, _options())
    assert live["host"]["memory"]["speed"] == ["8533 MT/s"]
    pids = {p["pid"] for key in ("top_cpu", "top_memory") for p in live["noise"][key]}
    clean = hostsrc.sanitise_snapshot(
        recorder.snapshot(), ALIAS, ALIAS, pids, {n["name"] for n in live["nics"]}
    )
    text = json.dumps(clean)
    for secret in (*DMIDECODE_SECRETS, "Serial Number", "Asset Tag", "Part Number", "c0ffee01"):
        assert secret not in text
    replayed = sut.collect(hostsrc.SnapshotSource(clean), _options())
    assert replayed["host"] == live["host"]
    assert replayed["sut_hash"] == live["sut_hash"]


def test_snapshot_source_errors_and_sequences() -> None:
    src = hostsrc.SnapshotSource(
        {
            "snapshot_version": 1,
            "constants": {"euid": 1000, "page_size": 4096, "clock_ticks": 100},
            "files": {
                "/a": ["one", "two"],
                "/root-only": [{"errno": 13, "error": "Permission denied"}],
            },
            "dirs": {},
            "links": {},
            "commands": {},
        }
    )
    assert [src.read("/a"), src.read("/a"), src.read("/a")] == ["one", "two", "two"]
    with pytest.raises(PermissionError):
        src.read("/root-only")
    with pytest.raises(FileNotFoundError):
        src.read("/missing")
    with pytest.raises(FileNotFoundError):
        src.run(["ethtool", "-i", "x"])
    with pytest.raises(ValueError):
        hostsrc.SnapshotSource({"snapshot_version": 99})


def test_permission_denied_as_root_is_an_error_not_needs_root() -> None:
    data = copy.deepcopy(snapshot())
    data["constants"]["euid"] = 0
    record = sut.collect(hostsrc.SnapshotSource(data), _options())
    kinds = {path: kind for path, kind, _ in sut.unavailable_fields(record)}
    assert kinds["os.sysctl_net_core.bpf_jit_harden"] == "error"
