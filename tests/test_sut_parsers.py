"""Each source parser of ``mbench sut``, on what dgx-spark actually returned."""

from __future__ import annotations

import pytest
from sutfixtures import ALIAS, FIXTURES, command_stdout, file_text, snapshot

from mbench import hostsrc, sut

X925 = "5-9,15-19"
A725 = "0-4,10-14"


def test_cpulist_round_trip() -> None:
    assert sut.parse_cpulist("0-4,10-14") == [0, 1, 2, 3, 4, 10, 11, 12, 13, 14]
    assert sut.parse_cpulist("") == []
    assert sut.parse_cpulist("3\n") == [3]
    assert sut.format_cpulist([5, 6, 7, 8, 9, 15, 16, 17, 18, 19]) == X925
    assert sut.format_cpulist([]) == ""
    assert sut.format_cpulist([0, 2, 3]) == "0,2-3"


def test_lscpu_models_heterogeneous_cpu() -> None:
    models = sut.parse_lscpu_models(command_stdout("lscpu", "-p=CPU,MODELNAME"))
    assert len(models) == 20
    x925 = sorted(c for c, m in models.items() if m == "Cortex-X925")
    a725 = sorted(c for c, m in models.items() if m == "Cortex-A725")
    assert sut.format_cpulist(x925) == X925
    assert sut.format_cpulist(a725) == A725


def test_lscpu_caches() -> None:
    caches = {c["name"]: c for c in sut.parse_lscpu_caches(command_stdout("lscpu", "-J", "-C"))}
    assert set(caches) == {"L1d", "L1i", "L2", "L3"}
    assert caches["L3"]["all_size"] == "24M"
    assert caches["L2"]["ways"] == 8


def test_cpuinfo_part_numbers() -> None:
    cpus = sut.parse_cpuinfo(file_text("/proc/cpuinfo"))
    assert len(cpus) == 20
    parts = sorted(info["cpu part"] for info in cpus.values())
    assert parts == ["0xd85"] * 10 + ["0xd87"] * 10  # X925, A725
    assert {info["cpu implementer"] for info in cpus.values()} == {"0x41"}


@pytest.mark.parametrize(
    ("cpu", "index", "kib"),
    [(0, 2, 512), (5, 2, 2048), (0, 3, 8192), (10, 3, 16384), (5, 0, 64)],
)
def test_cache_size_from_sysfs(cpu: int, index: int, kib: int) -> None:
    text = file_text(f"/sys/devices/system/cpu/cpu{cpu}/cache/index{index}/size")
    assert sut.parse_size_kib(text) == kib


def test_size_parser_rejects_garbage() -> None:
    assert sut.parse_size_kib("2M") == 2048
    with pytest.raises(ValueError):
        sut.parse_size_kib("lots")


def test_meminfo() -> None:
    meminfo = sut.parse_meminfo(file_text("/proc/meminfo"))
    assert meminfo["MemTotal"] == 125507832
    assert meminfo["Hugepagesize"] == 2048
    assert meminfo["HugePages_Total"] == 0
    node = sut.parse_meminfo(file_text("/sys/devices/system/node/node0/meminfo"))
    assert node["MemTotal"] == 125507832


def test_swaps_drop_the_swap_file_name() -> None:
    (area,) = sut.parse_swaps(file_text("/proc/swaps"))
    assert area["type"] == "file"
    assert area["size_kib"] == 16777212
    assert "name" not in area


def test_os_release() -> None:
    values = sut.parse_os_release(file_text("/etc/os-release"))
    assert values["ID"] == "ubuntu"
    assert values["VERSION_ID"] == "24.04"
    assert values["PRETTY_NAME"] == "Ubuntu 24.04.4 LTS"


def test_cmdline_redacts_filesystem_uuid() -> None:
    cmdline = sut.parse_cmdline(file_text("/proc/cmdline"))
    assert "root=UUID=<uuid>" in cmdline
    assert "pci=pcie_bus_safe" in cmdline
    assert sut.parse_cmdline("root=UUID=12345678-1234-5678-1234-567812345678 ro") == (
        "root=UUID=<uuid> ro"
    )


def test_cmdline_redacts_host_identifying_values() -> None:
    # Synthetic netboot and vendor parameters, documentation values only.
    raw = (
        "BOOT_IMAGE=/vmlinuz ro ip=192.0.2.10::192.0.2.1:255.255.255.0:bench-host:eth0:off "
        "nfsroot=192.0.2.1:/srv/nfs/bench-host,vers=4 BOOTIF=01-02-00-00-00-00-02 "
        "androidboot.serialno=SN-TEST-0001 serialno=SN-TEST-0002 "
        "ifname=boot0:02:00:00:00:00:03 netconsole=6665@192.0.2.10/eth0,6666@192.0.2.1/ "
        "hwaddr=02-00-00-00-00-05 server=198.51.100.7 console=ttyS0,115200 quiet\n"
    )
    assert sut.parse_cmdline(raw) == (
        "BOOT_IMAGE=/vmlinuz ro ip=<redacted> nfsroot=<redacted> BOOTIF=<redacted> "
        "androidboot.serialno=<redacted> serialno=<redacted> ifname=boot0:<mac> "
        "netconsole=<redacted> hwaddr=<mac> server=<ip> console=ttyS0,115200 quiet"
    )


def test_cmdline_of_dgx_spark_is_unchanged_by_the_redaction() -> None:
    cmdline = file_text("/proc/cmdline").strip()
    assert sut.parse_cmdline(cmdline) == cmdline.replace(
        "UUID=00000000-0000-0000-0000-000000000000", "UUID=<uuid>"
    )


def test_isolated_and_nohz_full_none() -> None:
    assert sut.parse_sysfs_cpumask_text(file_text("/sys/devices/system/cpu/isolated")) == ""
    assert sut.parse_sysfs_cpumask_text(file_text("/sys/devices/system/cpu/nohz_full")) == ""
    assert sut.parse_sysfs_cpumask_text("2-3\n") == "2-3"


def test_ethtool_i_realtek_and_connectx7() -> None:
    realtek = sut.parse_ethtool_i(command_stdout("ethtool", "-i", "enP7s7"))
    assert realtek["driver"] == "r8127"
    assert realtek["version"] == "11.014.00-NAPI"
    assert realtek["firmware-version"] == ""
    cx7 = sut.parse_ethtool_i(command_stdout("ethtool", "-i", "enp1s0f0np0"))
    assert cx7["driver"] == "mlx5_core"
    assert cx7["firmware-version"].startswith("28.45.4028")


def test_ethtool_k_offloads() -> None:
    features = sut.parse_ethtool_k(command_stdout("ethtool", "-k", "enP7s7"))
    assert features["generic-receive-offload"] == "on"
    assert features["large-receive-offload"] == "off [fixed]"
    assert features["tcp-segmentation-offload"] == "on"
    assert features["tx-checksum-ipv4"] == "on"  # indented sub-feature
    assert "Features for enP7s7" not in features


def test_ethtool_l_channels() -> None:
    realtek = sut.parse_ethtool_l(command_stdout("ethtool", "-l", "enP7s7"))
    assert realtek["max"] == {"rx": 4, "tx": 2, "other": None, "combined": None}
    assert realtek["current"]["rx"] == 1
    cx7 = sut.parse_ethtool_l(command_stdout("ethtool", "-l", "enp1s0f0np0"))
    assert cx7["current"]["combined"] == 20


def test_ethtool_g_rings() -> None:
    cx7 = sut.parse_ethtool_g(command_stdout("ethtool", "-g", "enp1s0f0np0"))
    assert cx7["max"] == {"rx": 8192, "rx_mini": None, "rx_jumbo": None, "tx": 8192}
    assert cx7["current"]["rx"] == 1024
    assert "cqe_size" not in cx7["current"]


def test_ethtool_x_rss_without_the_key() -> None:
    rss = sut.parse_ethtool_x(command_stdout("ethtool", "-x", "enp1s0f0np0"))
    assert rss["rx_rings"] == 20
    assert rss["indirection_table_size"] == 256
    assert rss["hash_functions"]["toeplitz"] == "on"
    assert "key" not in str(rss).lower()


def test_lspci_description() -> None:
    text = command_stdout("lspci", "-s", "0000:01:00.0", "-nn")
    assert sut.parse_lspci_nn(text) == (
        "Ethernet controller [0200]: Mellanox Technologies MT2910 Family [ConnectX-7] [15b3:1021]"
    )
    assert sut.parse_lspci_nn("") == ""


def test_docker_version_and_info() -> None:
    version = sut.parse_docker_version(
        command_stdout("docker", "version", "--format", "{{json .}}")
    )
    assert version["server_version"] == "29.2.1"
    assert version["containerd_version"] == "v2.2.1"
    assert version["runc_version"] == "1.3.4"
    info = sut.parse_docker_info(command_stdout("docker", "info", "--format", "{{json .}}"))
    assert info["cgroup_version"] == "2"
    assert info["cgroup_driver"] == "systemd"
    assert info["runtimes"] == ["io.containerd.runc.v2", "nvidia", "runc"]
    assert info["limit_support"]["cpuset"] is True


def test_proc_self_cgroup() -> None:
    path = sut.parse_proc_self_cgroup(file_text("/proc/self/cgroup"))
    assert path is not None and path.startswith("/user.slice/")
    assert sut.parse_proc_self_cgroup("12:cpu:/x\n") is None


def test_systemctl_show_user_units() -> None:
    props = "--property=Id,LoadState,ActiveState,SubState,UnitFileState"
    system = sut.parse_systemctl_show(
        command_stdout("systemctl", "show", "vllm-qwen.service", props, "--no-pager")
    )
    assert system["LoadState"] == "not-found"  # not a system unit on dgx-spark
    user = sut.parse_systemctl_show(
        command_stdout("systemctl", "--user", "show", "vllm-qwen.service", props, "--no-pager")
    )
    assert user["LoadState"] == "loaded"
    assert user["ActiveState"] == "active"


def test_loadavg() -> None:
    load = sut.parse_loadavg(file_text("/proc/loadavg"))
    assert set(load) == {"load1", "load5", "load15"}
    assert sut.parse_loadavg("3.76 3.83 4.61 8/5115 2430236\n") == {
        "load1": 3.76,
        "load5": 3.83,
        "load15": 4.61,
    }


def test_pid_stat() -> None:
    pids = [p for p in snapshot()["files"] if p.startswith("/proc/") and p.endswith("/stat")]
    pids = [p for p in pids if p.split("/")[2].isdigit()]
    assert pids
    stat = sut.parse_pid_stat(file_text(pids[0]))
    assert stat.pid == int(pids[0].split("/")[2])
    assert stat.ticks >= 0 and stat.rss_pages >= 0
    # A command name with spaces and parentheses.
    odd = sut.parse_pid_stat("42 (a (b) c) S 1 1 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 1 0 5 100 9 x")
    assert (odd.pid, odd.comm, odd.ticks, odd.rss_pages) == (42, "a (b) c", 10, 9)


def test_dmidecode_memory_synthetic() -> None:
    # Synthetic: a populated device and an empty slot (dgx-spark has no empty slot).
    text = (
        "Handle 0x0010, DMI type 17, 92 bytes\nMemory Device\n\tSize: 16 GB\n"
        "\tType: LPDDR5X\n\tSpeed: 8533 MT/s\n\tConfigured Memory Speed: 7500 MT/s\n\n"
        "Handle 0x0011, DMI type 17, 92 bytes\nMemory Device\n\tSize: No Module Installed\n"
        "\tType: Unknown\n"
    )
    assert sut.parse_dmidecode_memory(text) == {
        "devices": 1,
        "types": ["LPDDR5X"],
        # The two speeds differ, so a parser that swaps them fails here.
        "speeds": ["8533 MT/s"],
        "configured_speeds": ["7500 MT/s"],
    }


#: A synthetic ``dmidecode -t 17`` answer as root prints it: every identifying
#: field is present, with invented values.
DMIDECODE_AS_ROOT = (
    "# dmidecode 3.5\nGetting SMBIOS data from sysfs.\nSMBIOS 3.6.0 present.\n\n"
    "Handle 0x0010, DMI type 17, 92 bytes\nMemory Device\n\tArray Handle: 0x000F\n"
    "\tTotal Width: 16 bits\n\tSize: 16 GB\n\tLocator: DIMM-TEST-A\n"
    "\tBank Locator: BANK-TEST-0\n\tType: LPDDR5X\n\tSpeed: 8533 MT/s\n"
    "\tManufacturer: TestVendor\n\tSerial Number: SN-TEST-0001\n"
    "\tAsset Tag: AT-TEST-0001\n\tPart Number: PN-TEST-0001\n"
    "\tConfigured Memory Speed: 8533 MT/s\n\n"
    "Handle 0x0011, DMI type 17, 92 bytes\nMemory Device\n\tSize: No Module Installed\n"
    "\tLocator: DIMM-TEST-B\n\tType: Unknown\n\tSerial Number: Not Specified\n"
)
DMIDECODE_SECRETS = ("SN-TEST", "AT-TEST", "PN-TEST", "DIMM-TEST", "BANK-TEST", "TestVendor")


def test_dmidecode_reduced_to_the_fields_the_parser_reads() -> None:
    reduced = hostsrc.reduce_dmidecode_memory(DMIDECODE_AS_ROOT)
    for secret in (*DMIDECODE_SECRETS, "Serial Number", "Asset Tag", "Part Number"):
        assert secret not in reduced
    assert sut.parse_dmidecode_memory(reduced) == sut.parse_dmidecode_memory(DMIDECODE_AS_ROOT)
    assert sut.parse_dmidecode_memory(reduced)["devices"] == 1


#: The real ``dmidecode -t 17`` answer of dgx-spark, recorded as root with
#: ``mbench sut --record-sources`` on 2026-11-21 (#22): one memory device.
DMIDECODE_DGX_SPARK = (FIXTURES / "dmidecode-t17-root.txt").read_text(encoding="utf-8")


def _dmidecode_fields(text: str) -> list[tuple[str, str]]:
    return [
        (key.strip(), value.strip())
        for key, _, value in (line.partition(":") for line in text.splitlines()[1:])
    ]


def test_dmidecode_memory_of_dgx_spark() -> None:
    assert DMIDECODE_DGX_SPARK.splitlines()[0] == "Memory Device"
    # The parser reports no size: the size decides whether a device is populated.
    assert dict(_dmidecode_fields(DMIDECODE_DGX_SPARK))["Size"] == "128 GB"
    assert sut.parse_dmidecode_memory(DMIDECODE_DGX_SPARK) == {
        "devices": 1,
        "types": ["LPDDR5"],
        "speeds": ["8533 MT/s"],
        "configured_speeds": ["8533 MT/s"],
    }


def test_dmidecode_of_dgx_spark_is_unchanged_by_the_sanitiser() -> None:
    assert [key for key, _ in _dmidecode_fields(DMIDECODE_DGX_SPARK)] == list(
        hostsrc.DMIDECODE_MEMORY_KEYS
    )
    for field in ("Serial", "Asset Tag", "Part Number", "Locator", "Manufacturer"):
        assert field not in DMIDECODE_DGX_SPARK
    assert hostsrc.reduce_dmidecode_memory(DMIDECODE_DGX_SPARK) == DMIDECODE_DGX_SPARK
    assert hostsrc.sanitise_text(DMIDECODE_DGX_SPARK, ALIAS, ALIAS) == DMIDECODE_DGX_SPARK
    key = hostsrc.command_key(["dmidecode", "-t", "17"])
    answer = {"returncode": 0, "stdout": DMIDECODE_DGX_SPARK, "stderr": ""}
    recorded = {"files": {}, "dirs": {}, "links": {}, "commands": {key: [answer]}}
    clean = hostsrc.sanitise_snapshot(recorded, ALIAS, ALIAS, set(), set())
    assert clean["commands"][key] == [answer]


def test_raw_dmidecode_of_dgx_spark_is_recorded_as_the_fixture() -> None:
    # The real answer with a handle line and every identifying field put back,
    # all with synthetic values: the recorder must write the fixture.
    raw = DMIDECODE_DGX_SPARK.replace(
        "Memory Device\n",
        "Handle 0x0010, DMI type 17, 92 bytes\nMemory Device\n"
        "\tSerial Number: 00000000\n\tAsset Tag: AT-TEST\n\tPart Number: PN-TEST\n"
        "\tLocator: DIMM-TEST\n\tBank Locator: BANK-TEST\n\tManufacturer: TestVendor\n",
    )
    assert raw != DMIDECODE_DGX_SPARK
    assert hostsrc.reduce_dmidecode_memory(raw) == DMIDECODE_DGX_SPARK
    key = hostsrc.command_key(["dmidecode", "-t", "17"])
    answer = {"returncode": 0, "stdout": raw, "stderr": ""}
    recorded = {"files": {}, "dirs": {}, "links": {}, "commands": {key: [answer]}}
    clean = hostsrc.sanitise_snapshot(recorded, ALIAS, ALIAS, set(), set())
    assert clean["commands"][key] == [{**answer, "stdout": DMIDECODE_DGX_SPARK}]


def test_cpuinfo_serial_is_never_parsed() -> None:
    text = "processor\t: 0\nCPU part\t: 0xd85\nSerial\t\t: 00000000c0ffee01\n"
    assert sut.parse_cpuinfo(text) == {0: {"processor": "0", "cpu part": "0xd85"}}
