# The system-under-test fingerprint (`sut.json`)

Every campaign and every run carries a full record of the host it ran on
(plan §B4). A run without a complete record is invalid. This page describes
the record, how `mbench sut` collects it, and how `mbench validate` checks it.

- Code: `src/mbench/sut.py` (collector, parsers, `sut_hash`),
  `src/mbench/hostsrc.py` (live, recording and replay sources),
  `src/mbench/validate.py`.
- Schema: `src/mbench/schemas/sut.schema.json` (JSON Schema 2020-12).

## Commands

```sh
uv run mbench sut -o sut.json            # collect; a summary goes to stderr
uv run mbench sut --anonymise -o sut.json            # hostname -> "sut"
uv run mbench sut --anonymise bench-1 -o sut.json    # hostname -> "bench-1"
uv run mbench validate sut.json          # exit 0 complete, 1 incomplete, 2 unreadable
```

`mbench sut` options:

| Option | Meaning |
| --- | --- |
| `-o PATH` | Write the record to `PATH` (default: standard output). |
| `--anonymise [ALIAS]` | Record `ALIAS` (default `sut`) instead of the hostname. |
| `--nic IFACE` | The interface under test (`nics[].under_test`): its link state is hashed. A virtual one, for example the veth under test in P4, is recorded only when named here. Repeatable. Physical NICs are always recorded. |
| `--watch UNIT` | Also record this systemd unit's state. `vllm-qwen.service` and `vllm-health-watchdog.timer` are always recorded. Repeatable. |
| `--sample-seconds S` | Window over which the top CPU processes are measured (default 1). |
| `--top N` | Number of top CPU and top memory processes listed (default 10). |
| `--record-sources PATH` | Also write every source read, sanitised, as a replayable snapshot (how the test fixtures are captured). |

On stderr, `mbench sut` prints the field count, the number of unavailable
fields, the `sut_hash`, and one line per unavailable field with its reason.

`mbench sut` checks its own record against the schema. Exit status: 0 when the
record is written and complete, 1 when it is written but does not validate
(each problem is printed; please report the host), 2 on a usage error (an
unknown `--nic`, a bad option).

## Read-only, no sudo

`mbench sut` only reads `/proc`, `/sys` and `/etc/os-release`, and runs these
inspection commands, none of which changes host state:

`lscpu -p=CPU,MODELNAME`, `lscpu -J -C`, `uname -m`, `ethtool -i/-k/-l/-g/-x IFACE`,
`lspci -s ADDR -nn`, `docker version --format '{{json .}}'`,
`docker info --format '{{json .}}'`, `systemctl [--user] show UNIT --property=...`,
`dmidecode -t 17` only when the SMBIOS table is readable (that is, as root),
and, for `harness.mbench_commit` and `harness.mbench_dirty`,
`git --no-optional-locks -C DIR rev-parse --show-toplevel`,
`git --no-optional-locks -C DIR rev-parse --verify HEAD` and
`git --no-optional-locks -C DIR status --porcelain --untracked-files=no`.

`--no-optional-locks` (and `GIT_OPTIONAL_LOCKS=0` in the environment of every
command) stops `git status` from refreshing the index: without it, git takes
`.git/index.lock` and rewrites `.git/index`, which writes to the checkout and
can make a concurrent git command there fail. The commit is recorded only when
the git work tree around the mbench package is mbench's own source tree
(`<toplevel>/src/mbench` is the package); an mbench installed in another
repository (a project's `.venv`, a `$HOME` kept in git) records a
`not_applicable` marker, not that repository's HEAD.

It never starts, stops or inspects a container, and never changes a unit,
a governor or a sysctl. It writes nothing but its output file (and the
`--record-sources` file).

## Unavailable fields

Every field in the schema is required. A field the collector cannot read is
never dropped: it holds an *unavailable marker* instead of a value:

```json
{"unavailable": "needs_root", "reason": "/proc/sys/net/core/bpf_jit_harden is readable by root only"}
```

| Kind | Meaning |
| --- | --- |
| `needs_root` | Readable by root only; the collector runs without sudo. |
| `not_supported` | This host, kernel or driver does not expose it (no `ethtool -x` on the r8127). |
| `not_applicable` | The field has no meaning here (a link that is down has no speed; a host-scope record has no tool under test). |
| `missing_tool` | The inspection command is not installed. |
| `redacted` | Readable, deliberately not recorded because it is a secret (`net.core.netdev_rss_key`). |
| `error` | The read failed for another reason, given in `reason`. |

On dgx-spark without sudo, these fields need root:

- `host.memory.speed` and `host.memory.type`: the SMBIOS table
  (`/sys/firmware/dmi/tables/DMI`, read by `dmidecode`) is mode 0400.
- `os.sysctl_net_core.bpf_jit_harden`, `bpf_jit_kallsyms`, `bpf_jit_limit`.
- `noise.cpu_frequency[*].cpuinfo_cur_mhz`: `cpuinfo_cur_freq` is root only;
  `scaling_cur_mhz` is recorded next to it.

A host with no physical NIC (a container whose only interface is a veth) and
no `--nic` records `nics` as a `not_supported` marker that points to `--nic`;
an unreadable `/sys/class/net` records the marker of the failed read. `nics` is
never an empty list.

## A strict schema

- Every object of the record is closed (`additionalProperties: false`): a
  field the schema does not list, such as a planted `host.serial` or
  `nics[0].mac`, makes the record invalid. Only the maps keyed by the host
  (sysctls, mitigations, `ethtool -k` features, cache and cooling-device
  names, CPU variants) take any key, and each of their values is typed.
- Sizes and counts are `minimum: 0` (`host.memory.total_kib` and
  `host.cpu.logical_cpus` are at least 1; `host.cpu.core_types` is not empty).
- Core identity fields hold a value, or a marker that says the host does not
  expose it, it needs root, or the tool is missing (`not_supported`,
  `needs_root`, `missing_tool`). An `error`, `not_applicable` or `redacted`
  marker there makes the record invalid: `os.kernel.release`,
  `os.kernel.version`, `os.distro`, `os.cmdline`, `host.architecture`,
  `host.memory.total_kib` and `host.cpu.core_types[].model_name`.
- `container_runtime.limits.harness` and `container_runtime.limits.per_run`
  are the same closed object, `{cpu_max, memory_max, cpuset_cpus}` (the
  cgroup v2 `cpu.max`, `memory.max` and `cpuset.cpus.effective` of the harness,
  or of the run's container). In host scope, `per_run` may be a marker; in run
  scope it must be that object.

## Sections

| Section | §B4 content | Main sources |
| --- | --- | --- |
| `host` | Hostname (or alias), architecture, DMI vendor and model; CPU per core type (model, MIDR, count, CPUs, max and min frequency, governor, scaling driver, caches), boost, SMT, `isolated`, `nohz_full`, cache totals; NUMA nodes; memory size, speed and type, hugepages, transparent hugepages, swap | `/sys/devices/system/cpu`, `lscpu`, `/proc/cpuinfo`, `/sys/class/dmi/id`, `/sys/devices/system/node`, `/proc/meminfo`, `/sys/kernel/mm`, `/proc/swaps`, `dmidecode` (root) |
| `os` | Distro and version, kernel release and version, kernel command line, mitigations, every `net.core.*` sysctl | `/etc/os-release`, `/proc/sys/kernel`, `/proc/cmdline`, `/sys/devices/system/cpu/vulnerabilities`, `/proc/sys/net/core` |
| `nics` | Per NIC: whether it is under test (`--nic`), PCI ids and description, driver, driver version, firmware, link state and speed, MTU, queues and RPS, channels, ring sizes, offloads (GRO, LRO, TSO, GSO, every `ethtool -k` feature), RSS, IRQs with their affinity | `/sys/class/net`, `ethtool`, `lspci`, `/proc/irq` |
| `container_runtime` | Docker client, server, API, containerd and runc versions, storage and cgroup drivers, runtimes, limit support; cgroup version and controllers; the harness's own cgroup limits; per-run limits (filled by the runner) | `docker version`, `docker info`, `/sys/fs/cgroup`, `/proc/self/cgroup` |
| `tools` | Tools under test: image digest, version strings, build flags, rule-set id and hash, config hash and content. Filled from the adapter at run time (#5) | the adapter |
| `noise` | Load average before and after, top CPU and memory processes over a sample window, watched units and whether vLLM was stopped, running container count, available memory and swap used, thermal zones and cooling devices, current frequency per core type and `perf_limited` CPUs | `/proc/loadavg`, `/proc/PID/stat`, `systemctl show`, `docker info`, `/sys/class/thermal`, `cpufreq` |
| `harness` | mbench version, commit and dirty flag, Python version, collection start and end; run start and end and pcap sha256s (filled by the runner, #8) | the running mbench, `git` |

A CPU field that differs between CPUs of one core type keeps the first CPU's
value, is listed in `nonuniform_fields`, and has every variant with its CPUs in
`variants`. On dgx-spark the L3 is 8 MiB on CPUs 0–9 and 16 MiB on CPUs 10–19,
so `caches` is listed there for both core types.

## Scope: host and run

`mbench sut` writes a record with `"scope": "host"`. There, `tools`,
`harness.run`, `harness.pcaps` and `container_runtime.limits.per_run` hold
`not_applicable` markers. The runner (#8) embeds the record in each run with
`"scope": "run"` and fills them; the schema then requires real values for all
four, so a run record with a marker there is incomplete.

## `sut_hash`

`sut_hash` is `sha256:` plus the sha256 of the canonical JSON (sorted keys, no
spaces) of:

- `schema_version`;
- `host`, without `hostname`, `hostname_anonymised` and
  `cpu.core_types[].scaling_max_mhz` (a thermal or power limit lowers it; the
  hardware maximum `cpuinfo_max_mhz` is hashed);
- `os` as recorded: its `cmdline` never holds the hostname — every
  `*hostname=` value is `<redacted>`, and a hostname embedded in another
  value (a device path, a version string) is kept verbatim;
- the physical NICs in `nics` (or the `nics` marker), without `under_test`,
  `irqs[].affinity` (irqbalance rewrites it) and `irqs[].effective_affinity`
  (where the kernel last placed the interrupt), and without the link state
  (`link.operstate`, `link.speed_mbps`, `link.duplex`) of every NIC that is not
  under test.

It leaves out `container_runtime`, `tools`, `noise`, `harness`, the collection
times and any virtual NIC added with `--nic`. So it is unchanged when the load,
the tools or the Docker version change, when an unused port or the Wi-Fi link
comes up, when irqbalance moves an interrupt, or when the CPU is throttled; it
changes with the kernel, a sysctl, the governor, memory, a NIC setting such as
the MTU, and the link of a NIC under test. Naming a physical NIC with `--nic`
adds its link state, so it changes the hash. Runs are compared only when their
`sut_hash` matches; the report flags a mismatch (#8).

An unavailable marker is hashed like any value, so a record collected as root
(memory speed readable) and one collected without root have different hashes.

`mbench validate` re-computes the hash and reports a record whose `sut_hash`
does not match its content.

## `mbench validate`

`mbench validate PATH...` checks each sut.json record against the schema and
its `sut_hash`. It prints `valid` with the field count and lists the
unavailable fields (`-q` hides them), or prints `INVALID` with one line per
problem, naming the field:

```text
sut.json: INVALID (2 problems)
  missing field: host.cpu.core_types[0].governor
  missing field: os.kernel.release
```

Exit status: 0 when every record is complete, 1 when one is incomplete or not
JSON, 2 when a file cannot be read (missing, not readable, not UTF-8) or is not
a kind of record it checks yet.
The corpus manifest (`corpus/manifest.yaml`) is checked too (#7); campaign
files are added by #8.

## Privacy

Never recorded: MAC addresses, IP addresses, DMI and DIMM serial numbers,
asset tags and part numbers, the product UUID, the board serial number of
`/proc/cpuinfo`, the RSS hash key, process arguments (only the command name),
container names, the names of interfaces that are not recorded, and the path
of the mbench checkout.

In the kernel command line (`os.cmdline`), filesystem UUIDs become `<uuid>`;
the values of `ip=`, `nfsroot=`, `nfsaddrs=`, `BOOTIF=`, `netconsole=`,
`rd.iscsi.initiator=`, `iscsi_initiator=`, any `*serialno=` and any
`*hostname=` (`hostname=`, `systemd.hostname=` ...) become `<redacted>`; any
other MAC address (colon- or dash-separated) becomes `<mac>` and any IPv4
address `<ip>`. `--anonymise` replaces `host.hostname`. A hostname embedded in
another value, such as the volume names of an Ubuntu LVM root
(`root=/dev/mapper/ubuntu--vg-ubuntu--lv`), is kept verbatim: it names the
volume, not the host.

## Test fixtures

`tests/fixtures/dgx-spark/sources.json` is a snapshot of one `mbench sut` run
on dgx-spark, captured with:

```sh
uv run mbench sut --anonymise dgx-spark --record-sources tests/fixtures/dgx-spark/sources.json -o /dev/null
```

`--record-sources` sanitises before writing: the hostname becomes the alias,
MAC addresses (colon- or dash-separated) become `02:00:00:00:00:01`, IPv4
addresses `192.0.2.1`, IPv6 addresses `2001:db8::1`, UUIDs the nil UUID, long
colon- or dash-hex strings (RSS keys, `BOOTIF=01-...`) become zeros,
`docker info` is cut to the fields the collector reads, `dmidecode -t 17` to
the `Memory Device` headers and the `Size`, `Type`, `Speed` and
`Configured Memory Speed` lines (no serial number, asset tag, part number or
locator), `/proc/cpuinfo` loses its `Serial` line, the `git` answers (which
name the checkout path) are dropped, and only the listed processes and the
recorded NICs are kept. Review the file before committing it.

The tests replay it with `SnapshotSource`, so they run on a CI runner that has
never seen dgx-spark. `tests/fixtures/dgx-spark/sut.json` is the record the
replay produces; after changing the collector, regenerate it with:

```sh
MBENCH_REGEN_FIXTURES=1 uv run pytest tests/test_sut_collect.py -k golden
```

That snapshot was captured without root, so it holds no `dmidecode` answer.
`tests/fixtures/dgx-spark/dmidecode-t17-root.txt` is the answer of a
`--record-sources` run as root on dgx-spark (2026-11-21), already sanitised:
one memory device, 128 GB of LPDDR5 at 8533 MT/s. The `dmidecode` parser is
tested on it, and on synthetic samples with an empty slot and with every
identifying field.

## dgx-spark notes

- `vllm-qwen.service` and `vllm-health-watchdog.timer` are **user** units
  (`systemctl --user`), not system units. The collector looks in both scopes
  and records which one it found (`noise.services[].scope`).
- The four ConnectX-7 ports have no cable, so their `link.speed_mbps` is a
  `not_applicable` marker; enP7s7 (r8127) reports no firmware version and does
  not support `ethtool -x`.
