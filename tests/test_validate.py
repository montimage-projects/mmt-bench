"""``mbench validate`` on complete and incomplete sut.json records."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from sutfixtures import GOLDEN

from mbench import sut, validate
from mbench.cli import EXIT_INVALID, EXIT_OK, EXIT_USAGE, main

ROOT = Path(__file__).resolve().parent.parent
COMMITTED_SCHEMA = ROOT / "src/mbench/schemas/sut.schema.json"


def golden() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8"))
    return data


def write(tmp_path: Path, record: Any, name: str = "sut.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def test_committed_schema_is_valid_draft_2020_12() -> None:
    data = json.loads(COMMITTED_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(data)
    assert validate.schema() == data  # the packaged copy is the committed file


def test_schema_requires_every_b4_section() -> None:
    required = set(validate.schema()["required"])
    assert {"host", "os", "nics", "container_runtime", "tools", "noise", "harness"} <= required
    assert "sut_hash" in required


def test_complete_record_exits_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, golden())
    assert main(["validate", str(path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert f"{path}: valid sut record (scope host" in out
    assert "unavailable needs_root" in out and "host.memory.speed" in out


def test_quiet_does_not_list_markers(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate", "-q", str(write(tmp_path, golden()))]) == EXIT_OK
    assert "unavailable needs_root" not in capsys.readouterr().out


def drop(record: dict[str, Any], dotted: str) -> None:
    *parents, last = dotted.split(".")
    node: Any = record
    for part in parents:
        node = node[int(part)] if part.isdigit() else node[part]
    del node[last]


MISSING = [
    "host.cpu.core_types.0.governor",
    "os.kernel.release",
    "nics.2.driver",
    "container_runtime.docker.server_version",
    "noise.vllm_stopped",
    "harness.mbench_commit",
    "host.memory.swap",
]


def test_incomplete_record_names_each_missing_field(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    record = golden()
    for dotted in MISSING:
        drop(record, dotted)
    assert main(["validate", str(write(tmp_path, record))]) == EXIT_INVALID
    out = capsys.readouterr().out
    assert "INVALID" in out
    for name in [
        "host.cpu.core_types[0].governor",
        "os.kernel.release",
        "nics[2].driver",
        "container_runtime.docker.server_version",
        "noise.vllm_stopped",
        "harness.mbench_commit",
        "host.memory.swap",
    ]:
        assert f"missing field: {name}" in out


@pytest.mark.parametrize(
    "section", ["host", "os", "nics", "container_runtime", "tools", "noise", "harness"]
)
def test_each_missing_section_is_named(section: str) -> None:
    record = golden()
    del record[section]
    assert f"missing field: {section}" in validate.sut_errors(record)


def test_marker_without_reason_is_rejected() -> None:
    record = golden()
    record["host"]["memory"]["speed"] = {"unavailable": "needs_root"}
    errors = validate.sut_errors(record)
    assert "missing field: host.memory.speed.reason" in errors


def test_wrong_type_is_named() -> None:
    record = golden()
    record["host"]["cpu"]["logical_cpus"] = "twenty"
    assert any(e.startswith("host.cpu.logical_cpus:") for e in validate.sut_errors(record))


def test_tampered_record_fails_the_hash_check() -> None:
    record = golden()
    record["os"]["kernel"]["release"] = "6.18.0-1-nvidia"
    errors = validate.sut_errors(record)
    assert len(errors) == 1 and errors[0].startswith("sut_hash:")


def test_run_scope_requires_tools_run_times_pcaps_and_limits() -> None:
    record = golden()
    record["scope"] = "run"
    errors = validate.sut_errors(record)
    joined = "\n".join(errors)
    for name in ("tools", "harness.run", "harness.pcaps", "container_runtime.limits.per_run"):
        assert any(e.startswith(f"{name}:") for e in errors), joined


def test_run_scope_record_passes_when_filled() -> None:
    record = golden()
    record["scope"] = "run"
    record["tools"] = [
        {
            "name": "mmt-probe",
            "version": "1.6.0",
            "image": {"ref": "mmt-probe", "digest": "sha256:" + "a" * 64},
            "version_strings": {"mmt-dpi": "1.10.3"},
            "build_flags": {},
            "ruleset": {"id": "R-all", "sha256": "b" * 64},
            "config": {"sha256": "c" * 64, "content": "probe.conf"},
        }
    ]
    record["harness"]["run"] = {"start": "2026-11-20T22:00:00Z", "end": "2026-11-20T22:01:00Z"}
    record["harness"]["pcaps"] = [{"name": "c-small", "sha256": "d" * 64}]
    record["container_runtime"]["limits"]["per_run"] = {
        "cpu_max": "200000 100000",
        "memory_max": "8589934592",
        "cpuset_cpus": "5",
    }
    assert validate.sut_errors(record) == []


def test_record_from_collector_validates() -> None:
    from sutfixtures import replay

    assert validate.sut_errors(replay()) == []


def test_unreadable_or_unsupported_files_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["validate", str(tmp_path / "missing.json")]) == EXIT_USAGE
    assert main(["validate", str(write(tmp_path, {"a": 1}, "other.json"))]) == EXIT_USAGE
    # a yaml that is neither a manifest nor a campaign is still unsupported
    yaml_file = tmp_path / "other.yaml"
    yaml_file.write_text("foo: bar\n", encoding="utf-8")
    assert main(["validate", str(yaml_file)]) == EXIT_USAGE


def test_a_campaign_file_is_checked(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Campaign files are checked by #8 against schemas/campaign.schema.json.
    campaign = tmp_path / "smoke.yaml"
    campaign.write_text("question: x\n", encoding="utf-8")
    assert main(["validate", str(campaign)]) == EXIT_INVALID
    out = capsys.readouterr().out
    assert "INVALID" in out
    assert "missing field" in out


def test_campaign_errors_rejects_an_empty_or_descending_cpuset(tmp_path: Path) -> None:
    # The schema's pattern accepts "5-2", which parses to no cpu at all:
    # campaign_errors rejects it (review L4). "" stays valid — unpinned.
    doc: dict[str, Any] = {
        "schema_version": 1,
        "question": "q",
        "tools": ["mmt-probe"],
        "rulesets": ["rs"],
        "corpus": [{"path": "x.pcap", "sha256": "0" * 64}],
        "threads": [1],
        "cpusets": ["", "0-3"],
        "repeats": 1,
        "timeout_s": 1,
    }
    assert validate.campaign_errors(doc, manifest_path=tmp_path / "none.yaml") == []
    for cpuset in ("5-2", "0,5-2"):
        doc["cpusets"] = [cpuset]
        errors = validate.campaign_errors(doc, manifest_path=tmp_path / "none.yaml")
        assert any("cpusets[0]" in e for e in errors), cpuset


def test_a_valid_campaign_names_its_matrix(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    campaign = tmp_path / "campaigns" / "smoke.yaml"
    campaign.parent.mkdir()
    campaign.write_text(
        "\n".join(
            [
                "schema_version: 1",
                "question: does it keep up?",
                "tools: [mmt-probe]",
                "rulesets: [rs]",
                "corpus: [{path: x.pcap, sha256: '%s'}]" % ("0" * 64),
                "threads: [1, 2]",
                "cpusets: ['']",
                "repeats: 3",
                "timeout_s: 30",
            ]
        ),
        encoding="utf-8",
    )
    assert main(["validate", str(campaign)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "valid campaign" in out
    assert "2 matrix cells" in out


def test_a_yaml_manifest_is_checked(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The corpus manifest is a checked record kind since #7.
    path = tmp_path / "manifest.yaml"
    path.write_text("schema_version: 1\nentries: []\n", encoding="utf-8")
    assert main(["validate", str(path)]) == EXIT_OK
    assert "valid corpus manifest" in capsys.readouterr().out
    path.write_text("schema_version: 1\nentries: [{label: x}]\n", encoding="utf-8")
    assert main(["validate", str(path)]) == EXIT_INVALID
    assert "missing field: entries[0].path" in capsys.readouterr().out
    path.write_text("not: [closed\n", encoding="utf-8")
    assert main(["validate", str(path)]) == EXIT_INVALID
    assert "not valid YAML" in capsys.readouterr().out


def test_the_committed_corpus_manifest_validates(capsys: pytest.CaptureFixture[str]) -> None:
    manifest = ROOT / "corpus/manifest.yaml"
    assert manifest.is_file()
    assert main(["validate", str(manifest)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "valid corpus manifest" in out and "local-only" in out


# --- A ground-truth file (#26) ----------------------------------------------------


def _truth(*attacks: dict[str, Any], **top: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "pcap_sha256": "ab" * 32,
        "attacks": list(attacks),
        **top,
    }


def _attack(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "a1",
        "start": 1_700_000_000.0,
        "end": 1_700_000_010.0,
        "src": "192.0.2.20",
        "dst": "198.51.100.0/24",
        "proto": "tcp",
    }
    data.update(over)
    return data


def test_a_valid_truth_file_is_checked(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, _truth(_attack(), _attack(id="a2")), "x.truth.json")
    assert main(["validate", str(path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert f"{path}: valid ground truth (2 attacks, tolerance 1 s)" in out


def test_a_truth_file_is_recognised_without_the_suffix(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The content decides too: pcap_sha256 and attacks mark a truth file.
    path = write(tmp_path, _truth(_attack()), "truth.json")
    assert main(["validate", str(path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert f"{path}: valid ground truth (1 attack, tolerance 1 s)" in out


def test_the_truth_suffix_decides_the_kind(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # No schema_version: not a sut record, but a truth file by name, checked
    # as one rather than reported unsupported.
    path = tmp_path / "x.truth.json"
    path.write_text(json.dumps({"pcap_sha256": "ab" * 32, "attacks": []}), encoding="utf-8")
    assert main(["validate", str(path)]) == EXIT_INVALID
    assert "missing field: schema_version" in capsys.readouterr().out


def test_a_truth_schema_error_is_named(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = _truth(_attack())
    del data["pcap_sha256"]
    path = write(tmp_path, data, "x.truth.json")
    assert main(["validate", str(path)]) == EXIT_INVALID
    out = capsys.readouterr().out
    assert "INVALID" in out and "missing field: pcap_sha256" in out


def test_a_truth_semantic_error_is_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An attack that ends before it starts passes the schema, so only
    # truth.parse's own checks catch it.
    path = write(tmp_path, _truth(_attack(end=1_699_999_000.0)), "x.truth.json")
    assert main(["validate", str(path)]) == EXIT_INVALID
    out = capsys.readouterr().out
    assert "attacks[0].end: 1699999000.0 is before start" in out


def test_invalid_json_is_invalid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "sut.json"
    path.write_text("{", encoding="utf-8")
    assert main(["validate", str(path)]) == EXIT_INVALID
    assert "not valid JSON" in capsys.readouterr().out


def test_worst_status_wins_across_files(tmp_path: Path) -> None:
    good = write(tmp_path, golden(), "good.json")
    bad_record = golden()
    del bad_record["os"]
    bad = write(tmp_path, bad_record, "bad.json")
    assert main(["validate", str(good), str(bad)]) == EXIT_INVALID
    assert main(["validate", str(bad), str(tmp_path / "missing.json")]) == EXIT_USAGE


def test_unavailable_fields_listed_match_the_record() -> None:
    record = golden()
    report_fields = {p for p, _, _ in sut.unavailable_fields(record)}
    assert "tools" in report_fields
    assert copy.deepcopy(record) == record


def test_non_utf8_file_is_unreadable_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "sut.json"
    path.write_bytes(b'{"scope": "\xff\xfe"}')
    assert main(["validate", str(path)]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert f"mbench validate: {path}: unreadable: not UTF-8 text" in captured.err
    assert "Traceback" not in captured.err + captured.out


# --- A strict schema ---------------------------------------------------------------


def rehash(record: dict[str, Any]) -> dict[str, Any]:
    """``record`` with its sut_hash recomputed, so only the schema can reject it."""
    record["sut_hash"] = sut.sut_hash(record)
    return record


def put(record: dict[str, Any], dotted: str, value: Any) -> None:
    *parents, last = dotted.split(".")
    node: Any = record
    for part in parents:
        node = node[int(part)] if part.isdigit() else node[part]
    node[int(last) if last.isdigit() else last] = value


@pytest.mark.parametrize(
    ("dotted", "where"),
    [("host.serial", "host"), ("mac", "(record)"), ("nics.0.mac", "nics[0]")],
)
def test_an_unknown_field_is_rejected(dotted: str, where: str) -> None:
    record = golden()
    put(record, dotted, "02:00:00:00:00:01")
    errors = validate.sut_errors(rehash(record))
    name = dotted.rsplit(".", 1)[-1]
    assert errors == [f"{where}: Additional properties are not allowed ('{name}' was unexpected)"]


def test_an_unknown_field_inside_a_marker_is_rejected() -> None:
    record = golden()
    record["host"]["memory"]["speed"]["serial"] = "x"
    assert validate.sut_errors(rehash(record)) == [
        "host.memory.speed: Additional properties are not allowed ('serial' was unexpected)"
    ]


@pytest.mark.parametrize("scope", ["host", "run"])
@pytest.mark.parametrize(
    "per_run",
    [
        {},
        {"unavailable": "bogus"},
        {"cpuset": "5"},
        {"cpu_max": "max 100000", "memory_max": "max", "cpuset_cpus": "5", "extra": "x"},
    ],
    ids=["empty", "bogus-marker", "unknown-key", "extra-key"],
)
def test_per_run_limits_are_strict_in_both_scopes(scope: str, per_run: dict[str, Any]) -> None:
    record = golden()
    record["scope"] = scope
    record["container_runtime"]["limits"]["per_run"] = per_run
    errors = validate.sut_errors(rehash(record))
    assert any("container_runtime.limits.per_run" in e for e in errors), errors


def test_per_run_marker_is_accepted_in_host_scope_only() -> None:
    record = golden()
    marker = record["container_runtime"]["limits"]["per_run"]
    assert marker["unavailable"] == "not_applicable"
    assert validate.sut_errors(record) == []
    record["scope"] = "run"
    errors = validate.sut_errors(record)
    assert (
        "container_runtime.limits.per_run: must hold a value here, "
        "not an unavailable marker (not_applicable)"
    ) in errors


@pytest.mark.parametrize(
    "dotted",
    [
        "host.memory.hugepages.default_size_kib",
        "host.cpu.core_types.0.count",
        "nics.0.link.mtu",
        "nics.0.queues.rx",
        "noise.memory.available_kib",
        "noise.top_memory.0.rss_kib",
    ],
)
def test_negative_sizes_and_counts_are_rejected(dotted: str) -> None:
    record = golden()
    put(record, dotted, -1)
    errors = validate.sut_errors(rehash(record))
    assert any("-1 is less than the minimum of" in e for e in errors), errors


#: Fields without which two records cannot be compared: a value, or a marker
#: saying the host does not expose it, it needs root, or the tool is missing.
IDENTITY_FIELDS = [
    "os.kernel.release",
    "os.kernel.version",
    "os.distro",
    "os.cmdline",
    "host.architecture",
    "host.memory.total_kib",
    "host.cpu.core_types.0.model_name",
]


@pytest.mark.parametrize("dotted", IDENTITY_FIELDS)
@pytest.mark.parametrize("kind", ["error", "not_applicable", "redacted"])
def test_identity_fields_reject_error_and_not_applicable_markers(dotted: str, kind: str) -> None:
    record = golden()
    put(record, dotted, sut.unavailable(kind, "planted"))
    errors = validate.sut_errors(rehash(record))
    path = validate.format_path([int(p) if p.isdigit() else p for p in dotted.split(".")])
    assert errors == [f"{path}: must hold a value here, not an unavailable marker ({kind})"]


@pytest.mark.parametrize("dotted", IDENTITY_FIELDS)
def test_identity_fields_accept_a_needs_root_marker(dotted: str) -> None:
    record = golden()
    put(record, dotted, sut.unavailable("needs_root", "planted"))
    assert validate.sut_errors(rehash(record)) == []


def test_identity_values_must_not_be_empty() -> None:
    record = golden()
    record["os"]["kernel"]["release"] = ""
    record["host"]["memory"]["total_kib"] = 0
    record["host"]["cpu"]["core_types"] = []
    errors = "\n".join(validate.sut_errors(rehash(record)))
    for name in ("os.kernel.release", "host.memory.total_kib", "host.cpu.core_types"):
        assert f"{name}:" in errors


def test_nics_is_a_non_empty_list_or_a_marker() -> None:
    record = golden()
    record["nics"] = []
    assert validate.sut_errors(rehash(record)) == ["nics: [] should be non-empty"]
    record["nics"] = sut.unavailable("not_supported", "no physical network interface")
    assert validate.sut_errors(rehash(record)) == []
