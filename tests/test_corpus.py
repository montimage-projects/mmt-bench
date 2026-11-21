"""``mbench corpus``: the synthetic sets, the manifest and the sha256 check (#7)."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from mbench import corpus, pcap, validate
from mbench.cli import EXIT_INVALID, EXIT_OK, EXIT_USAGE, main


def frames(path: Path) -> Iterator[tuple[bytes, int]]:
    """Read a little-endian classic pcap without help from ``mbench.pcap``."""
    data = path.read_bytes()
    assert data[:4] == b"\xd4\xc3\xb2\xa1"
    pos = 24
    while pos < len(data):
        _, _, incl, orig = struct.unpack("<IIII", data[pos : pos + 16])
        pos += 16
        yield data[pos : pos + incl], orig
        pos += incl
    assert pos == len(data)


def _sum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    return sum(struct.unpack(f">{len(data) // 2}H", data))


def _fold(total: int) -> int:
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def entry(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "label": "x",
        "path": "data/x.pcap",
        "sha256": "0" * 64,
        "size_bytes": 100,
        "packets": 1,
        "avg_packet_bytes": 60.0,
        "source": "a capture",
        "licence": "CC0-1.0",
        "ground_truth": None,
        "local_only": False,
    }
    base.update(over)
    return base


def manifest(*entries: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": corpus.SCHEMA_VERSION, "entries": list(entries)}


# --- the generator ------------------------------------------------------------


@pytest.mark.parametrize("set_name", ["c-small", "c-large"])
def test_every_frame_is_the_set_size(set_name: str, tmp_path: Path) -> None:
    spec = corpus.SETS[set_name]
    out = tmp_path / "x.pcap"
    corpus.generate(spec, 0, 300, 4, out)
    sizes = {(len(frame), orig) for frame, orig in frames(out)}
    assert sizes == {(spec.frame_bytes, spec.frame_bytes)}


def test_same_seed_same_bytes(tmp_path: Path) -> None:
    spec = corpus.SETS["c-small"]
    a, b, c, d = (tmp_path / n for n in "abcd")
    corpus.generate(spec, 42, 500, 8, a)
    corpus.generate(spec, 42, 500, 8, b)
    corpus.generate(spec, 43, 500, 8, c)
    corpus.generate(spec, 42, 500, 16, d)
    assert a.read_bytes() == b.read_bytes()
    for other in (c, d):
        assert a.read_bytes() != other.read_bytes()


def test_frames_have_valid_ip_and_udp_checksums(tmp_path: Path) -> None:
    out = tmp_path / "x.pcap"
    corpus.generate(corpus.SETS["c-small"], 1, 50, 8, out)
    for frame, _ in frames(out):
        ip = frame[14:]
        assert ip[0] == 0x45 and ip[9] == 17
        assert _fold(_sum16(ip[:20])) == 0xFFFF, "bad IPv4 header checksum"
        udp_len = struct.unpack(">H", ip[24:26])[0]
        pseudo = ip[12:20] + struct.pack(">BBH", 0, 17, udp_len)
        assert _fold(_sum16(pseudo) + _sum16(ip[20 : 20 + udp_len])) == 0xFFFF


def test_flows_are_distinct_five_tuples(tmp_path: Path) -> None:
    out = tmp_path / "x.pcap"
    corpus.generate(corpus.SETS["c-large"], 3, 24, 6, out)
    tuples = set()
    for frame, _ in frames(out):
        ip = frame[14:]
        tuples.add((ip[12:16], ip[16:20], struct.unpack(">H", ip[20:22])[0]))
    assert len(tuples) == 6


def test_payloads_carry_the_sequence_number(tmp_path: Path) -> None:
    out = tmp_path / "x.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 20, 2, out)
    for i, (frame, _) in enumerate(frames(out)):
        assert struct.unpack(">Q", frame[14 + 20 + 8 : 14 + 20 + 16])[0] == i


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"seed": -1}, "seed"),
        ({"packets": 0}, "packet count"),
        ({"flows": 0}, "flow count"),
        ({"packets": 5, "flows": 6}, "flow count"),
    ],
)
def test_generate_rejects_bad_parameters(
    kwargs: dict[str, int], match: str, tmp_path: Path
) -> None:
    spec = corpus.SETS["c-small"]
    args = {"seed": 0, "packets": 10, "flows": 2} | kwargs
    with pytest.raises(ValueError, match=match):
        corpus.generate(spec, args["seed"], args["packets"], args["flows"], tmp_path / "x.pcap")


def test_flow_count_is_bounded_by_the_memory_budget() -> None:
    spec = corpus.SETS["c-large"]
    assert corpus.max_flows(spec, 1 << 24) == corpus.FLOW_BUDGET_BYTES // spec.frame_bytes


# --- the manifest -------------------------------------------------------------

REQUIRED = [
    "label",
    "path",
    "sha256",
    "size_bytes",
    "packets",
    "avg_packet_bytes",
    "source",
    "licence",
    "ground_truth",
    "local_only",
]


@pytest.mark.parametrize("missing", REQUIRED)
def test_a_missing_entry_field_is_named(missing: str) -> None:
    e = entry()
    del e[missing]
    errors = validate.manifest_errors(manifest(e))
    assert errors == [f"missing field: entries[0].{missing}"]


@pytest.mark.parametrize(
    ("over", "part"),
    [
        ({"label": "Bad Label"}, "entries[0].label"),
        ({"label": "x" * 65}, "entries[0].label"),
        ({"path": "elsewhere/x.pcap"}, "entries[0].path"),
        ({"path": "data/../x.pcap"}, "entries[0].path"),
        ({"path": "data//x.pcap"}, "entries[0].path"),
        ({"sha256": "0" * 63}, "entries[0].sha256"),
        ({"sha256": "g" * 64}, "entries[0].sha256"),
        ({"size_bytes": 10}, "entries[0].size_bytes"),
        ({"packets": -1}, "entries[0].packets"),
        ({"source": ""}, "entries[0].source"),
        ({"licence": ""}, "entries[0].licence"),
        ({"ground_truth": "../truth.txt"}, "entries[0].ground_truth"),
        ({"local_only": "yes"}, "entries[0].local_only"),
        ({"bogus": 1}, "bogus"),
    ],
)
def test_an_invalid_entry_field_is_named(over: dict[str, Any], part: str) -> None:
    errors = validate.manifest_errors(manifest(entry(**over)))
    assert errors and all(part in e for e in errors), errors


def test_labels_and_paths_are_unique() -> None:
    errors = validate.manifest_errors(
        manifest(entry(), entry(path="data/y.pcap"), entry(label="y"))
    )
    joined = "\n".join(errors)
    assert "entries[1].label: duplicate 'x'" in joined
    assert "entries[2].path: duplicate 'data/x.pcap'" in joined


def test_a_generator_entry_must_match_its_own_fields() -> None:
    gen = {"set": "c-small", "version": 1, "seed": 0, "packets": 2, "flows": 1, "frame_bytes": 64}
    errors = validate.manifest_errors(
        manifest(entry(generator=gen, packets=3, avg_packet_bytes=64.0))
    )
    assert errors == ["entries[0].packets: 3 does not match its generator (2)"]
    errors = validate.manifest_errors(
        manifest(entry(generator=gen, packets=2, avg_packet_bytes=128.0))
    )
    assert errors == ["entries[0].avg_packet_bytes: 128.0 does not match its generator (64)"]


def test_an_empty_manifest_is_valid() -> None:
    assert validate.manifest_errors(manifest()) == []
    assert validate.manifest_errors({"schema_version": 1, "entries": []}) == []


def test_the_committed_manifest_is_valid(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    assert main(["validate", str(root / "corpus/manifest.yaml")]) == EXIT_OK


def test_load_missing_is_empty_and_load_invalid_fails(tmp_path: Path) -> None:
    assert corpus.load(tmp_path / "none.yaml") == {"schema_version": 1, "entries": []}
    path = tmp_path / "manifest.yaml"
    path.write_text("schema_version: 2\nentries: []\n", encoding="utf-8")
    with pytest.raises(corpus.ManifestError) as exc:
        corpus.load(path)
    assert exc.value.problems
    path.write_text("not: [closed\n", encoding="utf-8")
    with pytest.raises(corpus.ManifestError, match="not valid YAML"):
        corpus.load(path)


def test_upsert_adds_replaces_and_keeps() -> None:
    m = manifest()
    assert corpus.upsert(m, entry()) == "added"
    assert corpus.upsert(m, entry()) == "unchanged"
    assert corpus.upsert(m, entry(source="another")) == "replaced"
    assert corpus.upsert(m, entry(label="y", path="data/y.pcap")) == "added"
    assert [e["label"] for e in m["entries"]] == ["x", "y"]


# --- entries from files ---------------------------------------------------------


def test_entry_from_file_computes_every_field(tmp_path: Path) -> None:
    mpath = tmp_path / "manifest.yaml"
    out = tmp_path / "data" / "sub" / "x.pcap"
    corpus.generate(corpus.SETS["c-small"], 5, 40, 3, out)
    e = corpus.entry_from_file(
        mpath, out, label="x", source="s", licence="l", ground_truth=None, local_only=False
    )
    st = pcap.stats(out)
    assert e["path"] == "data/sub/x.pcap"
    assert e["sha256"] == st.sha256 == pcap.sha256_file(out)
    assert e["size_bytes"] == st.size_bytes == out.stat().st_size
    assert e["packets"] == st.packets == 40
    assert e["avg_packet_bytes"] == 64.0


def test_entry_from_file_refuses_a_path_outside_data(tmp_path: Path) -> None:
    out = tmp_path / "elsewhere" / "x.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 5, 1, out)
    with pytest.raises(ValueError, match="under"):
        corpus.entry_from_file(
            tmp_path / "manifest.yaml",
            out,
            label="x",
            source="s",
            licence="l",
            ground_truth=None,
            local_only=False,
        )


def test_entry_from_file_refuses_a_bad_label(tmp_path: Path) -> None:
    out = tmp_path / "data" / "x.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 5, 1, out)
    with pytest.raises(ValueError, match="label"):
        corpus.entry_from_file(
            tmp_path / "manifest.yaml",
            out,
            label="Bad Label",
            source="s",
            licence="l",
            ground_truth=None,
            local_only=False,
        )


# --- gen through the manifest -----------------------------------------------------


def test_gen_entry_adds_then_is_unchanged_then_replaced(tmp_path: Path) -> None:
    mpath = tmp_path / "manifest.yaml"
    spec = corpus.SETS["c-small"]
    m = corpus.load(mpath)
    e, outcome = corpus.gen_entry(mpath, spec, 0, 60, 4, "c-small", m)
    assert outcome == "generated" and e["generator"]["seed"] == 0
    m = corpus.load(mpath)
    e2, outcome = corpus.gen_entry(mpath, spec, 0, 60, 4, "c-small", m)
    assert outcome == "unchanged" and e2 == e
    # The manifest on disk was not rewritten.
    assert corpus.load(mpath)["entries"] == [e]
    m = corpus.load(mpath)
    e3, outcome = corpus.gen_entry(mpath, spec, 1, 60, 4, "c-small", m)
    assert outcome == "generated" and e3["sha256"] != e["sha256"]
    assert corpus.load(mpath)["entries"] == [e3]


def test_gen_repairs_a_corrupted_file_it_owns(tmp_path: Path) -> None:
    mpath = tmp_path / "manifest.yaml"
    spec = corpus.SETS["c-small"]
    m = corpus.load(mpath)
    e, _ = corpus.gen_entry(mpath, spec, 0, 20, 4, "c-small", m)
    out = tmp_path / "data" / "c-small.pcap"
    out.write_bytes(b"garbage-not-a-pcap")
    m = corpus.load(mpath)
    e2, outcome = corpus.gen_entry(mpath, spec, 0, 20, 4, "c-small", m)
    assert outcome == "generated" and e2 == e
    assert corpus.check_entry(mpath, e).status == "ok"


def test_gen_entry_refuses_a_label_it_does_not_own(tmp_path: Path) -> None:
    mpath = tmp_path / "manifest.yaml"
    m = manifest(entry())
    with pytest.raises(ValueError, match="not generated"):
        corpus.gen_entry(mpath, corpus.SETS["c-small"], 0, 5, 1, "x", m)


def test_gen_writes_the_entry_from_the_file(tmp_path: Path) -> None:
    mpath = tmp_path / "manifest.yaml"
    spec = corpus.SETS["c-large"]
    m = corpus.load(mpath)
    e, _ = corpus.gen_entry(mpath, spec, 2, 25, 4, "c-large", m)
    st = pcap.stats(tmp_path / "data" / "c-large.pcap")
    assert e["sha256"] == st.sha256 and e["packets"] == 25 and e["avg_packet_bytes"] == 1500.0
    assert validate.manifest_errors(corpus.load(mpath)) == []


# --- result_ref: what results may show ------------------------------------------


def test_result_ref_shows_a_local_only_entry_only_by_label_and_sha256() -> None:
    ref = corpus.result_ref(entry(local_only=True))
    assert ref == {"label": "x", "sha256": "0" * 64, "local_only": True}
    # Missing local_only fails closed: hidden too.
    e = entry()
    del e["local_only"]
    assert corpus.result_ref(e) == {"label": "x", "sha256": "0" * 64, "local_only": True}


def test_result_ref_shows_a_public_entry_without_its_path() -> None:
    ref = corpus.result_ref(entry(ground_truth="truth/x.json"))
    assert ref == {
        "label": "x",
        "sha256": "0" * 64,
        "size_bytes": 100,
        "packets": 1,
        "avg_packet_bytes": 60.0,
        "source": "a capture",
        "licence": "CC0-1.0",
        "ground_truth": "truth/x.json",
        "local_only": False,
    }
    assert "path" not in ref and "generator" not in ref


# --- the sha256 check -------------------------------------------------------------


def test_check_entry_ok_missing_mismatch(tmp_path: Path) -> None:
    mpath = tmp_path / "manifest.yaml"
    out = tmp_path / "data" / "x.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 30, 2, out)
    e = corpus.entry_from_file(
        mpath, out, label="x", source="s", licence="l", ground_truth=None, local_only=False
    )
    assert corpus.check_entry(mpath, e).status == "ok"
    assert corpus.check_entry(mpath, entry(label="gone", path="data/gone.pcap")) == corpus.Check(
        "gone", "missing", ("the file is not present",)
    )
    data = bytearray(out.read_bytes())
    data[-1] ^= 0xFF  # flip one payload byte: still a valid pcap, wrong sha256
    out.write_bytes(bytes(data))
    bad = corpus.check_entry(mpath, e)
    assert bad.status == "mismatch" and "sha256" in bad.problems[0]


def test_check_entry_reports_a_hand_edited_field(tmp_path: Path) -> None:
    mpath = tmp_path / "manifest.yaml"
    out = tmp_path / "data" / "x.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 30, 2, out)
    e = corpus.entry_from_file(
        mpath, out, label="x", source="s", licence="l", ground_truth=None, local_only=False
    ) | {"packets": 31}
    bad = corpus.check_entry(mpath, e)
    assert bad.status == "mismatch" and "packets is 30" in bad.problems[0]


def test_check_entry_on_a_local_only_file_names_only_its_sha256(tmp_path: Path) -> None:
    mpath = tmp_path / "manifest.yaml"
    out = tmp_path / "data" / "x.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 30, 2, out)
    e = corpus.entry_from_file(
        mpath, out, label="x", source="s", licence="l", ground_truth=None, local_only=True
    )
    assert corpus.check_entry(mpath, e).status == "ok"
    bad = corpus.check_entry(mpath, e | {"sha256": "f" * 64})
    assert bad.status == "mismatch"
    assert all("sha256" in p for p in bad.problems)
    out.write_bytes(b"not even a capture")
    assert corpus.check_entry(mpath, e | {"sha256": pcap.sha256_file(out)}).status == "ok"


# --- the CLI -----------------------------------------------------------------------


def test_corpus_without_an_action_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["corpus"]) == EXIT_USAGE
    assert "usage:" in capsys.readouterr().err


def test_cli_gen_validate_check_cycle(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    m = tmp_path / "manifest.yaml"
    argv = [
        "corpus",
        "gen",
        "c-small",
        "--packets",
        "300",
        "--flows",
        "8",
        "--seed",
        "7",
        "--manifest",
        str(m),
    ]
    assert main(argv) == EXIT_OK
    out = capsys.readouterr().out
    assert "generated" in out and "sha256" in out
    assert main(argv) == EXIT_OK
    assert "unchanged" in capsys.readouterr().out
    assert main(["validate", str(m)]) == EXIT_OK
    assert "valid corpus manifest" in capsys.readouterr().out
    assert main(["corpus", "check", "--manifest", str(m)]) == EXIT_OK
    assert "c-small: ok" in capsys.readouterr().out


def test_cli_check_exits_non_zero_on_a_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    m = tmp_path / "manifest.yaml"
    assert main(["corpus", "gen", "c-small", "--packets", "30", "--manifest", str(m)]) == EXIT_OK
    capsys.readouterr()
    data = tmp_path / "data" / "c-small.pcap"
    data.write_bytes(data.read_bytes() + b"tampered")
    assert main(["corpus", "check", "--manifest", str(m)]) == EXIT_INVALID
    out = capsys.readouterr().out
    assert "c-small: MISMATCH" in out or "c-small: UNREADABLE" in out
    assert "1 failed" in out


def test_cli_check_reports_missing_without_failing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    m = tmp_path / "manifest.yaml"
    corpus.save(m, manifest(entry(), entry(label="y", path="data/y.pcap")))
    assert main(["corpus", "check", "--manifest", str(m)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "x: MISSING" in out and "2 missing" in out


def test_cli_check_filters_labels(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    m = tmp_path / "manifest.yaml"
    corpus.save(m, manifest(entry(), entry(label="y", path="data/y.pcap")))
    assert main(["corpus", "check", "y", "--manifest", str(m)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "y: MISSING" in out and "x:" not in out
    assert main(["corpus", "check", "unknown", "--manifest", str(m)]) == EXIT_USAGE
    assert "no manifest entry" in capsys.readouterr().err


def test_cli_gen_rejects_bad_parameters(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    m = tmp_path / "manifest.yaml"
    assert main(["corpus", "gen", "c-small", "--packets", "0", "--manifest", str(m)]) == (
        EXIT_USAGE
    )
    assert "packet count" in capsys.readouterr().err
    assert main(["corpus", "gen", "c-small", "--label", "Bad", "--manifest", str(m)]) == (
        EXIT_USAGE
    )
    assert "label" in capsys.readouterr().err


def test_cli_gen_does_not_clobber_a_manual_entry(tmp_path: Path) -> None:
    m = tmp_path / "manifest.yaml"
    corpus.save(m, manifest(entry(label="c-small")))
    assert main(["corpus", "gen", "c-small", "--packets", "5", "--manifest", str(m)]) == (
        EXIT_USAGE
    )


def test_cli_add_registers_a_local_capture(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    m = tmp_path / "manifest.yaml"
    out = tmp_path / "data" / "dgx.pcap"
    corpus.generate(corpus.SETS["c-small"], 9, 25, 4, out)
    assert (
        main(
            [
                "corpus",
                "add",
                str(out),
                "--source",
                "dgx-spark capture, anonymised",
                "--licence",
                "proprietary-local",
                "--local-only",
                "--manifest",
                str(m),
            ]
        )
        == EXIT_OK
    )
    assert "local-only" in capsys.readouterr().out
    entries = corpus.load(m)["entries"]
    assert entries[0]["local_only"] is True and entries[0]["path"] == "data/dgx.pcap"
    # A second add of the same file reports unchanged and does not rewrite.
    assert (
        main(
            [
                "corpus",
                "add",
                str(out),
                "--source",
                "dgx-spark capture, anonymised",
                "--licence",
                "proprietary-local",
                "--local-only",
                "--manifest",
                str(m),
            ]
        )
        == EXIT_OK
    )
    assert "unchanged" in capsys.readouterr().out


def test_cli_add_refuses_a_capture_outside_data(tmp_path: Path) -> None:
    out = tmp_path / "x.pcap"
    corpus.generate(corpus.SETS["c-small"], 0, 5, 1, out)
    assert (
        main(
            [
                "corpus",
                "add",
                str(out),
                "--source",
                "s",
                "--licence",
                "l",
                "--manifest",
                str(tmp_path / "manifest.yaml"),
            ]
        )
        == EXIT_USAGE
    )


def test_cli_manifest_must_be_valid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    m = tmp_path / "manifest.yaml"
    m.write_text(yaml.safe_dump({"schema_version": 1, "entries": [{"label": "x"}]}))
    for argv in (
        ["corpus", "gen", "c-small", "--packets", "5", "--manifest", str(m)],
        ["corpus", "check", "--manifest", str(m)],
    ):
        assert main(argv) == EXIT_INVALID
        assert "missing field" in capsys.readouterr().err
