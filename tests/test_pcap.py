"""``mbench.pcap``: pure-Python capture writer and reader (#7)."""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from mbench import pcap


def write_pcap(path: Path, frames: list[bytes]) -> None:
    with open(path, "wb") as f:
        w = pcap.Writer(f)
        for i, frame in enumerate(frames):
            w.write(frame, 1_767_225_600 + i // 1_000_000, i % 1_000_000)


def test_writer_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "x.pcap"
    frames = [b"\x00" * 60, bytes(range(256)) * 5 + b"\xab" * 20, b"z"]
    write_pcap(path, frames)
    st = pcap.stats(path)
    assert st.format == "pcap"
    assert st.size_bytes == path.stat().st_size == 24 + 3 * 16 + sum(map(len, frames))
    assert st.packets == 3
    assert st.wire_bytes == sum(map(len, frames))
    assert st.sha256 == pcap.sha256_file(path)


def test_stats_of_an_empty_capture(tmp_path: Path) -> None:
    path = tmp_path / "empty.pcap"
    write_pcap(path, [])
    st = pcap.stats(path)
    assert (st.packets, st.wire_bytes, st.avg_packet_bytes) == (0, 0, 0.0)


def test_avg_packet_bytes_rounds_to_two_decimals() -> None:
    st = pcap.Stats("pcap", "0" * 64, 100, 3, 100)
    assert st.avg_packet_bytes == 33.33


def test_big_endian_and_nanosecond_pcaps(tmp_path: Path) -> None:
    for magic, endian, name in (
        (0xA1B2C3D4, ">", "be.pcap"),
        (0xA1B23C4D, "<", "ns.pcap"),
    ):
        path = tmp_path / name
        with open(path, "wb") as f:
            f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
            f.write(struct.pack(endian + "IIII", 1, 2, 40, 40) + b"f" * 40)
            f.write(struct.pack(endian + "IIII", 1, 3, 100, 100) + b"g" * 100)
        st = pcap.stats(path)
        assert (st.format, st.packets, st.wire_bytes) == ("pcap", 2, 140)


def pcapng(packets: list[tuple[int, int]], endian: str = "<") -> bytes:
    """A minimal pcapng: SHB + IDB + one enhanced packet block per packet.

    ``packets`` is (captured length, wire length) per packet, so a truncated
    capture keeps its wire length in the record.
    """
    shb_body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = b"\x0a\x0d\x0d\x0a" + struct.pack(endian + "I", 12 + len(shb_body))
    out += shb_body + struct.pack(endian + "I", 12 + len(shb_body))
    idb_body = struct.pack(endian + "HHI", 1, 0, 65535)
    out += struct.pack(endian + "II", 1, 12 + len(idb_body))
    out += idb_body + struct.pack(endian + "I", 12 + len(idb_body))
    for caplen, wirelen in packets:
        pad = (4 - caplen % 4) % 4
        body = struct.pack(endian + "IIIII", 0, 0, 0, caplen, wirelen) + b"p" * caplen + b"\0" * pad
        out += struct.pack(endian + "II", 6, 12 + len(body))
        out += body + struct.pack(endian + "I", 12 + len(body))
    return out


def test_pcapng_reads_wire_lengths(tmp_path: Path) -> None:
    path = tmp_path / "x.pcapng"
    path.write_bytes(pcapng([(60, 60), (60, 1518), (100, 100)]))
    st = pcap.stats(path)
    assert st.format == "pcapng"
    assert st.packets == 3 and st.wire_bytes == 60 + 1518 + 100
    assert st.avg_packet_bytes == round((60 + 1518 + 100) / 3, 2)


def test_pcapng_big_endian_and_second_section(tmp_path: Path) -> None:
    path = tmp_path / "x.pcapng"
    path.write_bytes(pcapng([(50, 50)], endian=">") + pcapng([(70, 70)], endian="<"))
    st = pcap.stats(path)
    assert st.packets == 2 and st.wire_bytes == 120


@pytest.mark.parametrize(
    ("data", "match"),
    [
        (b"", "not a pcap or pcapng"),
        (b"\x01\x02\x03\x04" + b"0" * 100, "not a pcap or pcapng"),
        (pcap.MAGICS[0], "truncated pcap file header"),
        (pcap.MAGICS[0] + b"0" * 20 + b"0" * 8, "truncated pcap record header"),
        (pcap.MAGICS[0] + b"0" * 20 + struct.pack("<IIII", 0, 0, 10, 10) + b"abc", "truncated"),
        (pcap.MAGICS[-1] + struct.pack("<I", 28), "truncated pcapng section header"),
        (pcap.MAGICS[-1] + struct.pack("<I", 28) + b"0" * 4, "byte-order magic"),
        (pcapng([]) + b"\x01\x02", "truncated pcapng block header"),
    ],
    ids=[
        "empty",
        "unknown-magic",
        "pcap-short-header",
        "pcap-short-record",
        "pcap-past-end",
        "pcapng-short-shb",
        "pcapng-bad-bom",
        "pcapng-short-block",
    ],
)
def test_stats_rejects_a_file_it_cannot_read(tmp_path: Path, data: bytes, match: str) -> None:
    path = tmp_path / "bad.pcap"
    path.write_bytes(data)
    with pytest.raises(pcap.CaptureError, match=match):
        pcap.stats(path)


def test_writer_bytes_are_the_little_endian_us_format() -> None:
    out = io.BytesIO()
    pcap.Writer(out)
    assert out.getvalue()[:4] == pcap.MAGICS[0]
