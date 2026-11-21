"""Read and write packet captures in pure Python, with no packet tool (#7).

``mbench corpus`` needs two things from a capture: to write the synthetic
C-small and C-large sets, and to compute a manifest entry's fields from the
file itself (sha256, size, packet count, average packet size). Both are done
here with :mod:`struct`, so nothing is installed on the host.

Writing produces the classic libpcap format (microsecond timestamps, Ethernet
link type). Reading accepts classic pcap in either byte order, with microsecond
or nanosecond timestamps, and pcapng.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

#: Link type of an Ethernet capture (LINKTYPE_ETHERNET).
LINKTYPE_ETHERNET = 1
#: Snapshot length written in the file header: large enough for any frame.
SNAPLEN = 65535

_PCAP_MAGIC_US = 0xA1B2C3D4
_PCAP_MAGIC_NS = 0xA1B23C4D
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_BYTE_ORDER = 0x1A2B3C4D

#: The first four bytes of every capture format :func:`stats` reads, in file
#: order. ``tools/ci/check_no_captures.py`` looks for the same signatures.
MAGICS = (
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microseconds
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microseconds
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanoseconds
    b"\x0a\x0d\x0d\x0a",  # pcapng section header block
)

_CHUNK = 1 << 20


class CaptureError(ValueError):
    """The file is not a capture this module reads, or it is truncated."""


@dataclass(frozen=True)
class Stats:
    """What a manifest entry records about a capture, computed from its bytes."""

    format: str
    sha256: str
    size_bytes: int
    packets: int
    #: The sum of every packet's original (wire) length.
    wire_bytes: int

    @property
    def avg_packet_bytes(self) -> float:
        """The average wire length of a packet, rounded to 2 decimals."""
        return round(self.wire_bytes / self.packets, 2) if self.packets else 0.0


class Writer:
    """Write a classic libpcap file, one frame at a time."""

    def __init__(self, out: BinaryIO, linktype: int = LINKTYPE_ETHERNET) -> None:
        self._out = out
        out.write(struct.pack("<IHHiIII", _PCAP_MAGIC_US, 2, 4, 0, 0, SNAPLEN, linktype))

    def write(self, frame: bytes, ts_sec: int, ts_usec: int) -> None:
        self._out.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
        self._out.write(frame)


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exact(f: BinaryIO, n: int, what: str) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise CaptureError(f"truncated {what}: {len(data)} of {n} bytes")
    return data


def _pcap_lengths(f: BinaryIO, header: bytes) -> Iterator[int]:
    """The original length of each packet of a classic pcap file."""
    magic_le = struct.unpack("<I", header[:4])[0]
    endian = "<" if magic_le in (_PCAP_MAGIC_US, _PCAP_MAGIC_NS) else ">"
    _read_exact(f, 20, "pcap file header")
    record = struct.Struct(endian + "IIII")
    while True:
        raw = f.read(record.size)
        if not raw:
            return
        if len(raw) != record.size:
            raise CaptureError(f"truncated pcap record header: {len(raw)} of 16 bytes")
        _, _, incl_len, orig_len = record.unpack(raw)
        f.seek(incl_len, 1)
        yield orig_len


def _pcapng_lengths(f: BinaryIO) -> Iterator[int]:
    """The original length of each packet of a pcapng file."""
    endian = "<"
    first = True
    while True:
        head = f.read(8)
        if not head:
            return
        if len(head) != 8:
            raise CaptureError(f"truncated pcapng block header: {len(head)} of 8 bytes")
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            bom = _read_exact(f, 4, "pcapng section header")
            if struct.unpack("<I", bom)[0] == _PCAPNG_BYTE_ORDER:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == _PCAPNG_BYTE_ORDER:
                endian = ">"
            else:
                raise CaptureError("pcapng section header has no valid byte-order magic")
            length = struct.unpack(endian + "I", head[4:])[0]
            body_left = length - 12
        elif first:
            raise CaptureError("pcapng file does not start with a section header block")
        else:
            block_type, length = struct.unpack(endian + "II", head)
            body_left = length - 8
            if block_type in (6, 2):  # enhanced packet block, obsolete packet block
                body = _read_exact(f, 20, "pcapng packet block")
                body_left -= 20
                yield struct.unpack(endian + "I", body[16:20])[0]
            elif block_type == 3:  # simple packet block
                body = _read_exact(f, 4, "pcapng simple packet block")
                body_left -= 4
                yield struct.unpack(endian + "I", body)[0]
        first = False
        if length < 12 or length % 4 or body_left < 0:
            raise CaptureError(f"pcapng block has an invalid length ({length})")
        f.seek(body_left, 1)


def stats(path: str | Path) -> Stats:
    """Every manifest field that is computed from the capture's bytes.

    Raises :class:`OSError` and :class:`CaptureError`.
    """
    p = Path(path)
    size = p.stat().st_size
    with open(p, "rb") as f:
        header = f.read(4)
        if header not in MAGICS:
            raise CaptureError(f"{p}: not a pcap or pcapng file (magic {header.hex() or 'none'})")
        fmt = "pcapng" if header == MAGICS[-1] else "pcap"
        f.seek(0)
        lengths = _pcapng_lengths(f) if fmt == "pcapng" else _pcap_lengths(f, f.read(4))
        packets = wire = 0
        try:
            for length in lengths:
                packets += 1
                wire += length
        except CaptureError as exc:
            raise CaptureError(f"{p}: {exc}") from None
        if f.tell() > size:
            raise CaptureError(f"{p}: truncated: the last packet runs past the end of the file")
    return Stats(fmt, sha256_file(p), size, packets, wire)
