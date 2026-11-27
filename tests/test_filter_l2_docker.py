"""tools/capture/filter-l2.sh (#54) — the Docker-marked integration test.

C-benign is the anonymised capture filtered to IPv4, IPv6 and ARP: the
layer-2 control frames a real capture also carries — 802.3/LLC (spanning
tree) and ethertypes such as 0x7373 and 0x88e1 — are dropped, because
mmt-probe's reports never count them while the harness requires the
tool's packet count to equal the pcap's.

The input pcap is synthetic, written by the repo's own writer
(:mod:`mbench.pcap`) — no capture is committed — and tcpdump runs only
inside the pinned ``mmt-bench/tcpreplay:local`` image (tcpdump 4.99.4,
libpcap 1.10.4), never a host tcpdump. The test is skipped when docker is
not usable or the image is absent: CI builds only the mmt-probe image.
"""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path

import pytest
from test_mmt_probe_docker import _docker_usable

from mbench import pcap

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools/capture/filter-l2.sh"
IMAGE = "mmt-bench/tcpreplay:local"


def _image_present() -> bool:
    """Whether the pinned tcpreplay image is built locally."""
    try:
        return (
            subprocess.run(
                ["docker", "image", "inspect", IMAGE], capture_output=True, timeout=20
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.docker
needs_docker = pytest.mark.skipif(not _docker_usable(), reason="docker is not usable")
needs_image = pytest.mark.skipif(
    not _image_present(),
    reason=f"{IMAGE} is not built (docker build -t {IMAGE} tools/docker/tcpreplay)",
)

SRC_MAC = b"\x02\x00\x00\x00\x00\x01"
DST_MAC = b"\x02\x00\x00\x00\x00\x02"


def _ether(payload_type: int, payload: bytes) -> bytes:
    """An Ethernet frame: under 1536 the field is an 802.3 length, else an ethertype."""
    return DST_MAC + SRC_MAC + struct.pack(">H", payload_type) + payload


#: An Ethernet/IPv4 frame.
IPV4 = _ether(
    0x0800,
    struct.pack(">BBHHHBBHII", 0x45, 0, 28, 1, 0x4000, 64, 17, 0, 0xC6120001, 0xC6130001)
    + b"PAYLOAD4",
)
#: An Ethernet/IPv6 frame.
IPV6 = _ether(
    0x86DD,
    struct.pack(">IHBB", 6 << 28, 8, 17, 64) + bytes(32) + b"PAYLOAD6",
)
#: An Ethernet/ARP request.
ARP = _ether(
    0x0806,
    struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
    + SRC_MAC
    + b"\xc0\xa8\x00\x01"
    + DST_MAC
    + b"\xc0\xa8\x00\x02",
)
_LLC_BODY = b"\x42\x42\x03" + bytes(35)  # 802.2 LLC, STP's DSAP 0x42
#: An 802.3/LLC frame (spanning tree): the length field is not an ethertype.
LLC_8023 = _ether(len(_LLC_BODY), _LLC_BODY)
#: The two other ethertypes the real capture dropped (#54).
E7373 = _ether(0x7373, bytes(20))
E88E1 = _ether(0x88E1, bytes(20))

#: The frames the filter keeps, in their pcap order; the dropped frames sit
#: between them, so the filter is proved mid-stream, not on a prefix.
KEPT = [IPV4, IPV6, ARP]
FRAMES = [IPV4, LLC_8023, IPV6, E7373, ARP, E88E1]


def _write(path: Path, frames: list[bytes]) -> None:
    with open(path, "wb") as f:
        writer = pcap.Writer(f)
        for i, frame in enumerate(frames):
            writer.write(frame, 1_767_225_600, i)


def _frames(path: Path) -> list[bytes]:
    """Every frame of a classic pcap file, in either byte order."""
    data = path.read_bytes()
    assert data[:4] in (pcap.MAGICS[0], pcap.MAGICS[1]), f"{path}: not a classic pcap"
    endian = "<" if data[:4] == pcap.MAGICS[0] else ">"
    frames = []
    offset = 24
    while offset < len(data):
        incl_len = struct.unpack_from(endian + "IIII", data, offset)[2]
        offset += 16
        frames.append(data[offset : offset + incl_len])
        offset += incl_len
    return frames


@needs_image
@needs_docker
def test_filter_keeps_ip_ipv6_arp_and_drops_l2_control_frames(tmp_path: Path) -> None:
    in_pcap = tmp_path / "c-benign-all.pcap"
    out_pcap = tmp_path / "c-benign.pcap"
    again_pcap = tmp_path / "c-benign-again.pcap"
    _write(in_pcap, FRAMES)
    assert pcap.stats(in_pcap).packets == len(FRAMES)

    for out in (out_pcap, again_pcap):
        proc = subprocess.run(
            [str(SCRIPT), str(in_pcap), str(out)],
            capture_output=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")

    # IPv4, IPv6 and ARP survive byte-for-byte and in order; the 802.3/LLC
    # and unknown-ethertype frames are gone.
    assert _frames(out_pcap) == KEPT
    assert pcap.stats(out_pcap).packets == len(KEPT)

    # Byte-for-byte reproducible, as the runbook states: a second run of
    # the same filter gives the same sha256.
    assert pcap.sha256_file(again_pcap) == pcap.sha256_file(out_pcap)
