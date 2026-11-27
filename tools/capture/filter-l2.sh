#!/bin/sh
# filter-l2.sh IN.pcap OUT.pcap [IMAGE] — derive the C-benign corpus from
# the anonymised capture: keep only IPv4, IPv6 and ARP frames (#54).
#
# A real capture also carries layer-2 control frames mmt-probe's reports
# never count — 802.3/LLC (spanning tree) and ethertypes such as 0x7373
# and 0x88e1 — while the harness requires the tool's packet count to equal
# the pcap's. Filtering to 'ip or ip6 or arp' drops them.
#
# tcpdump runs inside the pinned mmt-bench/tcpreplay:local image (tcpdump
# 4.99.4, libpcap 1.10.4), so the filter is the same on every host and the
# output is byte-for-byte reproducible: two runs give the same sha256. No
# host tcpdump is installed or needed.
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 IN.pcap OUT.pcap [IMAGE]" >&2
    exit 2
fi
[ -f "$1" ] || { echo "$0: $1: no such file" >&2; exit 2; }

in_dir="$(cd "$(dirname "$1")" && pwd)"
out_dir="$(cd "$(dirname "$2")" && pwd)"   # must exist; OUT itself may not
image="${3:-mmt-bench/tcpreplay:local}"

# An mbench- container, --rm, no network, like every container the harness
# starts; --user keeps the output owned by the invoking user. --pull never
# keeps the filter strictly local: a missing image fails fast instead of
# trying a registry pull; timeout caps a hung daemon. tcpdump's file
# capabilities need both caps in docker's bounding set even to read a
# file, so --cap-add names them like the capture step does.
timeout 120 docker run --rm --pull never --name "mbench-filter-l2-$$" \
    --network none \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    --user "$(id -u):$(id -g)" -w / \
    -v "$in_dir:/in:ro" \
    -v "$out_dir:/out" \
    --entrypoint tcpdump \
    "$image" \
    -r "/in/$(basename "$1")" \
    -w "/out/$(basename "$2")" \
    'ip or ip6 or arp'
