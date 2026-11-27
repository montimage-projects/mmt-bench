#!/bin/sh
# c-benign — the no-sudo runbook for the anonymised 1-h capture (#10, #50)
# and the benchmark corpus derived from it (#54).
#
# This script ONLY PRINTS the commands. Nothing here runs them, but nothing
# in them needs root either: the capture runs tcpdump inside the pinned
# mmt-bench/tcpreplay:local image on the host network, with only the
# capabilities a capture needs and as the invoking user. Paste each step
# into a shell at the repo root.
#
# What it produces, under local/ and corpus/data/ (both git-ignored, never
# committed):
#   local/capture/c-benign-raw.pcap   the raw 1-h capture — stays local
#                                     only (see step 5)
#   corpus/data/c-benign-all.pcap     the anonymised capture, registered as
#                                     corpus entry `c-benign-all` (local_only)
#   corpus/data/c-benign.pcap         the benchmark corpus: c-benign-all
#                                     filtered to IPv4, IPv6 and ARP (#54),
#                                     registered as `c-benign` (local_only)
#
# Anonymisation is `tcprewrite` in the same pinned image (built by
# tools/docker/tcpreplay/Dockerfile; `docker inspect` prints the digest of
# the local build):
#   --seed        deterministic IP rewriting — tcprewrite --seed, not
#                 prefix-preserving (not crypto-PAn): the same address
#                 always maps to the same address, so flows and
#                 client/server roles survive, but address prefixes do
#                 not. The seed is the secret — keep it local, never in
#                 git, the manifest, results/ or REPORT.md
#   --enet-smac/--enet-dmac   MAC addresses replaced
#   --fixcsum     IP/TCP/UDP checksums recomputed
#
# What tcprewrite does NOT touch (it rewrites headers only):
#   - ARP payload: the sender/target MAC and IP addresses inside the ARP
#     body survive at their payload offsets.
#   - DHCP payload: chaddr (client MAC), yiaddr and giaddr survive inside
#     the BOOTP body.
#   - every L7 payload: DNS names, HTTP hosts and TLS SNI stay readable.
# tcprewrite cannot rewrite or strip those fields, and truncating with a
# snaplen would hide them but breaks the payload-reading rules (the 94 of
# R-all need payloads to fire). So the recommendation stands: keep full
# packets, keep the capture local_only — it is never published; only its
# label and sha256 appear in results. If the capture must ever leave this
# host, re-evaluate with a payload-aware anonymiser first.
#
# Why the filter (step 4): a real capture also carries layer-2 control
# frames that mmt-probe's reports do not count — in this capture 3,600
# frames of ethertype 0x7373, 3,599 802.3/LLC frames (spanning tree) and 1
# of 0x88e1, 7,200 of 508,584 in all — while the harness requires the
# tool's packet count to equal the pcap's, so every pass on the unfiltered
# file is invalid. The corpus keeps IPv4, IPv6 and ARP only, filtered by
# tcpdump 4.99.4 / libpcap 1.10.4 in the same pinned image.
set -eu

# The interface to listen on: the route to the outside, not a veth.
IFACE=$(ip -o -4 route show to default 2>/dev/null | awk 'NR==1 {print $5}')
: "${IFACE:=CHANGE-ME}"   # no default route: pick the interface yourself

cat <<EOF
# 1. Build the capture + anonymiser + filter image (user, once):
docker build -t mmt-bench/tcpreplay:local tools/docker/tcpreplay
docker inspect -f '{{.Id}}' mmt-bench/tcpreplay:local   # record this digest

# 2. Capture one hour of the host's real traffic (user, no sudo). tcpdump
#    runs in the pinned image on the host network: NET_RAW opens the
#    packet socket, NET_ADMIN sets promiscuous mode; --user makes the
#    pcap owned by you, not root. Full packets (snaplen 0): payloads are
#    not anonymised and the rules need them — that is why the capture
#    stays local_only and is never published. Run from the repo root so
#    \$PWD lands the mount where expected.
mkdir -p local/capture
docker run --rm --net host --cap-add NET_RAW --cap-add NET_ADMIN \\
    --user "\$(id -u):\$(id -g)" --entrypoint tcpdump \\
    -v "\$PWD/local/capture:/work" mmt-bench/tcpreplay:local \\
    -i $IFACE -s 0 -G 3600 -W 1 -w /work/c-benign-raw.pcap

# 3. Anonymise in the pinned container (user). SEED is the anonymisation
#    secret: choose it, keep it local — never in git, the manifest,
#    results/ or REPORT.md.
SEED=\$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
docker run --rm --user "\$(id -u):\$(id -g)" \\
    -v "\$PWD/local/capture:/work" mmt-bench/tcpreplay:local \\
    --infile=/work/c-benign-raw.pcap --outfile=/work/c-benign-all.pcap \\
    --seed=\$SEED \\
    --enet-smac=02:00:00:00:00:01 --enet-dmac=02:00:00:00:00:02 \\
    --fixcsum

# 4. Derive the benchmark corpus (user, #54): keep IPv4, IPv6 and ARP
#    only — the layer-2 control frames mmt-probe never counts are dropped.
#    tcpdump 4.99.4 / libpcap 1.10.4 runs in the pinned image:
#    'tcpdump -r c-benign-all.pcap -w c-benign.pcap "ip or ip6 or arp"'.
#    Byte-for-byte reproducible: run it again, the sha256 is the same.
tools/capture/filter-l2.sh local/capture/c-benign-all.pcap local/capture/c-benign.pcap
sha256sum local/capture/c-benign.pcap   # run step 4 again: same sha256

# 5. Register both captures (user). The raw capture stays local only, in
#    local/capture/ — not in git, not in any shared or synced path — and
#    is deleted only after asking Luong.
mv local/capture/c-benign-all.pcap corpus/data/c-benign-all.pcap
mv local/capture/c-benign.pcap corpus/data/c-benign.pcap
uv run mbench corpus add corpus/data/c-benign-all.pcap --label c-benign-all \\
    --source 'dgx-spark own traffic, 1 h, tcprewrite --seed, not prefix-preserving (local)' \\
    --licence 'local only — anonymised private capture' --local-only
uv run mbench corpus add corpus/data/c-benign.pcap --label c-benign \\
    --source 'c-benign-all filtered with tcpdump 4.99.4 (libpcap 1.10.4) in mmt-bench/tcpreplay:local: tcpdump -r c-benign-all.pcap -w c-benign.pcap "ip or ip6 or arp" (local)' \\
    --licence 'local only — anonymised private capture' --local-only
sha256sum corpus/data/c-benign.pcap   # the sha256 results and reports name
EOF
