#!/bin/sh
# c-benign — the root-only runbook for the anonymised 1-h capture (#10).
#
# This script ONLY PRINTS the commands. Nothing here runs them: the tcpdump
# step needs root, and agents never use sudo (AGENTS.md). Paste each step
# into a root-capable shell.
#
# What it produces, under local/ and corpus/data/ (both git-ignored, never
# committed):
#   local/capture/c-benign-raw.pcap   the raw 1-h capture — DELETE in step 4
#   corpus/data/c-benign.pcap         the anonymised capture, registered as
#                                     corpus entry `c-benign` (local_only)
#
# Anonymisation is `tcprewrite` in the pinned mmt-bench/tcpreplay:local
# image (built by tools/docker/tcpreplay/Dockerfile, image id
# sha256:8937ab7907f152b43ab40c971d5289c226625a9362910b28c70dc7c88eda118c
# at authoring; `docker inspect` prints the digest of the local build):
#   --seed        deterministic IP rewriting (tcprewrite's crypto-PAn-style
#                 seeded anonymisation: the same address always maps to the
#                 same address, preserving prefix, so flows and client/server
#                 roles survive; the seed is the secret — keep it local, do
#                 not commit it)
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
set -eu

# The interface to listen on: the route to the outside, not a veth.
IFACE=$(ip -o -4 route show to default 2>/dev/null | awk 'NR==1 {print $5}')
: "${IFACE:=CHANGE-ME}"   # no default route: pick the interface yourself

cat <<EOF
# 1. Build the anonymiser image (user, once):
docker build -t mmt-bench/tcpreplay:local tools/docker/tcpreplay
docker inspect -f '{{.Id}}' mmt-bench/tcpreplay:local   # record this digest

# 2. Capture one hour of the host's real traffic (ROOT). Full packets
#    (snaplen 0): payloads are not anonymised and the rules need them —
#    that is why the capture stays local_only and is never published.
sudo mkdir -p local/capture
sudo tcpdump -i $IFACE -s 0 -w local/capture/c-benign-raw.pcap -G 3600 -W 1
sudo chown \$USER:\$USER local/capture/c-benign-raw.pcap

# 3. Anonymise in the pinned container (user). SEED is the crypto key:
#    choose it, keep it local, never commit it.
SEED=\$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
docker run --rm -v "\$PWD/local/capture:/work" mmt-bench/tcpreplay:local \\
    --infile=/work/c-benign-raw.pcap --outfile=/work/c-benign.pcap \\
    --seed=\$SEED \\
    --enet-smac=02:00:00:00:00:01 --enet-dmac=02:00:00:00:00:02 \\
    --fixcsum

# 4. Delete the raw capture and register the anonymised one (user):
rm local/capture/c-benign-raw.pcap
mv local/capture/c-benign.pcap corpus/data/c-benign.pcap
uv run mbench corpus add corpus/data/c-benign.pcap --label c-benign \\
    --source 'dgx-spark own traffic, 1 h, tcprewrite --seed (local)' \\
    --licence 'local only — anonymised private capture' --local-only
sha256sum corpus/data/c-benign.pcap   # the sha256 results and reports name
EOF
