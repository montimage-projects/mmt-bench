# tcprewrite and tcpdump, the anonymiser, capturer and L2 filter of the
# C-benign runbook (issues #10, #50 and #54). One image serves all three
# steps: the capture is `docker run --net host --cap-add NET_RAW --cap-add
# NET_ADMIN --user $(id -u):$(id -g) --entrypoint tcpdump` (no sudo), the
# anonymisation keeps the default `tcprewrite` entrypoint, and the filter
# is `tools/capture/filter-l2.sh` (--entrypoint tcpdump on files).
#
# tcpdump carries cap_net_raw,cap_net_admin as *file* capabilities: docker's
# --cap-add does not apply to a non-root --user, so the capability the
# capture needs travels on the binary instead, and the pcap lands owned by
# the invoking user rather than by root.
#
# The base image is the same pinned Ubuntu the mmt-probe image uses; the
# package versions are pinned too, so a rebuild reproduces the same bits.
# Build (repo root):
#
#     docker build -t mmt-bench/tcpreplay:local tools/docker/tcpreplay
#
# The image id the build reports is the digest the runbook pins.
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tcpreplay=4.4.4-1build2 \
        tcpdump=4.99.4-3ubuntu4.24.04.1 \
        libcap2-bin=1:2.66-5ubuntu2.4 \
    && rm -rf /var/lib/apt/lists/* \
    && setcap 'cap_net_raw,cap_net_admin=ep' /usr/bin/tcpdump

ENTRYPOINT ["tcprewrite"]
