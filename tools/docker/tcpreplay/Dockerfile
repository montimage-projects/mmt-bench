# tcprewrite, the anonymiser of the C-benign capture runbook (issue #10).
#
# The base image is the same pinned Ubuntu the mmt-probe image uses; the
# tcpreplay package version is pinned too, so a rebuild reproduces the same
# bits. Build (repo root):
#
#     docker build -t mmt-bench/tcpreplay:local tools/docker/tcpreplay
#
# The image id the build reports is the digest the runbook pins.
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tcpreplay=4.4.4-1build2 \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["tcprewrite"]
