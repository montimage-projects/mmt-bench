# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
#
# mmt-bench probe image: mmt-dpi (release .deb) + mmt-security (source) +
# mmt-probe (source, STIX_FORMAT + SECURITY_MODULE), all pinned.
# Build recipe mirrors mmt-stack's pinned probe build.
#
# Every download is pinned: the BuildKit frontend and the base image by
# digest; the Ubuntu packages that the image ships or links against by
# version (APT_PIN_* below); the DPI .deb by the release's SHA256SUMS (itself
# pinned by its sha256); the sources by commit (fetched by commit id, not by
# branch). The build-only tools (gcc, make, git, curl) are not version-pinned.

ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8

# ---- pins -------------------------------------------------------------------
ARG DPI_VERSION=1.10.3
ARG DPI_BUILD=6a0afb46
ARG DPI_SHA256SUMS_SHA256=f7f7a80990bdb3c98f48978ff2bf00fa649a5c70633c906bd666543449ea6ed5
# mmt-security's source repo and commit: upstream Montimage/mmt-security by
# default. The internal fork is pinned with
#   --build-arg SECURITY_REPO=https://github.com/montimage-projects/mmt-security.git \
#               SECURITY_COMMIT=<fork sha> SECURITY_TAG=
# (SECURITY_TAG empty skips the tag→commit check; the repo lands in
# /opt/mmt/VERSIONS either way).
ARG SECURITY_REPO=https://github.com/Montimage/mmt-security.git
ARG SECURITY_TAG=v1.2.20
ARG SECURITY_COMMIT=a78a4fd4a33a3c4e218c1c4c11e7e1e23b6c7dff
ARG PROBE_COMMIT=1e00441a00bba1d064ede2ef95b851428c2b0183   # branch intact-new-features
# Ubuntu packages (noble-updates/-security, 2026-11-19). Ubuntu removes a
# version from the archive when it publishes the next update, and has no
# archive snapshot for arm64 (snapshot.ubuntu.com serves amd64 only). When a
# pinned version is gone, docker/apt-install-pinned.sh installs the current
# candidate with a loud WARNING and records it in /opt/mmt/VERSIONS
# (apt_pins=fallback). With MMT_STRICT_PINS=1 the build fails instead.
ARG MMT_STRICT_PINS=0
ARG APT_PIN_LIBPCAP=1.10.4-4.1ubuntu3.1
ARG APT_PIN_LIBXML2=2.9.14+dfsg-1.3ubuntu3.10
ARG APT_PIN_UTIL_LINUX=2.39.3-9ubuntu6.6
ARG APT_PIN_LIBCONFUSE=3.3-3build1

# =============================================================================
# fetch: downloads only (DPI .debs for both arches, sources), all verified
# =============================================================================
FROM --platform=$BUILDPLATFORM ${UBUNTU_IMAGE} AS fetch
ARG DPI_VERSION DPI_BUILD DPI_SHA256SUMS_SHA256 SECURITY_REPO SECURITY_TAG SECURITY_COMMIT PROBE_COMMIT
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /fetch
# DPI: SHA256SUMS is pinned by hash, then each .deb is checked against it.
RUN set -eux; \
    base="https://github.com/Montimage/mmt-dpi/releases/download/v${DPI_VERSION}"; \
    curl -fsSL -o SHA256SUMS "$base/SHA256SUMS"; \
    echo "${DPI_SHA256SUMS_SHA256}  SHA256SUMS" | sha256sum -c -; \
    for a in aarch64 x86_64; do \
      f="mmt-dpi_${DPI_VERSION}_${DPI_BUILD}_ubuntu-24.04_${a}.deb"; \
      curl -fsSL -o "$f" "$base/$f"; \
      grep "  $f\$" SHA256SUMS | sha256sum -c -; \
    done
# Sources, fetched by commit id (a force-pushed branch cannot change them),
# checked; when SECURITY_TAG is set, the mmt-security tag must still name
# the pinned commit (a fork pinned by sha sets SECURITY_TAG= to skip it).
RUN set -eux; \
    fetch() { git init -q "$1"; git -C "$1" fetch -q --depth 1 "$2" "$3"; \
              git -C "$1" checkout -q FETCH_HEAD; test "$(git -C "$1" rev-parse HEAD)" = "$3"; }; \
    fetch mmt-security "${SECURITY_REPO}" "${SECURITY_COMMIT}"; \
    fetch mmt-probe https://github.com/Montimage/mmt-probe.git "${PROBE_COMMIT}"; \
    if [ -n "${SECURITY_TAG}" ]; then \
      git ls-remote "${SECURITY_REPO}" "refs/tags/${SECURITY_TAG}^{}" "refs/tags/${SECURITY_TAG}" \
        | grep -q "^${SECURITY_COMMIT}"; \
    fi

# =============================================================================
# build: native build for $TARGETARCH
# =============================================================================
FROM ${UBUNTU_IMAGE} AS build
ARG TARGETARCH DPI_VERSION DPI_BUILD APT_PIN_LIBPCAP APT_PIN_LIBXML2 APT_PIN_UTIL_LINUX APT_PIN_LIBCONFUSE MMT_STRICT_PINS
COPY apt-install-pinned.sh /usr/local/bin/apt-install-pinned
RUN apt-get update \
 && apt-install-pinned /opt/mmt/probe/apt-build-versions \
      gcc make git libc6-dev \
      libconfuse-dev="${APT_PIN_LIBCONFUSE}" libpcap-dev="${APT_PIN_LIBPCAP}" \
      libxml2-dev="${APT_PIN_LIBXML2}" uuid-dev="${APT_PIN_UTIL_LINUX}" \
 && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /fetch /fetch
# Only the mmt-dpi package is needed: mmt-dpi-security holds DPI's legacy
# libmmt_security/libmmt_fuzz, which neither probe nor security use.
RUN set -eux; \
    case "$TARGETARCH" in arm64) a=aarch64;; amd64) a=x86_64;; *) echo "unsupported $TARGETARCH"; exit 1;; esac; \
    dpkg -i "/fetch/mmt-dpi_${DPI_VERSION}_${DPI_BUILD}_ubuntu-24.04_${a}.deb"; \
    echo /opt/mmt/dpi/lib > /etc/ld.so.conf.d/mmt-dpi.conf; ldconfig
WORKDIR /src/mmt-security
RUN cp -a /fetch/mmt-security/. . \
 && make -j1 \
 && make install
WORKDIR /src/mmt-probe
RUN cp -a /fetch/mmt-probe/. . \
 && make -j"$(nproc)" SECURITY_MODULE STIX_FORMAT compile \
 && make test-stix \
 && install -D -m 0755 probe /opt/mmt/probe/bin/probe \
 && /opt/mmt/probe/bin/probe -v

# =============================================================================
# runtime: probe + security tools + the shared objects they load
# =============================================================================
FROM ${UBUNTU_IMAGE} AS runtime
ARG DPI_VERSION SECURITY_REPO SECURITY_TAG SECURITY_COMMIT PROBE_COMMIT APT_PIN_LIBPCAP APT_PIN_LIBXML2 APT_PIN_UTIL_LINUX MMT_STRICT_PINS
COPY apt-install-pinned.sh /usr/local/bin/apt-install-pinned
RUN apt-get update \
 && apt-install-pinned /opt/mmt/apt-versions \
      libpcap0.8t64="${APT_PIN_LIBPCAP}" libxml2="${APT_PIN_LIBXML2}" \
      libuuid1="${APT_PIN_UTIL_LINUX}" \
 && rm -f /usr/local/bin/apt-install-pinned \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/mmt/dpi/lib/ /opt/mmt/dpi/lib/
COPY --from=build /opt/mmt/plugins/ /opt/mmt/plugins/
COPY --from=build /opt/mmt/security/ /opt/mmt/security/
COPY --from=build /opt/mmt/probe/ /opt/mmt/probe/
RUN rm -f /opt/mmt/dpi/lib/*.a /opt/mmt/security/lib/*.a* \
 && rm -rf /opt/mmt/dpi/lib/pkgconfig /opt/mmt/security/include \
 && printf '/opt/mmt/dpi/lib\n/opt/mmt/security/lib\n' > /etc/ld.so.conf.d/mmt.conf && ldconfig \
 && security_label="${SECURITY_COMMIT}" \
 && if [ -n "${SECURITY_TAG}" ]; then security_label="${SECURITY_TAG} (${SECURITY_COMMIT})"; fi \
 && printf 'dpi=%s\nsecurity=%s\nsecurity_repo=%s\nprobe=%s\nprobe_modules=SECURITY_MODULE STIX_FORMAT\n' \
        "${DPI_VERSION}" "${security_label}" "${SECURITY_REPO}" "${PROBE_COMMIT}" > /opt/mmt/VERSIONS \
 && cat /opt/mmt/apt-versions >> /opt/mmt/VERSIONS && rm -f /opt/mmt/apt-versions \
 && sed 's/^/build_/' /opt/mmt/probe/apt-build-versions >> /opt/mmt/VERSIONS \
 && /opt/mmt/probe/bin/probe -v
LABEL org.opencontainers.image.title="mmt-bench probe" \
      io.montimage.mmt-dpi.version="${DPI_VERSION}" \
      io.montimage.mmt-security.version="${SECURITY_TAG}" \
      io.montimage.mmt-security.commit="${SECURITY_COMMIT}" \
      io.montimage.mmt-security.repo="${SECURITY_REPO}" \
      io.montimage.mmt-probe.commit="${PROBE_COMMIT}"
# mmt-security's check captures and expected alerts: the integration test
# runs the probe on them and compares with the expects and mmt_sec_standalone
# (all from the same pinned commit). No capture leaves the image or the repo.
COPY --from=fetch /fetch/mmt-security/check/pcap/ /opt/mmt/check/pcap/
COPY --from=fetch /fetch/mmt-security/check/expect/ /opt/mmt/check/expect/
COPY entrypoint.sh /usr/local/bin/mmt-bench-tool
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/mmt-bench-tool"]
CMD ["probe"]
