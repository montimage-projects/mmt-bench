# mmt-probe image for mmt-bench

The image runs mmt-probe (with mmt-dpi and mmt-security) for mmt-bench's
offline benchmarks. It is built here by the harness or by hand; it is never
the production mmt-stack image.

## Pins (see the Dockerfile ARGs)

| piece | pin |
|-------|-----|
| base image | `ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8` |
| mmt-dpi | v1.10.3 release `.deb`, build `6a0afb46`; the release `SHA256SUMS` is itself pinned by `f7f7a809…ea6ed5`, and the `.deb` is verified against it |
| mmt-security | fork `main` = commit `855931a37bd73bd43b26ff03ea108c6745c11b19` from `SECURITY_REPO` (default `montimage-projects/mmt-security`; no tag names it, so `SECURITY_TAG` is empty) |
| mmt-probe | fork `intact-new-features` = commit `7f4710d9846c1654ca3555479394ed720556f340` from `PROBE_REPO` (default `montimage-projects/mmt-probe`; fixes the upstream `snap-len = 0` worker-ring overflow and the exit-0 crash masking the P1 review found — fork PRs #3 and #4) |

The probe is built with `SECURITY_MODULE` and `STIX_FORMAT`; security alerts
come out as STIX bundles, other reports as JSON.

mmt-security's source is a build argument, so the upstream v1.2.20 baseline
builds with a one-line change:

```sh
docker build -t mmt-bench/mmt-probe:local tools/docker/mmt-probe \
  --build-arg SECURITY_REPO=https://github.com/Montimage/mmt-security.git \
  --build-arg SECURITY_TAG=v1.2.20 \
  --build-arg SECURITY_COMMIT=a78a4fd4a33a3c4e218c1c4c11e7e1e23b6c7dff
```

An empty `SECURITY_TAG` skips the tag→commit check; the source repo is
recorded in `/opt/mmt/VERSIONS` (`security_repo=`) either way, and reaches the
tools record through the `versions` output. The probe's source is a build
argument too: the upstream `Montimage/mmt-probe` commit the image used to pin
builds with

```sh
docker build -t mmt-bench/mmt-probe:local tools/docker/mmt-probe \
  --build-arg PROBE_REPO=https://github.com/Montimage/mmt-probe.git \
  --build-arg PROBE_COMMIT=1e00441a00bba1d064ede2ef95b851428c2b0183
```

and `/opt/mmt/VERSIONS` records `probe=` and `probe_repo=` the same way.

## Build

```sh
docker build -t mmt-bench/mmt-probe:local tools/docker/mmt-probe
```

`docker image inspect -f '{{.Id}}' mmt-bench/mmt-probe:local` gives the
`sha256:` digest the adapter records. `MMT_STRICT_PINS=1` makes the build fail
when an apt pin has left the Ubuntu archive instead of falling back to the
current candidate.

## The image's rules

The compiled mmt-security `.so` rules live in the image at
`/opt/mmt/security/rules`. They are architecture-specific build artefacts,
so they are never committed: a campaign that needs the image's rule set
copies it out of the local build, into the git-ignored `local/`:

```sh
tools/docker/mmt-probe/extract-rules.sh [DEST] [IMAGE]
# default: local/rulesets/mmt-security — the path campaigns/smoke.yaml uses
```

## Entrypoint

`mmt-bench-tool` dispatches on its first argument:

- `probe …` — run the probe (`probe -c conf -t pcap` for offline mode);
- `rule_info [x.so]` — list the rules of one `.so`, or of every `.so` in
  `/opt/mmt/security/rules`;
- `mmt_sec_standalone -t pcap -f dir` — mmt-security's standalone check tool,
  for comparing alert counts;
- `versions` — `/opt/mmt/VERSIONS` (all build pins) then `probe -v`.
