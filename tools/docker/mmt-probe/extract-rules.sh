#!/bin/sh
# extract-rules.sh [DEST] [IMAGE] — copy the mmt-security rule set out of the
# pinned probe image into DEST (default: local/rulesets/mmt-security, the
# ruleset campaigns/smoke.yaml resolves).
#
# The compiled .so rules live in the image at /opt/mmt/security/rules. They
# are architecture-specific build artefacts, so they are never committed:
# each host copies them out of its own build (tools/docker/mmt-probe).
set -eu

dest="${1:-local/rulesets/mmt-security}"
image="${2:-mmt-bench/mmt-probe:local}"

mkdir -p "$dest"
dest="$(cd "$dest" && pwd)"
rm -f "$dest"/*.so   # a rebuilt image's rule set replaces the last copy's

# An mbench- container, --rm, no network, like every container the harness
# starts; --user keeps the copied files owned by the invoking user.
docker run --rm --name "mbench-extract-rules-$$" --network none \
  --user "$(id -u):$(id -g)" -w / \
  -v "$dest:/data" \
  "$image" sh -c 'cp /opt/mmt/security/rules/*.so /data/'

echo "$dest: $(ls "$dest"/*.so | wc -l) rules copied out of $image"
