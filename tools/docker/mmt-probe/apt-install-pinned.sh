#!/bin/sh
# apt-install-pinned OUT PKG[=VERSION]...  (build stages only; after apt-get update)
# Installs the packages with apt-get. A PKG=VERSION whose version is no longer
# in the Ubuntu archive (Ubuntu drops a version when it publishes the next
# update, and has no arm64 snapshot archive):
#   - by default: installs the current candidate instead and prints a loud
#     WARNING;
#   - with MMT_STRICT_PINS=1 (CI, reviews, exact rebuilds): fails the build.
# Writes the versions actually installed to OUT, one "pkg=version" per line,
# then "apt_pins=exact" or "apt_pins=fallback (<pkgs>)".
set -eu
out="$1"; shift
strict="${MMT_STRICT_PINS:-0}"
args=""; pinned=""; fell=""
for spec in "$@"; do
  pkg="${spec%%=*}"
  case "$spec" in
    *=*)
      ver="${spec#*=}"; pinned="$pinned $pkg"
      if apt-cache madison "$pkg" | awk -F'|' '{gsub(/ /, "", $2); print $2}' | grep -qxF "$ver"; then
        args="$args $pkg=$ver"
      else
        cand="$(apt-cache policy "$pkg" | sed -n 's/^ *Candidate: //p')"
        if [ "$strict" = 1 ]; then
          echo "ERROR: $pkg $ver is not in the archive (candidate: ${cand:-none}); MMT_STRICT_PINS=1: refresh the APT_PIN_* arguments" >&2
          exit 1
        fi
        echo "################################################################" >&2
        echo "WARNING: $pkg $ver not in the archive, using $cand" >&2
        echo "WARNING: refresh the APT_PIN_* arguments;" >&2
        echo "WARNING: build with MMT_STRICT_PINS=1 to fail instead" >&2
        echo "################################################################" >&2
        args="$args $pkg"; fell="$fell $pkg"
      fi ;;
    *) args="$args $pkg" ;;
  esac
done
# shellcheck disable=SC2086
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $args
mkdir -p "$(dirname "$out")"
: > "$out"
for pkg in $pinned; do
  echo "$pkg=$(dpkg-query -W -f '${Version}' "$pkg")" >> "$out"
done
if [ -n "$fell" ]; then echo "apt_pins=fallback (${fell# })" >> "$out"; else echo "apt_pins=exact" >> "$out"; fi
