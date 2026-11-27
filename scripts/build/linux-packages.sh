#!/usr/bin/env bash
# Builds the scribe .deb and .rpm (plan phase 13) with nfpm from packaging/linux/nfpm.yaml.
#
#   scripts/build/linux-packages.sh <folder with scribed and scribe> <target triple> [<version>]
#
# Writes dist/scribe_<version>_<arch>.deb and dist/scribe-<version>.<arch>.rpm and prints their
# paths; the caller adds checksums (scripts/build/linux.sh release, .github/workflows/release.yml).
# <version> defaults to SCRIBE_VERSION, else the one this checkout builds. The shipped config gets
# `user = "scribe"` under [daemon]: scribed leaves root once its sensor is open.
# nfpm NFPM_VERSION (scripts/build/config) is taken from the PATH, else downloaded once into
# target/tools/ and checked against its NFPM_SHA256_* sum. Runs on Linux and macOS.
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

[[ $# -ge 2 ]] || { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
bins=$(cd "$1" && pwd)
target=$2
version=${3:-${SCRIBE_VERSION:-$(build_version)}}
[[ -x $bins/scribed && -x $bins/scribe ]] || die "no scribed and scribe in $bins"

case $target in
  x86_64-*linux*) arch=amd64 ;;
  aarch64-*linux*) arch=arm64 ;;
  *) die "no Linux package for $target" ;;
esac

# nfpm: the pinned version from the PATH, or the checked download.
nfpm_tool() {
  if command -v nfpm >/dev/null && [[ $(nfpm --version 2>/dev/null | awk '/GitVersion/ { print $2 }') == "$NFPM_VERSION" ]]; then
    command -v nfpm; return
  fi
  local os machine key sum dir="$ROOT/target/tools/nfpm-$NFPM_VERSION"
  [[ -x $dir/nfpm ]] && { echo "$dir/nfpm"; return; }
  os=$(uname -s)
  machine=$(uname -m)
  [[ $machine == aarch64 ]] && machine=arm64
  key="NFPM_SHA256_$(tr '[:lower:]' '[:upper:]' <<<"${os}_$machine")"
  sum=${!key:-}
  [[ -n $sum ]] || die "no nfpm checksum for $os $machine in scripts/build/config ($key)"
  local archive="nfpm_${NFPM_VERSION}_${os}_${machine}.tar.gz"
  say "downloading nfpm $NFPM_VERSION ($os $machine)"
  mkdir -p "$dir"
  curl -sSfL -o "$dir/$archive" "https://github.com/goreleaser/nfpm/releases/download/v$NFPM_VERSION/$archive"
  if [[ $(sha256_of "$dir/$archive") != "$sum" ]]; then
    rm -rf "$dir"
    die "nfpm download does not match its checksum in scripts/build/config"
  fi
  tar xzf "$dir/$archive" -C "$dir" nfpm
  rm -f "$dir/$archive"
  echo "$dir/nfpm"
}

nfpm=$(nfpm_tool)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
sed 's/^# user = "scribe"$/user = "scribe"/' "$ROOT/config/scribe.toml" >"$stage/scribe.toml"
grep -q '^user = "scribe"$' "$stage/scribe.toml" || die 'config/scribe.toml has no `# user = "scribe"` line to turn on'

# nfpm expands variables only in some fields, not in file paths: fill them all in here.
for v in "$version" "$arch" "$bins" "$stage"; do
  [[ $v != *'|'* ]] || die "'|' in $v"
done
sed -e "s|\${SCRIBE_VERSION}|$version|g" -e "s|\${PKG_ARCH}|$arch|g" \
  -e "s|\${BINS}|$bins|g" -e "s|\${STAGE}|$stage|g" \
  "$ROOT/packaging/linux/nfpm.yaml" >"$stage/nfpm.yaml"
if grep -q '\${' "$stage/nfpm.yaml"; then die "packaging/linux/nfpm.yaml uses a variable this script doesn't set"; fi

mkdir -p "$ROOT/dist"
for packager in deb rpm; do
  out=$(cd "$ROOT" && "$nfpm" package --config "$stage/nfpm.yaml" --packager "$packager" --target dist/ 2>&1) \
    || die "nfpm ($packager): $out"
  file=$(sed -n 's/.*created package: //p' <<<"$out" | tail -1)
  [[ -n $file ]] || die "nfpm ($packager) did not say what it made: $out"
  [[ $file == /* ]] || file="$ROOT/$file"
  say "packaged ${file#"$ROOT"/}"
  echo "$file"
done
