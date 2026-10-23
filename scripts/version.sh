#!/usr/bin/env bash
# Tag-based versioning helper. Tags are the source of truth: vMAJOR.MINOR.PATCH[-PRERELEASE].
# The workspace version in Cargo.toml always equals the latest release tag (set by `bump`).
#
#   scripts/version.sh current            version of this checkout, e.g. 1.2.0 or 1.2.0+3.gabc1234.dirty
#   scripts/version.sh latest-tag         newest release tag reachable from HEAD (empty if none)
#   scripts/version.sh cargo              workspace version in Cargo.toml
#   scripts/version.sh next <major|minor|patch> [prerelease]
#                                         next version from the latest tag, e.g. `next minor rc.1`
#   scripts/version.sh validate <version> exit 1 unless <version> is MAJOR.MINOR.PATCH[-PRERELEASE]
#   scripts/version.sh set <version>      write <version> into Cargo.toml and Cargo.lock
#   scripts/version.sh check [tag]        Cargo.toml must match [tag], or be >= the latest tag
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CARGO_TOML="$ROOT/Cargo.toml"
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'

die() { echo "version.sh: $*" >&2; exit 1; }

latest_tag() {
  git -C "$ROOT" describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true
}

cargo_version() {
  # first `version = "..."` under [workspace.package]
  awk '
    /^\[workspace\.package\]/ { in_pkg = 1; next }
    /^\[/                     { in_pkg = 0 }
    in_pkg && /^version *= *"/ { gsub(/^version *= *"|".*$/, ""); print; exit }
  ' "$CARGO_TOML"
}

validate() {
  [[ $1 =~ $SEMVER_RE ]] || die "not a valid version: '$1' (expected MAJOR.MINOR.PATCH[-PRERELEASE])"
}

# Compare MAJOR.MINOR.PATCH only; prints -1, 0 or 1.
compare_core() {
  local a b i
  IFS=. read -r -a a <<< "${1%%-*}"
  IFS=. read -r -a b <<< "${2%%-*}"
  for i in 0 1 2; do
    if (( a[i] > b[i] )); then echo 1; return; fi
    if (( a[i] < b[i] )); then echo -1; return; fi
  done
  echo 0
}

current() {
  local describe
  describe=$(git -C "$ROOT" describe --tags --match 'v[0-9]*' --dirty --always --abbrev=7 2>/dev/null) \
    || { cargo_version; return; }
  local dirty="" meta=()
  if [[ $describe == *-dirty ]]; then dirty=1; describe=${describe%-dirty}; fi
  if [[ $describe == v* ]]; then
    if [[ $describe =~ ^v(.+)-([0-9]+)-(g[0-9a-f]+)$ ]]; then
      base=${BASH_REMATCH[1]}; meta+=("${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")
    else
      base=${describe#v}
    fi
  else
    base=$(cargo_version); meta+=("g$describe")
  fi
  [[ -n $dirty ]] && meta+=("dirty")
  if (( ${#meta[@]} )); then
    (IFS=.; echo "$base+${meta[*]}")
  else
    echo "$base"
  fi
}

next() {
  local bump=${1:-} pre=${2:-} tag base major minor patch
  tag=$(latest_tag)
  base=${tag#v}
  base=${base:-0.0.0}
  IFS=. read -r major minor patch <<< "${base%%-*}"
  # After a pre-release, a bump of the same level finalizes it: 2.0.0-rc.1 + major -> 2.0.0.
  local pre_release=""
  [[ $base == *-* ]] && pre_release=1
  case $bump in
    major)
      [[ -n $pre_release && $minor == 0 && $patch == 0 ]] || { major=$((major + 1)); minor=0; patch=0; } ;;
    minor)
      [[ -n $pre_release && $patch == 0 ]] || { minor=$((minor + 1)); patch=0; } ;;
    patch)
      [[ -n $pre_release ]] || patch=$((patch + 1)) ;;
    *) die "next: expected major, minor or patch" ;;
  esac
  local version="$major.$minor.$patch${pre:+-$pre}"
  validate "$version"
  echo "$version"
}

set_version() {
  local version=$1 tmp
  validate "$version"
  tmp=$(mktemp)
  awk -v v="$version" '
    /^\[workspace\.package\]/ { in_pkg = 1; print; next }
    /^\[/                     { in_pkg = 0 }
    in_pkg && !done && /^version *= *"/ { print "version = \"" v "\""; done = 1; next }
    { print }
  ' "$CARGO_TOML" > "$tmp"
  mv "$tmp" "$CARGO_TOML"
  [[ $(cargo_version) == "$version" ]] || die "failed to update $CARGO_TOML"
  (cd "$ROOT" && cargo update --workspace --quiet)
  echo "$version"
}

check() {
  local cargo tag=${1:-}
  cargo=$(cargo_version)
  validate "$cargo"
  if [[ -n $tag ]]; then
    [[ ${tag#v} == "$cargo" ]] || die "tag $tag does not match Cargo.toml version $cargo"
    echo "ok: $tag matches Cargo.toml"
    return
  fi
  tag=$(latest_tag)
  if [[ -z $tag ]]; then
    echo "ok: no release tag yet, Cargo.toml is $cargo"
    return
  fi
  [[ $(compare_core "$cargo" "${tag#v}") != -1 ]] \
    || die "Cargo.toml version $cargo is older than latest tag $tag"
  echo "ok: Cargo.toml $cargo, latest tag $tag"
}

cmd=${1:-current}
shift || true
case $cmd in
  current)    current ;;
  latest-tag) latest_tag ;;
  cargo)      cargo_version ;;
  next)       next "$@" ;;
  validate)   validate "${1:?version required}"; echo "ok" ;;
  set)        set_version "${1:?version required}" ;;
  check)      check "$@" ;;
  *)          die "unknown command '$cmd' (see header of $0)" ;;
esac
