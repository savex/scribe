#!/usr/bin/env bash
# Tag-based versioning helper. Tags are the source of truth: vMAJOR.MINOR.PATCH[-PRERELEASE].
# The workspace version in Cargo.toml and the newest section of changelog.md follow the latest
# release (both written by `Bump version`). Versions are ordered by SemVer 2.0 precedence, so
# 0.1.0-alpha.1 < 0.1.0 < 0.1.1.
#
#   scripts/version.sh current            version of this checkout, e.g. 1.2.0 or 1.2.0+3.gabc1234.dirty
#   scripts/version.sh latest-tag         highest release tag in the repository (empty if none)
#   scripts/version.sh nearest-tag        nearest release tag reachable from HEAD (empty if none)
#   scripts/version.sh cargo              workspace version in Cargo.toml
#   scripts/version.sh changelog-version  newest released version in changelog.md (empty if none)
#   scripts/version.sh highest            highest of the latest tag, Cargo.toml and changelog.md
#   scripts/version.sh versions           all of the above and whether they agree; exit 1 if not
#   scripts/version.sh next <major|minor|patch> [prerelease]
#                                         next version after `highest`, e.g. `next minor rc.1`
#   scripts/version.sh newer <version>    exit 1 unless <version> is newer than `highest` and untagged
#   scripts/version.sh compare <a> <b>    print -1, 0 or 1 by SemVer precedence
#   scripts/version.sh validate <version> exit 1 unless <version> is MAJOR.MINOR.PATCH[-PRERELEASE]
#   scripts/version.sh set <version>      write <version> into Cargo.toml and Cargo.lock
#   scripts/version.sh changelog <version> [date]
#                                         turn the Unreleased section of changelog.md into <version>
#   scripts/version.sh check [tag]        Cargo.toml must match [tag], or not be older than the latest tag
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CARGO_TOML="$ROOT/Cargo.toml"
CHANGELOG="$ROOT/changelog.md"
REPO_URL="https://github.com/savex/scribe"
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'

die() { echo "version.sh: $*" >&2; exit 1; }

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

# Full SemVer 2.0 precedence (build metadata ignored); prints -1, 0 or 1.
compare() {
  local a=${1%%+*} b=${2%%+*} c pa="" pb="" i n p q
  c=$(compare_core "$a" "$b")
  if [[ $c != 0 ]]; then echo "$c"; return; fi
  [[ $a == *-* ]] && pa=${a#*-}
  [[ $b == *-* ]] && pb=${b#*-}
  if [[ -z $pa && -z $pb ]]; then echo 0; return; fi
  if [[ -z $pa ]]; then echo 1; return; fi    # a release is newer than its pre-releases
  if [[ -z $pb ]]; then echo -1; return; fi
  local -a x y
  IFS=. read -r -a x <<< "$pa"
  IFS=. read -r -a y <<< "$pb"
  n=${#x[@]}
  (( ${#y[@]} > n )) && n=${#y[@]}
  for (( i = 0; i < n; i++ )); do
    if (( i >= ${#x[@]} )); then echo -1; return; fi
    if (( i >= ${#y[@]} )); then echo 1; return; fi
    p=${x[i]} q=${y[i]}
    if [[ $p =~ ^[0-9]+$ && $q =~ ^[0-9]+$ ]]; then
      if (( 10#$p > 10#$q )); then echo 1; return; fi
      if (( 10#$p < 10#$q )); then echo -1; return; fi
    elif [[ $p =~ ^[0-9]+$ ]]; then echo -1; return   # numeric identifiers sort first
    elif [[ $q =~ ^[0-9]+$ ]]; then echo 1; return
    elif [[ $p > $q ]]; then echo 1; return
    elif [[ $p < $q ]]; then echo -1; return
    fi
  done
  echo 0
}

# The higher of two versions; an empty argument loses.
max_version() {
  if [[ -z $1 ]]; then echo "$2"; return; fi
  if [[ -z $2 ]]; then echo "$1"; return; fi
  if [[ $(compare "$1" "$2") == -1 ]]; then echo "$2"; else echo "$1"; fi
}

latest_tag() {
  local tag best=""
  while IFS= read -r tag; do
    [[ ${tag#v} =~ $SEMVER_RE ]] || continue
    if [[ -z $best || $(compare "${tag#v}" "${best#v}") == 1 ]]; then best=$tag; fi
  done < <(git -C "$ROOT" tag -l 'v[0-9]*')
  echo "$best"
}

current() {
  local describe base
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

nearest_tag() {
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

changelog_version() {
  [[ -f $CHANGELOG ]] || return 0
  awk '/^## \[/ && !/^## \[Unreleased\]/ { sub(/^## \[/, ""); sub(/\].*$/, ""); print; exit }' "$CHANGELOG"
}

highest() {
  local tag
  tag=$(latest_tag)
  max_version "$(max_version "${tag#v}" "$(cargo_version)")" "$(changelog_version)"
}

versions() {
  local tag cargo log high ok=1
  tag=$(latest_tag); cargo=$(cargo_version); log=$(changelog_version); high=$(highest)
  echo "latest tag:      ${tag:-none}"
  echo "nearest tag:     $(nearest_tag | sed 's/^$/none/')"
  echo "Cargo.toml:      $cargo"
  echo "changelog.md:    ${log:-none}"
  echo "highest:         ${high:-none}"
  if [[ -n $tag && ${tag#v} != "$cargo" ]]; then
    echo "out of sync: Cargo.toml $cargo is not the latest tag $tag"; ok=""
  fi
  if [[ -n $log && $log != "$cargo" ]]; then
    echo "out of sync: changelog.md's newest release $log is not Cargo.toml $cargo"; ok=""
  fi
  if [[ -z $tag && -n $high ]]; then
    echo "out of sync: no release tag here, but Cargo.toml / changelog.md say $high (tags not fetched or not pushed?)"; ok=""
  fi
  [[ -n $ok ]] && echo "in sync"
  [[ -n $ok ]]
}

next() {
  local bump=${1:-} pre=${2:-} base major minor patch
  base=$(highest)
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
  newer "$version" >/dev/null
  echo "$version"
}

# <version> must be newer than every version we know of, and not tagged yet.
newer() {
  local version=$1 high
  validate "$version"
  if git -C "$ROOT" rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
    die "tag v$version already exists"
  fi
  high=$(highest)
  if [[ -n $high && $(compare "$version" "$high") != 1 ]]; then
    die "$version is not newer than $high (the highest of the latest tag, Cargo.toml and changelog.md); pick a higher version, e.g. with a pre-release label on the next patch"
  fi
  echo "ok: $version is newer than ${high:-nothing}"
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

# Unreleased entries become the <version> section; a fresh, empty Unreleased goes on top and the
# links at the bottom follow.
changelog_release() {
  local version=$1 date=${2:-} tmp
  [[ -n $date ]] || date=$(date -u +%Y-%m-%d)
  validate "$version"
  [[ -f $CHANGELOG ]] || die "no $CHANGELOG"
  grep -q '^## \[Unreleased\]' "$CHANGELOG" || die "changelog.md has no '## [Unreleased]' section"
  if grep -q "^## \[$version\]" "$CHANGELOG"; then die "changelog.md already has a $version section"; fi
  tmp=$(mktemp)
  awk -v v="$version" -v d="$date" -v url="$REPO_URL" '
    /^## \[Unreleased\]/ { print; print ""; print "## [" v "] - " d; next }
    /^\[Unreleased\]: /   { print "[Unreleased]: " url "/compare/v" v "...HEAD"; print "[" v "]: " url "/releases/tag/v" v; linked = 1; next }
    { print }
    END { if (!linked) { print ""; print "[Unreleased]: " url "/compare/v" v "...HEAD"; print "[" v "]: " url "/releases/tag/v" v } }
  ' "$CHANGELOG" > "$tmp"
  mv "$tmp" "$CHANGELOG"
  [[ $(changelog_version) == "$version" ]] || die "failed to update $CHANGELOG"
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
  [[ $(compare "$cargo" "${tag#v}") != -1 ]] \
    || die "Cargo.toml version $cargo is older than latest tag $tag"
  echo "ok: Cargo.toml $cargo, latest tag $tag"
}

cmd=${1:-current}
shift || true
case $cmd in
  current)           current ;;
  latest-tag)        latest_tag ;;
  nearest-tag)       nearest_tag ;;
  cargo)             cargo_version ;;
  changelog-version) changelog_version ;;
  highest)           highest ;;
  versions)          versions ;;
  next)              next "$@" ;;
  newer)             newer "${1:?version required}" ;;
  compare)           validate "${1:?a required}"; validate "${2:?b required}"; compare "$1" "$2" ;;
  validate)          validate "${1:?version required}"; echo "ok" ;;
  set)               set_version "${1:?version required}" ;;
  changelog)         changelog_release "${1:?version required}" "${2:-}" ;;
  check)             check "$@" ;;
  *)                 die "unknown command '$cmd' (see header of $0)" ;;
esac
