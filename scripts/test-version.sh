#!/usr/bin/env bash
# Tests for scripts/version.sh, run in a throwaway git repository (no network, no real tags).
#   scripts/test-version.sh
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/version.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fails=0

expect() { # expect <wanted output> <command...>
  local want=$1 got; shift
  got=$("$@" 2>&1) || true
  if [[ $got != "$want" ]]; then echo "FAIL: $* -> '$got', expected '$want'"; fails=$((fails + 1)); fi
}
expect_fail() { # expect_fail <message part> <command...>
  local part=$1 got; shift
  if got=$("$@" 2>&1); then echo "FAIL: $* succeeded: '$got'"; fails=$((fails + 1)); return; fi
  [[ $got == *"$part"* ]] || { echo "FAIL: $* -> '$got', expected '$part'"; fails=$((fails + 1)); }
}

# SemVer precedence (semver.org, section 11).
order=(1.0.0-alpha 1.0.0-alpha.1 1.0.0-alpha.beta 1.0.0-beta 1.0.0-beta.2 1.0.0-beta.11 1.0.0-rc.1 1.0.0 1.0.1 1.1.0 2.0.0)
for (( i = 0; i + 1 < ${#order[@]}; i++ )); do
  expect -1 "$SCRIPT" compare "${order[i]}" "${order[i+1]}"
  expect 1 "$SCRIPT" compare "${order[i+1]}" "${order[i]}"
done
expect 0 "$SCRIPT" compare 1.2.3 1.2.3
expect -1 "$SCRIPT" compare 0.1.0-alpha.1 0.1.1

# A repository with Cargo.toml, Cargo.lock-free workspace and a changelog.
repo="$WORK/repo"
mkdir -p "$repo/scripts"
cp "$SCRIPT" "$repo/scripts/version.sh"
cd "$repo"
git init -q -b main
git config user.email test@example.com
git config user.name test
printf '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "0.1.1"\n' > Cargo.toml
cat > changelog.md <<'LOG'
# Changelog

## [Unreleased]

### Added
- Something new.

## [0.1.1] - 2026-11-08

### Added
- First.

[Unreleased]: https://github.com/savex/scribe/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/savex/scribe/releases/tag/v0.1.1
LOG
git add -A && git commit -qm init
V=scripts/version.sh

# Tags missing (never pushed, or not fetched): Cargo.toml and the changelog still count.
expect "" $V latest-tag
expect 0.1.1 $V highest
expect 0.1.2 $V next patch
expect 0.2.0-alpha.1 $V next minor alpha.1
expect_fail "out of sync: no release tag here" $V versions
expect_fail "not newer than 0.1.1" $V newer 0.1.0-alpha.1
expect_fail "not newer than 0.1.1" $V newer 0.1.1

# Tags: the highest wins, not the nearest; a pre-release tag below a release doesn't lower it.
git tag v0.1.1
git commit -q --allow-empty -m two
git tag v0.1.0-alpha.1
expect v0.1.1 $V latest-tag
expect v0.1.0-alpha.1 $V nearest-tag
expect 0.1.2 $V next patch
expect "ok: Cargo.toml 0.1.1, latest tag v0.1.1" $V check
expect_fail "tag v0.1.1 already exists" $V newer 0.1.1

# Pre-release finalised by a same-level bump.
git tag v0.2.0-rc.1
expect 0.2.0 $V next minor
expect "ok: 0.2.0-rc.2 is newer than 0.2.0-rc.1" $V newer 0.2.0-rc.2
expect_fail "older than latest tag v0.2.0-rc.1" $V check

# The changelog release: entries move under the new version, links follow.
expect 0.2.0 $V changelog 0.2.0 2026-12-01
expect 0.2.0 $V changelog-version
grep -q '^## \[0.2.0\] - 2026-12-01$' changelog.md || { echo "FAIL: no 0.2.0 heading"; fails=$((fails + 1)); }
[[ $(awk '/^## \[Unreleased\]/{u=1;next} u&&/^## \[/{print;exit} u&&/^- /{print "entry before release"}' changelog.md) == "## [0.2.0] - 2026-12-01" ]] \
  || { echo "FAIL: Unreleased is not empty"; fails=$((fails + 1)); }
grep -q '^\[Unreleased\]: https://github.com/savex/scribe/compare/v0.2.0...HEAD$' changelog.md \
  || { echo "FAIL: Unreleased link"; fails=$((fails + 1)); }
grep -q '^\[0.2.0\]: https://github.com/savex/scribe/releases/tag/v0.2.0$' changelog.md \
  || { echo "FAIL: release link"; fails=$((fails + 1)); }
expect_fail "already has a 0.2.0 section" $V changelog 0.2.0

if (( fails )); then echo "test-version: $fails failure(s)"; exit 1; fi
echo "test-version: ok"
