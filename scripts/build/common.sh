# Shared helpers for scripts/build/*.sh. Source it; don't run it.
# shellcheck shell=bash

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD_DIR="$ROOT/scripts/build"

# Settings from scripts/build/config, unless already set in the environment.
while IFS='=' read -r key value; do
  [[ -z $key || $key == \#* ]] && continue
  [[ -n ${!key:-} ]] || printf -v "$key" '%s' "$value"
done < "$BUILD_DIR/config"

say() { printf '\033[1m==> %s\033[0m\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Minimum Rust version from Cargo.toml.
msrv() {
  awk -F'"' '/^rust-version *=/ { print $2; exit }' "$ROOT/Cargo.toml"
}

# The version the binaries report: the tag, or tag+commits.gsha for a later commit.
# No dirty marker (crates/core/build.rs doesn't add one either).
build_version() {
  local v
  v=$("$ROOT/scripts/version.sh" current)
  v=${v%.dirty}
  echo "${v%+dirty}"
}

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# package <target> <binary dir> <version> [smoke]
# Makes dist/scribe-<version>-<target>.(tar.gz|zip) exactly as .github/workflows/release.yml does and
# adds it to dist/SHA256SUMS. With "smoke", the binaries must report <version> and accept the shipped
# config (only for binaries this machine can run).
package() {
  local target=$1 bins=$2 version=$3 smoke=${4:-}
  local name="scribe-$version-$target" exe=""
  [[ $target == *windows* ]] && exe=".exe"
  local dist="$ROOT/dist" out="$ROOT/dist/$name"
  rm -rf "$out"
  mkdir -p "$out/service"
  cp "$bins/scribed$exe" "$bins/scribe$exe" "$out/"
  cp "$ROOT/readme.md" "$ROOT/LICENSE-MIT" "$ROOT/LICENSE-APACHE" "$ROOT/config/scribe.toml" "$out/"
  cp "$ROOT/packaging/README.md" "$out/service/"
  case $target in
    *linux*)
      cp "$ROOT/packaging/linux/scribed.service" "$ROOT/packaging/linux/scribe-notify.service" "$out/service/"
      cp "$ROOT/scripts/install/linux.sh" "$out/install.sh" ;;
    *apple*)
      cp "$ROOT/packaging/macos/io.github.savex.scribed.plist" "$ROOT/packaging/macos/io.github.savex.scribe-notify.plist" "$out/service/"
      cp "$ROOT/scripts/install/macos.sh" "$out/install.sh" ;;
    *windows*)
      cp "$ROOT/packaging/windows/install-service.ps1" "$ROOT/packaging/windows/install-notify.ps1" "$out/"
      cp "$ROOT/scripts/install/windows.ps1" "$out/install.ps1" ;;
  esac
  if [[ $smoke == smoke ]]; then
    smoke_test "$out" "$exe" "$version"
  fi
  local archive
  (
    cd "$dist"
    if [[ -n $exe ]]; then
      rm -f "$name.zip"
      if command -v 7z >/dev/null; then 7z a -tzip "$name.zip" "$name" >/dev/null; else zip -qr "$name.zip" "$name"; fi
    else
      rm -f "$name.tar.gz"
      tar czf "$name.tar.gz" "$name"
    fi
  )
  rm -rf "$out"
  archive=$(ls "$dist/$name".* | head -1)
  add_sum "$archive"
  say "packaged dist/$(basename "$archive")"
}

# add_sum <file in dist/>: puts its SHA-256 into dist/SHA256SUMS, replacing an older line for it.
add_sum() {
  local file=$1 sums="$ROOT/dist/SHA256SUMS" base
  base=$(basename "$file")
  touch "$sums"
  grep -v "  $base\$" "$sums" > "$sums.tmp" || true
  echo "$(sha256_of "$file")  $base" >> "$sums.tmp"
  sort -k2 "$sums.tmp" > "$sums"
  rm -f "$sums.tmp"
}

# smoke_test <unpacked dir> <exe suffix> <version>: the checks release.yml runs.
smoke_test() {
  local dir=$1 exe=$2 version=$3 got effective
  got=$("$dir/scribe$exe" --version)
  [[ $got == "scribe $version" ]] || die "scribe reports '$got', expected 'scribe $version'"
  got=$("$dir/scribed$exe" --version)
  [[ $got == "scribed $version" ]] || die "scribed reports '$got', expected 'scribed $version'"
  effective=$("$dir/scribed$exe" --check-config --config "$dir/scribe.toml") \
    || die "scribed rejects the shipped config"
  grep -q '^\[modules.url\]' <<<"$effective" || die "the URL module is missing from the effective config"
  say "smoke test passed: $version"
}

# The quality checks every host runs (the Tests workflow's lint and test jobs).
run_checks() {
  local msrv_version
  msrv_version=$(msrv)
  say "fmt";              cargo fmt --all --check
  say "clippy";           cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  say "tests";            cargo nextest run --workspace --all-features --locked
  say "doc examples";     cargo test --workspace --all-features --locked --doc -q
  say "test tags";        "$ROOT/scripts/check-test-tags.sh"
  say "version script";   "$ROOT/scripts/test-version.sh"
  say "fixtures";         cargo run -q --locked -p scribe-test-support --bin gen-fixtures -- --check
  say "msrv $msrv_version"; cargo "+$msrv_version" check --workspace --all-targets --all-features --locked -q
}

ensure_nextest() {
  if ! cargo nextest --version >/dev/null 2>&1; then
    say "installing cargo-nextest $NEXTEST_VERSION"
    cargo install --locked "cargo-nextest@$NEXTEST_VERSION"
  fi
}
