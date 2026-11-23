#!/usr/bin/env bash
# Build, test and package scribe on macOS (Apple silicon), from Terminal or from Xcode.
#
#   scripts/build/macos.sh doctor                 check the toolchain and say what's missing
#   scripts/build/macos.sh build [--release] [--arch arm64|x86_64|universal]
#   scripts/build/macos.sh test                   tests for this Mac's architecture
#   scripts/build/macos.sh check                  fmt, clippy, tests, doc examples, tags, fixtures, MSRV
#   scripts/build/macos.sh release                dist/ archives for aarch64- and x86_64-apple-darwin
#   scripts/build/macos.sh all                    release here, then the Linux release (scripts/build/linux.sh)
#   scripts/build/macos.sh clean
#
# x86_64 is cross-compiled and never run here: Rosetta ends after macOS 27 (workfiles/plan.md,
# risk 10), so x86_64 tests run in CI.
#
# Inside Xcode (an External Build System target with "Build Tool" set to this script and
# "Arguments" to `$(ACTION)`, or a Run Script phase), the script reads ACTION, CONFIGURATION and
# ARCHS, builds those architectures, joins them with lipo, copies scribed and scribe to
# BUILT_PRODUCTS_DIR and prints errors in the form Xcode lists in its Issue navigator.
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

# Xcode starts scripts with a minimal PATH.
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"

ARCH_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

target_for() {
  case $1 in
    arm64 | aarch64) echo aarch64-apple-darwin ;;
    x86_64) echo x86_64-apple-darwin ;;
    *) die "unknown architecture '$1' (arm64, x86_64)" ;;
  esac
}

# cargo build for one target; `short` gives `file:line:col: error: …` lines for Xcode.
cargo_build() {
  local target=$1 profile=$2 format=${3:-human}
  local args=(build --locked --target "$target")
  [[ $profile == release ]] && args+=(--release)
  for p in $RELEASE_PACKAGES; do args+=(-p "$p"); done
  if [[ $format == xcode ]]; then
    # Absolute paths so Xcode can open the file at the line.
    cargo "${args[@]}" --message-format=short 2>&1 |
      sed -E "s#^((crates|tests|fuzz)/[^:]+):([0-9]+):([0-9]+): #$ROOT/\\1:\\3:\\4: #"
    return "${PIPESTATUS[0]}"
  fi
  cargo "${args[@]}"
}

bin_dir() { echo "$ROOT/target/$1/$2"; }

# Join the binaries of several targets into one universal binary per program.
universal() {
  local profile=$1 out=$2
  shift 2
  mkdir -p "$out"
  for prog in scribed scribe; do
    local inputs=()
    for t in "$@"; do inputs+=("$(bin_dir "$t" "$profile")/$prog"); done
    if (($# == 1)); then cp "${inputs[0]}" "$out/$prog"; else lipo -create -output "$out/$prog" "${inputs[@]}"; fi
  done
}

cmd_doctor() {
  local ok=1 need msrv_version
  msrv_version=$(msrv)
  check() { if eval "$2" >/dev/null 2>&1; then printf '  ok       %s\n' "$1"; else printf '  MISSING  %s — %s\n' "$1" "$3"; ok=; fi; }
  say "macOS toolchain"
  check "Apple silicon" '[[ $(uname -m) == arm64 ]]' "this script expects an Apple silicon Mac"
  check "Xcode command line tools" 'xcode-select -p' "xcode-select --install"
  check "lipo" 'command -v lipo' "comes with the Xcode command line tools"
  check "rustup" 'command -v rustup' "https://rustup.rs"
  check "Rust stable" 'rustup run stable rustc --version' "rustup toolchain install stable"
  check "Rust $msrv_version (MSRV)" "rustup run $msrv_version rustc --version" "rustup toolchain install $msrv_version"
  for need in "${ARCH_TARGETS[@]}"; do
    check "target $need" "rustup target list --installed | grep -qx $need" "rustup target add $need"
  done
  check "cargo-nextest" 'cargo nextest --version' "cargo install --locked cargo-nextest@$NEXTEST_VERSION"
  check "python3 (test tag check)" 'command -v python3' "comes with the Xcode command line tools"
  check "Apple container (Linux builds)" 'command -v container' "optional: https://github.com/apple/container"
  [[ -n $ok ]] || die "install what's missing, then run doctor again"
  say "all set"
}

cmd_build() {
  local profile=debug arch
  arch=$(uname -m)
  while (($#)); do
    case $1 in
      --release) profile=release ;;
      --arch) arch=${2:?--arch needs a value}; shift ;;
      *) die "build: unknown option $1" ;;
    esac
    shift
  done
  if [[ $arch == universal ]]; then
    for t in "${ARCH_TARGETS[@]}"; do say "build $t ($profile)"; cargo_build "$t" "$profile"; done
    universal "$profile" "$ROOT/target/universal-apple-darwin/$profile" "${ARCH_TARGETS[@]}"
    say "universal binaries in target/universal-apple-darwin/$profile"
  else
    local t
    t=$(target_for "$arch")
    say "build $t ($profile)"
    cargo_build "$t" "$profile"
  fi
}

cmd_test() {
  ensure_nextest
  say "tests (aarch64-apple-darwin; x86_64 runs in CI)"
  cargo nextest run --workspace --all-features --locked
}

cmd_check() {
  ensure_nextest
  cd "$ROOT"
  run_checks
  say "all checks passed"
}

cmd_release() {
  local version
  version=$(build_version)
  export SCRIBE_VERSION=$version
  for t in "${ARCH_TARGETS[@]}"; do
    say "release build $t ($version)"
    cargo_build "$t" release
    local smoke=""
    [[ $t == aarch64-apple-darwin ]] && smoke=smoke
    package "$t" "$(bin_dir "$t" release)" "$version" "$smoke"
  done
}

cmd_clean() {
  say "cargo clean"
  cargo clean --manifest-path "$ROOT/Cargo.toml"
  rm -rf "$ROOT/dist"
}

# Xcode: ACTION is "" or "build", "clean", "install"; CONFIGURATION is Debug or Release.
cmd_xcode() {
  local action=${1:-${ACTION:-build}}
  [[ -n $action ]] || action=build
  if [[ $action == clean ]]; then
    cargo clean --manifest-path "$ROOT/Cargo.toml"
    return
  fi
  local profile=debug targets=() a
  [[ ${CONFIGURATION:-Debug} == Release ]] && profile=release
  for a in ${ARCHS:-$(uname -m)}; do targets+=("$(target_for "$a")"); done
  # Xcode's deployment target reaches the C parts (ring, SQLite) through the environment; an
  # empty value would break rustc.
  [[ -n ${MACOSX_DEPLOYMENT_TARGET:-} ]] || unset MACOSX_DEPLOYMENT_TARGET
  echo "note: building ${targets[*]} ($profile) for Xcode"
  for t in "${targets[@]}"; do cargo_build "$t" "$profile" xcode; done
  local out=${BUILT_PRODUCTS_DIR:-$ROOT/target/xcode/$profile}
  universal "$profile" "$out" "${targets[@]}"
  echo "note: scribed and scribe are in $out"
}

main() {
  cd "$ROOT"
  if [[ -n ${XCODE_VERSION_ACTUAL:-} ]]; then
    cmd_xcode "$@"
    return
  fi
  local cmd=${1:-help}
  shift || true
  case $cmd in
    doctor) cmd_doctor ;;
    build) cmd_build "$@" ;;
    test) cmd_test ;;
    check) cmd_check ;;
    release) cmd_release ;;
    all) cmd_release; "$BUILD_DIR/linux.sh" release ;;
    clean) cmd_clean ;;
    xcode) cmd_xcode "$@" ;;
    help | -h | --help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' ;;
    *) die "unknown command '$cmd' (see --help)" ;;
  esac
}

main "$@"
