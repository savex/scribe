#!/usr/bin/env bash
# Build, test and package scribe for Linux.
#
#   scripts/build/linux.sh doctor
#   scripts/build/linux.sh image [--rebuild]           build the container image (container mode)
#   scripts/build/linux.sh build [--release] [--target <triple>]
#   scripts/build/linux.sh test                        tests for the build machine's architecture
#   scripts/build/linux.sh check                       fmt, clippy, tests, doc examples, tags, fixtures, MSRV
#   scripts/build/linux.sh release                     dist/ archive, .deb and .rpm for
#                                                      x86_64-unknown-linux-gnu (and
#                                                      aarch64-unknown-linux-gnu with --all-targets)
#   scripts/build/linux.sh shell                       a shell in the build container
#   scripts/build/linux.sh run [--privileged] <command…>
#                                                      one command in the build container (as root;
#                                                      --privileged adds every capability, for the
#                                                      eBPF and capture tests: `cargo nextest run
#                                                      -p scribe-sensor-conformance --run-ignored only`)
#   scripts/build/linux.sh clean
#
# Modes:
#   default    in a container: Apple `container` on macOS, else docker or podman (SCRIBE_CTR picks one).
#              The image is native arm64 on Apple silicon; x86_64 is cross-compiled there and its
#              binaries aren't run (Rosetta ends after macOS 27: workfiles/plan.md, risk 10).
#              `--arch amd64` runs an amd64 image instead (under Rosetta while it exists).
#   --native   on this Linux machine as it is: the GitHub runner, WSL2, a Linux workstation.
#              The container mode runs the script this way inside the container.
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

NATIVE=""
ARCH=""

# ---------------------------------------------------------------------------- native mode

host_target() { rustc -vV | sed -n 's/^host: //p'; }

linux_build() {
  local target=$1 profile=$2
  local args=(build --locked --target "$target")
  [[ $profile == release ]] && args+=(--release)
  for p in $RELEASE_PACKAGES; do args+=(-p "$p"); done
  say "build $target ($profile)"
  cargo "${args[@]}"
}

native_doctor() {
  local ok=1 msrv_version
  msrv_version=$(msrv)
  check() { if eval "$2" >/dev/null 2>&1; then printf '  ok       %s\n' "$1"; else printf '  MISSING  %s — %s\n' "$1" "$3"; ok=; fi; }
  say "Linux toolchain ($(uname -m))"
  check "Linux" '[[ $(uname -s) == Linux ]]' "run without --native on macOS"
  check "C compiler" 'command -v cc' "apt-get install build-essential"
  check "pkg-config" 'command -v pkg-config' "apt-get install pkg-config"
  check "libpcap headers" 'test -e /usr/include/pcap.h || test -e /usr/include/pcap/pcap.h' "apt-get install libpcap-dev (phase 6)"
  check "clang (eBPF programs)" 'command -v clang' "apt-get install clang (phase 7)"
  check "libelf and zlib headers" 'test -e /usr/include/libelf.h && test -e /usr/include/zlib.h' "apt-get install libelf-dev zlib1g-dev (phase 7)"
  check "python3" 'command -v python3' "apt-get install python3"
  check "Rust stable" 'rustup run stable rustc --version' "https://rustup.rs"
  check "Rust $msrv_version (MSRV)" "rustup run $msrv_version rustc --version" "rustup toolchain install $msrv_version"
  check "target x86_64-unknown-linux-gnu" 'rustup target list --installed | grep -qx x86_64-unknown-linux-gnu' "rustup target add x86_64-unknown-linux-gnu"
  if [[ $(uname -m) != x86_64 ]]; then
    check "x86_64 cross compiler" 'command -v x86_64-linux-gnu-gcc' "apt-get install gcc-x86-64-linux-gnu libc6-dev-amd64-cross"
  fi
  check "cargo-nextest" 'cargo nextest --version' "cargo install --locked cargo-nextest@$NEXTEST_VERSION"
  [[ -n $ok ]] || die "install what's missing, then run doctor again"
  say "all set"
}

native_release() {
  local all=${1:-} version host targets=(x86_64-unknown-linux-gnu)
  version=${SCRIBE_VERSION:-$(build_version)}
  export SCRIBE_VERSION=$version
  host=$(host_target)
  [[ $all == --all-targets && $host != x86_64-unknown-linux-gnu ]] && targets+=("$host")
  for t in "${targets[@]}"; do
    linux_build "$t" release
    local smoke=""
    [[ $t == "$host" ]] && smoke=smoke
    package "$t" "${CARGO_TARGET_DIR:-$ROOT/target}/$t/release" "$version" "$smoke"
    local pkg
    for pkg in $("$BUILD_DIR/linux-packages.sh" "${CARGO_TARGET_DIR:-$ROOT/target}/$t/release" "$t" "$version"); do
      add_sum "$pkg"
    done
  done
}

native_main() {
  local cmd=${1:-help}
  shift || true
  case $cmd in
    doctor) native_doctor ;;
    build)
      local profile=debug target
      target=$(host_target)
      while (($#)); do
        case $1 in
          --release) profile=release ;;
          --target) target=${2:?--target needs a value}; shift ;;
          *) die "build: unknown option $1" ;;
        esac
        shift
      done
      linux_build "$target" "$profile"
      ;;
    test) ensure_nextest; say "tests ($(host_target))"; cargo nextest run --workspace --all-features --locked ;;
    check) ensure_nextest; run_checks; say "all checks passed" ;;
    release) native_release "$@" ;;
    clean) cargo clean ;;
    *) die "unknown command '$cmd' for --native (see --help)" ;;
  esac
}

# ------------------------------------------------------------------------- container mode

container_tool() {
  if [[ -n ${SCRIBE_CTR:-} ]]; then echo "$SCRIBE_CTR"; return; fi
  if [[ $(uname -s) == Darwin ]] && command -v container >/dev/null; then echo container; return; fi
  for t in docker podman; do
    if command -v "$t" >/dev/null && "$t" info >/dev/null 2>&1; then echo "$t"; return; fi
  done
  die "no container tool: install Apple container (macOS), docker or podman, or use --native on Linux"
}

default_arch() {
  case $(uname -m) in arm64 | aarch64) echo arm64 ;; *) echo amd64 ;; esac
}

image_tag() { echo "$LINUX_IMAGE:$ARCH"; }

image_exists() {
  local ctr=$1
  case $ctr in
    container) container image inspect "$(image_tag)" >/dev/null 2>&1 ;;
    *) "$ctr" image inspect "$(image_tag)" >/dev/null 2>&1 ;;
  esac
}

build_image() {
  local ctr=$1 rebuild=${2:-}
  if [[ -z $rebuild ]] && image_exists "$ctr"; then return; fi
  say "building image $(image_tag) from $LINUX_BASE_IMAGE with $ctr"
  local args=(build -f "$BUILD_DIR/linux.Containerfile" -t "$(image_tag)"
    --build-arg "BASE=$LINUX_BASE_IMAGE" --build-arg "MSRV=$(msrv)"
    --build-arg "NEXTEST_VERSION=$NEXTEST_VERSION")
  case $ctr in
    container) args+=(--arch "$ARCH" -c "$CONTAINER_CPUS" -m "$CONTAINER_MEMORY") ;;
    *) args+=(--platform "linux/$ARCH") ;;
  esac
  [[ -n $rebuild ]] && args+=(--no-cache)
  "$ctr" "${args[@]}" "$BUILD_DIR"
}

# A named volume keeps the cargo registry between runs. `run -v <name>:…` creates it on first use
# (Apple container then logs a harmless `volumeAlreadyExists` on later runs).
registry_volume() { echo "scribe-cargo-registry-$ARCH"; }

# run_in <tool> [-it] <command...>: run a command in the build container with the repository at /src.
run_in() {
  local ctr=$1
  shift
  local tty=() privileged=()
  if [[ ${1:-} == -it ]]; then tty=(-i -t); shift; fi
  if [[ ${1:-} == --privileged ]]; then
    case $ctr in
      container) privileged=(--cap-add ALL) ;;
      *) privileged=(--privileged) ;;
    esac
    shift
  fi
  local volume
  volume=$(registry_volume)
  local args=(run --rm "${tty[@]}" "${privileged[@]}" -v "$ROOT:/src" -v "$volume:/usr/local/cargo/registry" -w /src
    -e "CARGO_TARGET_DIR=/src/target/linux-$ARCH"
    -e "SCRIBE_VERSION=$(build_version)"
    -e "CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-always}")
  case $ctr in
    container) args+=(--arch "$ARCH" -c "$CONTAINER_CPUS" -m "$CONTAINER_MEMORY") ;;
    *) args+=(--platform "linux/$ARCH") ;;
  esac
  "$ctr" "${args[@]}" "$(image_tag)" "$@"
}

container_main() {
  local cmd=${1:-help} ctr
  shift || true
  case $cmd in
    help | -h | --help) usage; return ;;
  esac
  ctr=$(container_tool)
  case $cmd in
    image) build_image "$ctr" "${1:-}" ;;
    doctor)
      say "container tool: $ctr, image $(image_tag) ($LINUX_BASE_IMAGE)"
      build_image "$ctr"
      run_in "$ctr" scripts/build/linux.sh --native doctor
      ;;
    shell) build_image "$ctr"; run_in "$ctr" -it bash ;;
    run) build_image "$ctr"; run_in "$ctr" "$@" ;;
    clean) rm -rf "$ROOT/target/linux-$ARCH" ;;
    build | test | check | release)
      build_image "$ctr"
      run_in "$ctr" scripts/build/linux.sh --native "$cmd" "$@"
      ;;
    *) die "unknown command '$cmd' (see --help)" ;;
  esac
}

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }

main() {
  cd "$ROOT"
  local args=()
  while (($#)); do
    case $1 in
      --native) NATIVE=1 ;;
      --arch) ARCH=${2:?--arch needs arm64 or amd64}; shift ;;
      *) args+=("$1") ;;
    esac
    shift
  done
  set -- "${args[@]+"${args[@]}"}"
  if [[ -n $NATIVE ]]; then
    native_main "$@"
  else
    ARCH=${ARCH:-$(default_arch)}
    container_main "$@"
  fi
}

main "$@"
