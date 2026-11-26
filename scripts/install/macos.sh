#!/usr/bin/env bash
# Installs or removes scribed as a launchd daemon by hand, until the notarized .pkg of plan phase 13
# does it. Run with sudo.
#
#   scripts/install/macos.sh install [--from <dir>] [--dry-run]
#   scripts/install/macos.sh uninstall [--purge] [--dry-run]
#
# install    scribed and scribe to /usr/local/bin, the config to
#            /Library/Application Support/scribe/scribe.toml (kept if it is there; data lives in the
#            same folder), logs in /var/log/scribe and /Library/Logs/scribe, the groups `scribe` (may
#            read the API) and `scribe-admin` (may also control scribed), the LaunchDaemon, loaded
#            and running. Run it again to upgrade. The `scribe notify` LaunchAgent goes to
#            /Library/LaunchAgents/ (each user loads it). scribed runs as root: pcap needs /dev/bpf
#            each time capture starts again after hibernation.
# uninstall  stops and removes the daemon, the agent and the binaries; keeps the config, data, logs
#            and groups unless --purge.
# --from     the folder with scribed and scribe: an extracted release archive (the default when
#            this script sits in one), else this repository's release build
#            (target/<this Mac's arch>-apple-darwin/release, target/universal-apple-darwin/release,
#            target/release).
# --dry-run  prints the commands instead of running them.
#
# Add people to the groups with `sudo dseditgroup -o edit -a <name> -t user scribe`.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." 2>/dev/null && pwd || echo "$HERE")
BIN=/usr/local/bin
SUPPORT="/Library/Application Support/scribe"
LOGS=/var/log/scribe
STDERR_LOGS=/Library/Logs/scribe
LABEL=io.github.savex.scribed
DAEMON=/Library/LaunchDaemons/$LABEL.plist
AGENT=/Library/LaunchAgents/io.github.savex.scribe-notify.plist

DRY=""
say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
run() {
  if [[ -n $DRY ]]; then printf '    %s\n' "$*"; else "$@"; fi
}

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

find_bins() {
  local from=$1 arch dir
  if [[ -n $from ]]; then
    [[ -x $from/scribed && -x $from/scribe ]] || die "no scribed and scribe in $from"
    echo "$from"; return
  fi
  arch=$(uname -m)
  [[ $arch == arm64 ]] && arch=aarch64
  for dir in "$HERE" "$ROOT/target/$arch-apple-darwin/release" "$ROOT/target/universal-apple-darwin/release" "$ROOT/target/release"; do
    if [[ -x $dir/scribed && -x $dir/scribe ]]; then echo "$dir"; return; fi
  done
  die "no scribed found: pass --from <dir> (a release archive), or build with scripts/build/macos.sh build --release"
}

find_file() {
  local from=$1 archive=$2 repo=$3
  if [[ -f $from/$archive ]]; then echo "$from/$archive"
  elif [[ -f $ROOT/$repo ]]; then echo "$ROOT/$repo"
  else die "$archive not found next to the binaries or in this repository ($repo)"
  fi
}

need_root() {
  [[ -n $DRY || $(id -u) == 0 ]] || die "run with sudo (sudo $0 $1 …)"
}

loaded() { launchctl print "system/$LABEL" >/dev/null 2>&1; }

# bootout returns before launchd has let go of the job; bootstrap fails until it has.
unloaded() {
  [[ -n $DRY ]] && return
  local i
  for i in $(seq 40); do
    loaded || return 0
    sleep 0.25
  done
  die "launchd still has $LABEL loaded"
}

make_group() {
  local name=$1 what=$2
  if ! dseditgroup -o read "$name" >/dev/null 2>&1; then
    run dseditgroup -o create -r "$what" "$name"
  fi
}

install_scribed() {
  local from=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --from) from=${2:?--from needs a folder}; shift 2 ;;
      --dry-run) DRY=1; shift ;;
      *) usage 2 ;;
    esac
  done
  need_root install
  local bins daemon agent config
  bins=$(find_bins "$from")
  daemon=$(find_file "$bins" "service/$LABEL.plist" "packaging/macos/$LABEL.plist")
  agent=$(find_file "$bins" service/io.github.savex.scribe-notify.plist packaging/macos/io.github.savex.scribe-notify.plist)
  config=$(find_file "$bins" scribe.toml config/scribe.toml)
  say "installing $("$bins/scribed" --version) from $bins"
  if xattr -p com.apple.quarantine "$bins/scribed" >/dev/null 2>&1; then
    echo "    note: $bins/scribed is quarantined (downloaded, not notarized before phase 13);"
    echo "    if launchd can't start it, check System Settings → Privacy & Security"
  fi

  say "groups"
  make_group scribe "scribe API (read)"
  make_group scribe-admin "scribe API (control)"

  if loaded; then
    say "stopping the running scribed"
    run launchctl bootout "system/$LABEL"
    unloaded
  fi

  say "binaries to $BIN"
  run install -d -m 0755 -o root -g wheel "$BIN"
  run install -m 0755 -o root -g wheel "$bins/scribed" "$bins/scribe" "$BIN/"

  say "config and data in $SUPPORT"
  # Not writable by others (scribed refuses to start otherwise); clients only need the socket.
  run install -d -m 0750 -o root -g wheel "$SUPPORT"
  if [[ -e $SUPPORT/scribe.toml ]]; then
    echo "    config kept (it exists)"
  else
    run install -m 0640 -o root -g wheel "$config" "$SUPPORT/scribe.toml"
  fi
  run install -d -m 0750 -o root -g wheel "$LOGS" "$STDERR_LOGS"
  # /var/run is emptied at boot: scribed creates /var/run/scribe with the scribe group itself.
  if [[ -d /var/run/scribe ]]; then
    run chgrp scribe /var/run/scribe
  fi

  say "launchd"
  run install -m 0644 -o root -g wheel "$daemon" "$DAEMON"
  run install -m 0644 -o root -g wheel "$agent" "$AGENT"
  run launchctl bootstrap system "$DAEMON"

  if [[ -z $DRY ]]; then
    local i
    for i in $(seq 30); do
      [[ -S /var/run/scribe/api.sock ]] && break
      sleep 1
    done
    loaded && [[ -S /var/run/scribe/api.sock ]] ||
      die "scribed did not start: see $LOGS/ and $STDERR_LOGS/scribed.stderr.log"
  fi
  say "scribed is running"
  echo "    status:        scribe status   (with sudo, or as a member of the scribe group)"
  echo "    give access:   sudo dseditgroup -o edit -a <name> -t user scribe   (scribe-admin for control calls)"
  echo "    notifications: launchctl bootstrap gui/\$(id -u) $AGENT   (as each desktop user)"
}

uninstall_scribed() {
  local purge=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --purge) purge=1; shift ;;
      --dry-run) DRY=1; shift ;;
      *) usage 2 ;;
    esac
  done
  need_root uninstall
  say "stopping and removing the daemon"
  if [[ -n $DRY ]] || loaded; then
    run launchctl bootout "system/$LABEL"
    unloaded
  fi
  run rm -f "$DAEMON" "$AGENT" "$BIN/scribed" "$BIN/scribe"
  if [[ -n $purge ]]; then
    say "removing config, data, logs and the groups"
    run rm -rf "$SUPPORT" "$LOGS" "$STDERR_LOGS" /var/run/scribe
    if [[ -n $DRY ]] || dseditgroup -o read scribe-admin >/dev/null 2>&1; then run dseditgroup -o delete scribe-admin; fi
    if [[ -n $DRY ]] || dseditgroup -o read scribe >/dev/null 2>&1; then run dseditgroup -o delete scribe; fi
  else
    echo "    kept: $SUPPORT, $LOGS, $STDERR_LOGS and the groups (--purge removes them)"
  fi
  echo "    users who loaded the notify agent: launchctl bootout gui/\$(id -u)/io.github.savex.scribe-notify"
  say "scribed removed"
}

case ${1:-} in
  install) shift; install_scribed "$@" ;;
  uninstall) shift; uninstall_scribed "$@" ;;
  -h | --help | help) usage ;;
  *) usage 2 ;;
esac
