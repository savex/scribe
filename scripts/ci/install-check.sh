#!/usr/bin/env bash
# Sensors workflow, Linux and macOS (sudo): scripts/install/<system> installs scribed from a build,
# a member of the scribe group reads its status, a second install upgrades in place and
# `uninstall --purge` leaves nothing behind.
#
#   install-check.sh <folder with scribed and scribe>
set -euo pipefail

bins=$(cd "$1" && pwd)
case $(uname -s) in
  Linux) script=scripts/install/linux.sh bin=/usr/bin run=/run/scribe config=/etc/scribe/scribe.toml ;;
  Darwin) script=scripts/install/macos.sh bin=/usr/local/bin run=/var/run/scribe config="/Library/Application Support/scribe/scribe.toml" ;;
  *) echo "::error::install-check.sh is for Linux and macOS"; exit 1 ;;
esac
me=$(id -un)

fail() { echo "::error::$*"; exit 1; }
logs() {
  echo "--- logs"
  if [[ $(uname -s) == Linux ]]; then
    sudo journalctl -u scribed --no-pager -n 60 || true
  else
    sudo sh -c 'tail -n 60 /var/log/scribe/* /Library/Logs/scribe/* 2>/dev/null' || true
  fi
}
cleanup() {
  local status=$?
  [[ $status == 0 ]] || logs
  sudo "$script" uninstall --purge >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

sudo "$script" install --from "$bins"

# A new login (sudo -u) picks up the group the running session doesn't have yet.
if [[ $(uname -s) == Linux ]]; then
  sudo usermod -aG scribe "$me"
  owner=$(ps -o user= -C scribed | head -1 | tr -d ' ')
  echo "scribed runs as $owner"
  [[ $owner == scribe ]] || fail "scribed runs as '$owner', not scribe"
else
  sudo dseditgroup -o edit -a "$me" -t user scribe
fi
group=$(stat -c %G "$run" 2>/dev/null || stat -f %Sg "$run")
[[ $group == scribe ]] || fail "$run belongs to group '$group', not scribe"
status=$(sudo -u "$me" "$bin/scribe" status)
echo "$status"
grep -q '^sensor ' <<<"$status" || fail "a member of the scribe group cannot read scribed's status"

# Upgrade in place: the config stays.
echo "# kept across upgrades" | sudo tee -a "$config" >/dev/null
sudo "$script" install --from "$bins"
sudo grep -q 'kept across upgrades' "$config" || fail "the upgrade replaced $config"
sudo -u "$me" "$bin/scribe" status >/dev/null || fail "scribed did not come back after the upgrade"

sudo "$script" uninstall --purge
[[ ! -e $bin/scribed && ! -e $bin/scribe ]] || fail "binaries left in $bin"
sudo test ! -e "$config" || fail "$config left after --purge"
if [[ $(uname -s) == Linux ]]; then
  [[ ! -e /etc/systemd/system/scribed.service ]] || fail "unit left"
  ! id -u scribe >/dev/null 2>&1 || fail "user scribe left"
  ! getent group scribe >/dev/null || fail "group scribe left"
else
  [[ ! -e /Library/LaunchDaemons/io.github.savex.scribed.plist ]] || fail "LaunchDaemon left"
  ! dseditgroup -o read scribe >/dev/null 2>&1 || fail "group scribe left"
fi
echo "install check passed"
