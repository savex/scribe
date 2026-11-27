#!/usr/bin/env bash
# Sensors workflow, Ubuntu (sudo, systemd, docker): the .deb and .rpm from
# scripts/build/linux-packages.sh.
#   .deb on this runner: apt installs it with its dependencies, scribed runs as `scribe` with the
#        config root:scribe 0640, a member of the scribe group reads its status, a reinstall keeps
#        the changed config and restarts scribed, `apt-get purge` leaves nothing behind.
#   .rpm in a Fedora container (no systemd there): dnf installs it with its dependencies, the user,
#        groups, folders and config modes are in place, scribed accepts the config, `rpm -e`
#        removes the programs and keeps the data.
#
#   package-check.sh <folder with scribed and scribe>
set -euo pipefail

FEDORA=fedora:44
bins=$(cd "$1" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)
me=$(id -un)
fail() { echo "::error::$*"; exit 1; }

[[ $(uname -s) == Linux && -d /run/systemd/system ]] || fail "package-check.sh needs Linux with systemd"
dpkg-query -W scribe >/dev/null 2>&1 && fail "a scribe package is already installed"
[[ ! -e /usr/bin/scribed ]] || fail "/usr/bin/scribed exists (a manual install?)"

rm -f "$root"/dist/scribe_*.deb "$root"/dist/scribe-*.rpm
mapfile -t pkgs < <("$root/scripts/build/linux-packages.sh" "$bins" x86_64-unknown-linux-gnu)
deb=$(printf '%s\n' "${pkgs[@]}" | grep '\.deb$')
rpm=$(printf '%s\n' "${pkgs[@]}" | grep '\.rpm$')
dpkg-deb --info "$deb"
dpkg-deb --contents "$deb"

cleanup() {
  local status=$?
  if [[ $status != 0 ]]; then
    echo "--- logs"
    sudo journalctl -u scribed --no-pager -n 60 || true
  fi
  sudo apt-get purge -y -q scribe >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

echo "::group::.deb install"
sudo apt-get install -y -q "$deb"
echo "::endgroup::"
for i in $(seq 30); do
  systemctl is-active --quiet scribed && [[ -S /run/scribe/api.sock ]] && break
  sleep 1
done
systemctl is-active --quiet scribed || fail "scribed is not running after the install"
systemctl is-enabled --quiet scribed || fail "scribed is not enabled"
owner=$(ps -o user= -C scribed | head -1 | tr -d ' ')
[[ $owner == scribe ]] || fail "scribed runs as '$owner', not scribe"
[[ $(sudo stat -c '%U:%G %a' /etc/scribe/scribe.toml) == "root:scribe 640" ]] \
  || fail "/etc/scribe/scribe.toml is $(sudo stat -c '%U:%G %a' /etc/scribe/scribe.toml)"
sudo grep -q '^user = "scribe"$' /etc/scribe/scribe.toml || fail 'the config does not set user = "scribe"'
[[ $(stat -c '%U:%G %a' /var/lib/scribe) == "scribe:scribe 750" ]] || fail "/var/lib/scribe is $(stat -c '%U:%G %a' /var/lib/scribe)"
[[ $(stat -c '%G' /run/scribe) == scribe ]] || fail "/run/scribe belongs to group $(stat -c '%G' /run/scribe)"
getent group scribe-admin >/dev/null || fail "no group scribe-admin"

# A new login (sudo -u) picks up the group the running session doesn't have yet.
sudo usermod -aG scribe "$me"
status=$(sudo -u "$me" scribe status)
echo "$status"
grep -q '^sensor ' <<<"$status" || fail "a member of the scribe group cannot read scribed's status"

echo "::group::.deb reinstall (upgrade path)"
echo "# kept across upgrades" | sudo tee -a /etc/scribe/scribe.toml >/dev/null
pid=$(systemctl show -p MainPID --value scribed)
sudo apt-get install -y -q --reinstall -o Dpkg::Options::=--force-confold "$deb"
echo "::endgroup::"
sudo grep -q 'kept across upgrades' /etc/scribe/scribe.toml || fail "the upgrade replaced the config"
for i in $(seq 30); do
  [[ -S /run/scribe/api.sock ]] && sudo -u "$me" scribe status >/dev/null 2>&1 && break
  sleep 1
done
[[ $(systemctl show -p MainPID --value scribed) != "$pid" ]] || fail "scribed was not restarted by the upgrade"
sudo -u "$me" scribe status >/dev/null || fail "scribed did not come back after the upgrade"

echo "::group::.deb purge"
sudo apt-get purge -y -q scribe
echo "::endgroup::"
! systemctl is-active --quiet scribed || fail "scribed still runs after the purge"
for p in /usr/bin/scribed /usr/bin/scribe /usr/lib/systemd/system/scribed.service /etc/scribe /var/lib/scribe /var/log/scribe; do
  sudo test ! -e "$p" || fail "$p left after the purge"
done
! getent passwd scribe >/dev/null || fail "user scribe left"
! getent group scribe >/dev/null || fail "group scribe left"
! getent group scribe-admin >/dev/null || fail "group scribe-admin left"
echo ".deb check passed"

echo "::group::.rpm in $FEDORA"
docker run --rm -v "$(dirname "$rpm"):/dist:ro" "$FEDORA" bash -euc '
  fail() { echo "::error::$*"; exit 1; }
  dnf install -y -q "/dist/'"$(basename "$rpm")"'"
  rpm -qi scribe
  id scribe
  getent group scribe-admin >/dev/null || fail "no group scribe-admin"
  [[ $(stat -c "%U:%G %a" /etc/scribe/scribe.toml) == "root:scribe 640" ]] || fail "config is $(stat -c "%U:%G %a" /etc/scribe/scribe.toml)"
  [[ $(stat -c "%U:%G %a" /var/lib/scribe) == "scribe:scribe 750" ]] || fail "/var/lib/scribe is $(stat -c "%U:%G %a" /var/lib/scribe)"
  grep -q "^user = \"scribe\"$" /etc/scribe/scribe.toml || fail "the config does not set user = scribe"
  scribed --check-config --config /etc/scribe/scribe.toml >/dev/null || fail "scribed rejects the installed config"
  scribe --version
  rpm -e scribe
  [[ ! -e /usr/bin/scribed ]] || fail "scribed left after rpm -e"
  [[ -d /var/lib/scribe ]] || fail "rpm -e removed the data"
'
echo "::endgroup::"
echo ".rpm check passed"
echo "package check passed"
