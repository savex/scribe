#!/bin/sh
# End-to-end test on Linux. Usage: sudo ./run.sh path/to/scribe.deb|rpm
set -eu
PKG=${1:?usage: run.sh <package>}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../traffic.env"

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }
expect_host() { scribe hosts | grep -q "$1" || fail "host $1 not tracked"; }
expect_alert() { scribe alerts | grep -q "$1" || fail "no alert for $1"; }

step "install"
case "$PKG" in
  *.deb) apt-get install -y "$PKG" ;;
  *.rpm) dnf install -y "$PKG" ;;
  *) fail "unknown package type: $PKG" ;;
esac
systemctl is-active --quiet scribed || fail "service not running"
scribe status | grep -q "health: ok" || fail "daemon not healthy"

step "learn"
scribe mode learn
curl -sS -o /dev/null "https://$TLS_HOST/"
curl -sS -o /dev/null "http://$PLAIN_HOST/"
sleep 2
expect_host "$TLS_HOST"
expect_host "$PLAIN_HOST"
scribe alerts | grep -q . && fail "learn mode raised alerts"

step "caution"
scribe mode caution
curl -sS -o /dev/null "https://$TLS_HOST/"
curl -sS -o /dev/null "http://$PLAIN_HOST/"
(printf 'x' | nc -w 2 "$RAW_IP" "$RAW_PORT" || true)
sleep 2
expect_alert "$PLAIN_HOST"
expect_alert "$RAW_IP"
scribe alerts | grep -q "$TLS_HOST" && fail "known TLS host raised an alert"

step "alert"
scribe mode alert
curl -sS -o /dev/null "https://$TLS_HOST_NEW/"
sleep 2
expect_alert "$TLS_HOST_NEW"

step "upgrade (reinstall)"
case "$PKG" in
  *.deb) apt-get install -y --reinstall "$PKG" ;;
  *.rpm) dnf reinstall -y "$PKG" ;;
esac
expect_host "$TLS_HOST"

step "uninstall"
case "$PKG" in
  *.deb) apt-get purge -y scribe ;;
  *.rpm) dnf remove -y scribe ;;
esac
systemctl list-unit-files | grep -q scribed && fail "service unit left behind"
command -v scribe >/dev/null && fail "cli left behind"

echo "PASS"
