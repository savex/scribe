#!/bin/sh
# End-to-end test on macOS. Usage: sudo ./run.sh path/to/scribe.pkg
# The lab Mac must have the MDM profile that pre-approves ScribeExtension.
set -eu
PKG=${1:?usage: run.sh <scribe.pkg>}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../traffic.env"

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }
expect_host() { scribe hosts | grep -q "$1" || fail "host $1 not tracked"; }
expect_alert() { scribe alerts | grep -q "$1" || fail "no alert for $1"; }

step "install"
installer -pkg "$PKG" -target /
launchctl print system/com.scribe.daemon >/dev/null || fail "daemon not loaded"
systemextensionsctl list | grep -q "activated enabled" || fail "network extension not active"
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
curl -sS -o /dev/null "http://$PLAIN_HOST/"
(printf 'x' | nc -G 2 "$RAW_IP" "$RAW_PORT" || true)
sleep 2
expect_alert "$PLAIN_HOST"
expect_alert "$RAW_IP"

step "alert"
scribe mode alert
curl -sS -o /dev/null "https://$TLS_HOST_NEW/"
sleep 2
expect_alert "$TLS_HOST_NEW"

step "upgrade (reinstall)"
installer -pkg "$PKG" -target /
expect_host "$TLS_HOST"

step "uninstall"
/Library/Application\ Support/scribe/uninstall.sh
launchctl print system/com.scribe.daemon >/dev/null 2>&1 && fail "daemon left behind"
command -v scribe >/dev/null && fail "cli left behind"

echo "PASS"
