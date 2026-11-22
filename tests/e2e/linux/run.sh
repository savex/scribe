#!/bin/sh
# End-to-end test on Linux, as root, on a clean lab VM.
#   ./run.sh <previous release .deb|.rpm> <new .deb|.rpm> [--purge]
# Needs: jq, sqlite3, curl, nc. Targets come from ../traffic.env (lab servers only).
set -eu
PREV=${1:?usage: run.sh <previous package> <new package> [--purge]}
NEW=${2:?usage: run.sh <previous package> <new package> [--purge]}
PURGE=${3:-}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../traffic.env"
DATA=/var/lib/scribe
CONF=/etc/scribe/scribe.toml

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }
for v in TLS_HOST TLS_HOST_NEW PLAIN_HOST RAW_IP; do
  eval "[ -n \"\${$v}\" ]" || fail "$v is empty in traffic.env (point it at a lab server)"
done

# wait_for <description> <command...>: retry for up to 15 s.
wait_for() {
  what=$1; shift
  i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -ge 30 ] && fail "timed out: $what"
    sleep 0.5
  done
}
has_host()  { scribe hosts --json | jq -e --arg h "$1" 'any(.items[]; .name == $h)'; }
has_alert() { scribe alerts --json | jq -e --arg h "$1" 'any(.items[]; .host == $h or (.dst | startswith($h + ":")))'; }
alert_count() { scribe alerts --json | jq '.items | length'; }
mode_is()   { scribe daemon status --json | jq -e --arg m "$1" '.mode == $m'; }
state_is()  { scribe daemon status --json | jq -e --arg s "$1" '.run_state == $s'; }
install() {
  case "$1" in
    *.deb) apt-get install -y "$1" ;;
    *.rpm) dnf install -y "$1" ;;
    *) fail "unknown package type: $1" ;;
  esac
}
tls()   { curl -sS -o /dev/null "https://$1/" || true; }
plain() { curl -sS -o /dev/null "http://$PLAIN_HOST$PLAIN_PATH" || true; }
raw()   { printf 'x' | nc -w 2 "$RAW_IP" "$RAW_PORT" || true; }

step "install previous release"
install "$PREV"
wait_for "service active" systemctl is-active --quiet scribed
wait_for "daemon healthy" scribe daemon health

step "learn (previous release)"
scribe mode learn
tls "$TLS_HOST"; plain
wait_for "host $TLS_HOST tracked" has_host "$TLS_HOST"
wait_for "host $PLAIN_HOST tracked" has_host "$PLAIN_HOST"
[ "$(alert_count)" -eq 0 ] || fail "learn mode raised alerts"
scribe mode caution

step "upgrade to the new package"
install "$NEW"
wait_for "daemon healthy after upgrade" scribe daemon health
has_host "$TLS_HOST" >/dev/null || fail "hosts lost in the upgrade"
has_host "$PLAIN_HOST" >/dev/null || fail "hosts lost in the upgrade"
mode_is caution >/dev/null || fail "mode lost in the upgrade"
scribe baseline --json | jq -e --arg h "$TLS_HOST" 'any(.entries[]; .host == $h)' >/dev/null \
  || fail "baseline lost in the upgrade"
[ "$(sqlite3 "$DATA/state.db" 'PRAGMA user_version')" = "$SCHEMA_VERSION" ] || fail "state.db not migrated"
scribed --check-config --config "$CONF" | grep -q '^\[modules.url\]' || fail "installed config not valid"
scribe modules --json | jq -e 'any(.[]; .id == "url" and .state == "running")' >/dev/null \
  || fail "URL module not running"

step "security"
getent group scribe >/dev/null || fail "group scribe missing"
getent group scribe-admin >/dev/null || fail "group scribe-admin missing"
for f in "$CONF" "$DATA/state.db" "$DATA/events.db"; do
  mode=$(stat -c %a "$f")
  case "$mode" in 600|640) ;; *) fail "$f has mode $mode, expected 600 or 640" ;; esac
done
[ "$(stat -c %a /run/scribe)" = 750 ] || fail "/run/scribe is not 0750"
[ "$(systemctl show -p NoNewPrivileges --value scribed)" = yes ] || fail "unit lacks NoNewPrivileges"
[ "$(systemctl show -p ProtectSystem --value scribed)" = strict ] || fail "unit lacks ProtectSystem=strict"

step "caution"
tls "$TLS_HOST"; plain; raw
wait_for "plaintext alert for $PLAIN_HOST" has_alert "$PLAIN_HOST"
wait_for "alert for raw IP $RAW_IP" has_alert "$RAW_IP"
scribe alerts --json | jq -e --arg h "$PLAIN_HOST" \
  'any(.items[]; .host == $h and .reason == "plaintext" and (.notes.url | startswith("http://")))' >/dev/null \
  || fail "plaintext alert without its URL note"
has_alert "$TLS_HOST" >/dev/null && fail "known TLS host raised an alert"

step "alert"
scribe mode alert
tls "$TLS_HOST_NEW"
wait_for "alert for new host $TLS_HOST_NEW" has_alert "$TLS_HOST_NEW"

step "daemon commands"
scribe daemon hibernate --for 1m
wait_for "hibernating" state_is hibernating
scribe alerts --json | jq -e 'any(.items[]; .reason == "hibernated")' >/dev/null || fail "no hibernated alert"
before=$(scribe hosts --json | jq '[.items[].conn_count] | add')
tls "$TLS_HOST"; sleep 2
[ "$(scribe hosts --json | jq '[.items[].conn_count] | add')" = "$before" ] || fail "recorded while hibernating"
scribe daemon wakeup
wait_for "running again" state_is running
scribe daemon reset --counters
scribe daemon status --json | jq -e '.counters.flows == 0' >/dev/null || fail "reset kept runtime counters"
[ "$(scribe hosts --json | jq '[.items[].conn_count] | add')" = "$before" ] || fail "reset changed stored counters"

step "uninstall"
case "$NEW" in
  *.deb) if [ "$PURGE" = --purge ]; then apt-get purge -y scribe; else apt-get remove -y scribe; fi ;;
  *.rpm) dnf remove -y scribe; [ "$PURGE" = --purge ] && rm -rf "$DATA" /etc/scribe ;;
esac
systemctl list-unit-files | grep -q scribed && fail "service unit left behind"
command -v scribe >/dev/null && fail "cli left behind"
if [ "$PURGE" = --purge ]; then
  [ -e "$DATA" ] && fail "data left behind after --purge"
else
  [ -f "$DATA/state.db" ] || fail "data removed without --purge"
fi

echo "PASS"
