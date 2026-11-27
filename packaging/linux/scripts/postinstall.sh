#!/bin/sh
# scribe package, after its files are in place (deb postinst, rpm %post): data and log folders for
# the user `scribe`, the socket folder, then the service: enabled and started on a first install,
# restarted if it runs on an upgrade. Without systemd (containers) only the folders.
set -e
# deb: `configure <version before, empty on a first install>`; rpm: 1 = install, 2 or more = upgrade.
case "$1" in
  configure) upgrade=${2:+1} ;;
  [0-9]*) if [ "$1" -gt 1 ]; then upgrade=1; else upgrade=""; fi ;;
  *) exit 0 ;;
esac

install -d -m 0750 -o scribe -g scribe /var/lib/scribe /var/log/scribe
# Files written while scribed ran as root belong to the user it continues as.
chown -R scribe:scribe /var/lib/scribe /var/log/scribe

if [ -d /run/systemd/system ]; then
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/scribe.conf || true
  systemctl daemon-reload || true
  if [ -n "$upgrade" ]; then
    systemctl try-restart scribed.service || echo "scribed did not restart: journalctl -u scribed" >&2
  else
    systemctl enable --now scribed.service || echo "scribed did not start: journalctl -u scribed" >&2
  fi
fi
