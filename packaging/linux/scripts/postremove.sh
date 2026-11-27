#!/bin/sh
# scribe package, after its files are gone (deb postrm, rpm %postun). A deb purge also removes the
# config, data, logs, the user and the groups; a plain remove (and rpm -e) keeps them.
set -e
if [ "$1" = purge ]; then
  rm -rf /etc/scribe /var/lib/scribe /var/log/scribe /run/scribe
  if getent passwd scribe >/dev/null; then userdel scribe; fi
  if getent group scribe-admin >/dev/null; then groupdel scribe-admin; fi
  if getent group scribe >/dev/null; then groupdel scribe; fi
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
