#!/bin/sh
# scribe package, before its files are removed (deb prerm, rpm %preun): stop and disable scribed,
# unless this is an upgrade (deb `upgrade`, rpm 1 or more).
set -e
case "$1" in
  remove | 0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now scribed.service || true
    fi
    ;;
esac
