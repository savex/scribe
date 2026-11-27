#!/bin/sh
# scribe package, before its files are unpacked (deb preinst, rpm %pre): the groups `scribe` (may
# read the API) and `scribe-admin` (may also control scribed), and the system user `scribe` that
# scribed continues as after opening the sensor (`[daemon] user`). Kept when they exist.
set -e
getent group scribe >/dev/null || groupadd --system scribe
getent group scribe-admin >/dev/null || groupadd --system scribe-admin
if ! getent passwd scribe >/dev/null; then
  useradd --system --gid scribe --home-dir /var/lib/scribe --no-create-home \
    --shell "$(command -v nologin || echo /bin/false)" --comment "scribe daemon" scribe
fi
