#!/usr/bin/env bash
# Installs or removes scribed as a systemd service by hand, for systems without the .deb / .rpm
# packages (scripts/build/linux-packages.sh); refused while the package is installed. Run as root.
#
#   scripts/install/linux.sh install [--from <dir>] [--as-root] [--no-join] [--dry-run]
#   scripts/install/linux.sh uninstall [--purge] [--dry-run]
#
# install    scribed and scribe to /usr/bin, the config to /etc/scribe/scribe.toml (kept if it is
#            there), the groups `scribe` (may read the API) and `scribe-admin` (may also control
#            scribed), the system user `scribe` that scribed continues as after opening the sensor
#            (`[daemon] user`; --as-root leaves it running as root), /var/lib/scribe and
#            /var/log/scribe owned by it, /run/scribe (root:scribe 0750, recreated at boot by
#            systemd-tmpfiles), the systemd unit, enabled and started. Run it again to upgrade.
#            The `scribe notify` user unit goes to /etc/systemd/user/ (each user enables it).
# uninstall  stops and removes the service, the units and the binaries; keeps the config, data,
#            logs, user and groups unless --purge.
# --from     the folder with scribed and scribe: an extracted release archive (the default when
#            this script sits in one), else this repository's release build (target/release,
#            target/<host>/release or the build container's target/linux-<arch>/<host>/release),
#            which must be of this checkout (rebuild it otherwise).
# --no-join  don't add the person who ran sudo to the scribe group (added by default).
# --dry-run  prints the commands instead of running them.
#
# Add other people to the groups with `usermod -aG scribe <name>` (they log in again to get it).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." 2>/dev/null && pwd || echo "$HERE")
BIN=/usr/bin
ETC=/etc/scribe
DATA=/var/lib/scribe
LOGS=/var/log/scribe
UNIT=/etc/systemd/system/scribed.service
USER_UNIT=/etc/systemd/user/scribe-notify.service
TMPFILES=/etc/tmpfiles.d/scribe.conf
ACCOUNT=scribe

DRY=""
say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
run() {
  if [[ -n $DRY ]]; then printf '    %s\n' "$*"; else "$@"; fi
}

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# The folder holding scribed and scribe.
find_bins() {
  local from=$1 host
  if [[ -n $from ]]; then
    [[ -x $from/scribed && -x $from/scribe ]] || die "no scribed and scribe in $from"
    echo "$from"; return
  fi
  host="$(uname -m)-unknown-linux-gnu"
  local dir
  for dir in "$HERE" "$ROOT/target/release" "$ROOT/target/$host/release" "$ROOT"/target/linux-*/"$host"/release; do
    if [[ -x $dir/scribed && -x $dir/scribe ]]; then echo "$dir"; return; fi
  done
  die "no scribed found: pass --from <dir> (a release archive), or build with scripts/build/linux.sh build --release"
}

# A file from the release archive (<from>/<archive path>) or this repository (<repo path>).
find_file() {
  local from=$1 archive=$2 repo=$3
  if [[ -f $from/$archive ]]; then echo "$from/$archive"
  elif [[ -f $ROOT/$repo ]]; then echo "$ROOT/$repo"
  else die "$archive not found next to the binaries or in this repository ($repo)"
  fi
}

# A build left in target/ by an older checkout installs old code: its version must be this
# checkout's. Only for builds found in this repository; --from installs what it is given.
check_fresh() {
  local bins=$1 have want
  [[ -x $ROOT/scripts/version.sh && $bins == "$ROOT"/target/* ]] || return 0
  have=$("$bins/scribed" --version | awk '{ print $2 }')
  # As the person who ran sudo: git refuses a repository that belongs to someone else.
  if [[ $(id -u) == 0 && -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    want=$(sudo -u "$SUDO_USER" "$ROOT/scripts/version.sh" current 2>/dev/null) || want=""
  else
    want=$("$ROOT/scripts/version.sh" current 2>/dev/null) || want=""
  fi
  want=${want%.dirty}
  want=${want%+dirty}
  if [[ -z $want ]]; then
    echo "    note: can't tell this checkout's version; installing scribed $have"
  elif [[ $have != "$want" ]]; then
    die "$bins holds scribed $have, but this checkout is $want: rebuild (scripts/build/linux.sh build --release) or pass --from $bins to install it anyway"
  fi
}

# The person who ran `sudo … install` may read scribed's status without sudo.
join_group() {
  local who=${SUDO_USER:-}
  [[ -n $who && $who != root ]] || return 0
  if id -nG "$who" 2>/dev/null | tr ' ' '\n' | grep -qx scribe; then return 0; fi
  run usermod -aG scribe "$who"
  echo "    added $who to the scribe group (log in again for it to apply; --no-join skips this)"
}

need_root() {
  [[ -n $DRY || $(id -u) == 0 ]] || die "run as root (sudo $0 $*)"
}

# The .deb / .rpm puts the same files elsewhere (/usr/lib/systemd) and removes them itself.
no_package() {
  if dpkg-query -W -f='${Status}' scribe 2>/dev/null | grep -q 'ok installed' || rpm -q scribe >/dev/null 2>&1; then
    die "the scribe package is installed: upgrade or remove it with apt / dnf (or remove it first)"
  fi
}

need_systemd() {
  [[ -n $DRY || -d /run/systemd/system ]] || die "systemd is not running here; start scribed another way (see packaging/README.md)"
}

install_scribed() {
  local from="" as_root="" join=1
  while [[ $# -gt 0 ]]; do
    case $1 in
      --from) from=${2:?--from needs a folder}; shift 2 ;;
      --as-root) as_root=1; shift ;;
      --no-join) join=""; shift ;;
      --dry-run) DRY=1; shift ;;
      *) usage 2 ;;
    esac
  done
  need_root install
  need_systemd
  [[ -n $DRY ]] || no_package
  local bins unit user_unit config owner
  bins=$(find_bins "$from")
  [[ -n $from ]] || check_fresh "$bins"
  unit=$(find_file "$bins" service/scribed.service packaging/linux/scribed.service)
  user_unit=$(find_file "$bins" service/scribe-notify.service packaging/linux/scribe-notify.service)
  config=$(find_file "$bins" scribe.toml config/scribe.toml)
  say "installing $("$bins/scribed" --version) from $bins"

  say "groups and user"
  getent group scribe >/dev/null || run groupadd --system scribe
  getent group scribe-admin >/dev/null || run groupadd --system scribe-admin
  [[ -z $join ]] || join_group
  owner=root
  if [[ -z $as_root ]]; then
    owner=$ACCOUNT
    if ! id -u "$ACCOUNT" >/dev/null 2>&1; then
      run useradd --system --gid scribe --home-dir "$DATA" --no-create-home \
        --shell "$(command -v nologin || echo /bin/false)" "$ACCOUNT"
    fi
  fi

  if systemctl is-active --quiet scribed 2>/dev/null; then
    say "stopping the running scribed"
    run systemctl stop scribed
  fi

  say "binaries to $BIN"
  run install -m 0755 -o root -g root "$bins/scribed" "$bins/scribe" "$BIN/"

  say "config $ETC/scribe.toml"
  run install -d -m 0755 -o root -g root "$ETC"
  if [[ -e $ETC/scribe.toml ]]; then
    echo "    kept (it exists)"
    if [[ -z $as_root ]] && ! grep -Eq '^[[:space:]]*user[[:space:]]*=[[:space:]]*"'"$ACCOUNT"'"' "$ETC/scribe.toml"; then
      echo "    note: set user = \"$ACCOUNT\" under [daemon] in it for scribed to leave root"
    fi
  else
    run install -m 0640 -o root -g scribe "$config" "$ETC/scribe.toml"
    if [[ -z $as_root ]]; then
      run sed -i "s/^# user = \"scribe\"$/user = \"$ACCOUNT\"/" "$ETC/scribe.toml"
    fi
  fi
  # Readable by scribed after it left root (reload with SIGHUP), not writable by anyone else.
  run chown root:scribe "$ETC/scribe.toml"
  run chmod 0640 "$ETC/scribe.toml"

  say "data $DATA, logs $LOGS, socket folder /run/scribe"
  run install -d -m 0750 -o "$owner" -g scribe "$DATA" "$LOGS"
  # Data written while scribed ran as root must belong to the user it now continues as.
  run chown -R "$owner:scribe" "$DATA" "$LOGS"
  if [[ -n $DRY ]]; then
    printf '    write %s: d /run/scribe 0750 root scribe -\n' "$TMPFILES"
  else
    printf '# scribed API socket folder: members of the scribe group may connect.\nd /run/scribe 0750 root scribe -\n' >"$TMPFILES"
  fi
  run systemd-tmpfiles --create "$TMPFILES"

  say "systemd units"
  run install -m 0644 -o root -g root "$unit" "$UNIT"
  run install -d -m 0755 "$(dirname "$USER_UNIT")"
  run install -m 0644 -o root -g root "$user_unit" "$USER_UNIT"
  run systemctl daemon-reload
  run systemctl enable --now scribed

  if [[ -z $DRY ]]; then
    local i
    for i in $(seq 30); do
      systemctl is-active --quiet scribed && [[ -S /run/scribe/api.sock ]] && break
      sleep 1
    done
    systemctl is-active --quiet scribed || { systemctl status scribed --no-pager || true; die "scribed did not start (journalctl -u scribed)"; }
  fi
  say "scribed is running as ${owner}"
  echo "    status:        scribe status   (as root, or a member of the scribe group)"
  echo "    give access:   usermod -aG scribe <name>   (scribe-admin for control calls)"
  echo "    notifications: systemctl --user enable --now scribe-notify   (as each desktop user)"
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
  [[ -n $DRY ]] || no_package
  say "stopping and removing the service"
  if [[ -n $DRY ]] || systemctl list-unit-files scribed.service >/dev/null 2>&1; then
    run systemctl disable --now scribed || true
  fi
  run rm -f "$UNIT" "$USER_UNIT" "$TMPFILES"
  [[ -n $DRY || -d /run/systemd/system ]] && run systemctl daemon-reload
  run rm -f "$BIN/scribed" "$BIN/scribe"
  if [[ -n $purge ]]; then
    say "removing config, data, logs, the user and the groups"
    run rm -rf "$ETC" "$DATA" "$LOGS" /run/scribe
    if [[ -n $DRY ]] || id -u "$ACCOUNT" >/dev/null 2>&1; then run userdel "$ACCOUNT"; fi
    if [[ -n $DRY ]] || getent group scribe-admin >/dev/null; then run groupdel scribe-admin; fi
    if [[ -n $DRY ]] || getent group scribe >/dev/null; then run groupdel scribe; fi
  else
    echo "    kept: $ETC, $DATA, $LOGS, the user $ACCOUNT and the groups (--purge removes them)"
  fi
  say "scribed removed"
}

case ${1:-} in
  install) shift; install_scribed "$@" ;;
  uninstall) shift; uninstall_scribed "$@" ;;
  -h | --help | help) usage ;;
  *) usage 2 ;;
esac
