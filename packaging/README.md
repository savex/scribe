# Running scribed as a service

**Linux packages:** each release has a `.deb` and an `.rpm` (x86_64), built with nfpm from
[`linux/nfpm.yaml`](linux/nfpm.yaml) by `scripts/build/linux-packages.sh` (also part of
`scripts/build/linux.sh release`). They need glibc 2.39 or newer (Ubuntu 24.04, Debian 13, Fedora 40)
and put the files where the table below says, with the units in `/usr/lib/systemd/` and
`/usr/lib/tmpfiles.d/scribe.conf`:

```sh
sudo apt install ./scribe_<version>_amd64.deb      # or: sudo dnf install ./scribe-<version>.x86_64.rpm
sudo apt remove scribe                             # keeps config, data and logs; `apt purge` removes them,
                                                   # the user and the groups (rpm -e keeps them)
```

The package creates the groups and the user `scribe`, ships the config with `user = "scribe"` (kept on
upgrades as a changed config file), and enables and starts scribed on a first install (on an upgrade it
restarts it if it runs; without systemd, as in containers, it only puts the files in place). The install
scripts below refuse to run while the package is installed.

**The quick way without packages:** the install scripts put everything in place, from a release archive
(`install.sh` / `install.ps1` in it) or from this repository's release build, and take it out again. On
macOS and Windows they stand in for the `.pkg` and the MSI of plan phase 13.

```sh
sudo scripts/install/linux.sh install      # systemd; scribed continues as the user `scribe`
sudo scripts/install/macos.sh install      # launchd; scribed runs as root (pcap)
sudo scripts/install/linux.sh uninstall    # keeps config, data and logs; --purge removes them
```

```powershell
scripts\install\windows.ps1 install      # Administrator; C:\Program Files\scribe, NT SERVICE\scribed
scripts\install\windows.ps1 uninstall    # -Purge also removes config, data, logs and the groups
```

| | Linux | macOS | Windows |
|---|---|---|---|
| Programs | `/usr/bin` | `/usr/local/bin` | `C:\Program Files\scribe` (on the PATH) |
| Config | `/etc/scribe/scribe.toml` (`root:scribe 0640`) | `/Library/Application Support/scribe/scribe.toml` | next to the programs |
| Data / logs | `/var/lib/scribe`, `/var/log/scribe` (user `scribe`) | `/Library/Application Support/scribe`, `/var/log/scribe` | `data\`, `logs\` next to the programs |
| API socket | `/run/scribe` (`root:scribe 0750`, `tmpfiles.d`) | `/var/run/scribe` (group set by scribed) | `\\.\pipe\scribed` |

All three create the groups `scribe` (may read the API: `scribe status`, `hosts`, `alerts`) and `scribe-admin`
(may also control scribed), keep an existing config when run again (upgrade), and install the `scribe notify`
unit, agent or script for each user to enable. Options: `--from <dir>` / `-From` (where the binaries are),
`--as-root` (Linux), `-LocalSystem` and `-Dir` (Windows), `--dry-run` (Linux, macOS). Sensor tests run all
three on GitHub's runners; on Ubuntu they also install, upgrade and purge the `.deb` and install and
remove the `.rpm` in a Fedora container (`scripts/ci/package-check.sh`).

**By hand**, with the service files:

| System | File | Install |
|---|---|---|
| Linux (systemd) | [linux/scribed.service](linux/scribed.service) | copy to `/etc/systemd/system/`, `systemctl enable --now scribed` |
| macOS (launchd) | [macos/io.github.savex.scribed.plist](macos/io.github.savex.scribed.plist) | copy to `/Library/LaunchDaemons/`, `launchctl bootstrap system <file>` |
| Windows | [windows/install-service.ps1](windows/install-service.ps1) | run as Administrator next to `scribed.exe` |

- **systemd:** `Type=notify`: scribed reports `READY=1` when it captures and `STOPPING=1` when it stops.
  `systemctl reload scribed` sends SIGHUP, which re-reads the config.
- **launchd:** runs scribed in the foreground and stops it with SIGTERM.
- **Windows:** the service runs `scribed.exe --service` as its virtual account `NT SERVICE\scribed` (in
  Performance Log Users for the ETW session; reads its folder, writes `data` and `logs`; `-Writable` adds
  folders for a `data_dir` or log file elsewhere). `-LocalSystem` installs it as LocalSystem instead, e.g. when
  Npcap is restricted to Administrators. Stop and system shutdown end it cleanly.
- **Privileges (Unix):** `[daemon] user = "scribe"` makes scribed continue as that user once storage and the
  sensor are open. `data_dir` must belong to it.

The packages of plan phase 13 install these files with a hardened unit, the `scribe` and `scribe-admin`
groups and the right file modes.

## Desktop notifications (`scribe notify`)

scribed runs as a system service, which can't show notifications in a desktop session on any of the
three systems. `scribe notify` runs in the user's session instead: it follows scribed's alert stream
and shows one notification per alert (at most 10 a minute by default, the rest as one summary),
waits while scribed is down and, after a reconnect, shows what it missed. The user must be able to
read scribed's socket (the `scribe` group).

| System | File | Install (as the desktop user) |
|---|---|---|
| Linux (systemd user unit) | [linux/scribe-notify.service](linux/scribe-notify.service) | copy to `/etc/systemd/user/`, `systemctl --user enable --now scribe-notify` |
| macOS (launchd agent) | [macos/io.github.savex.scribe-notify.plist](macos/io.github.savex.scribe-notify.plist) | copy to `/Library/LaunchAgents/`, `launchctl bootstrap gui/$(id -u) <file>` |
| Windows (logon) | [windows/install-notify.ps1](windows/install-notify.ps1) | run next to `scribe.exe`, no Administrator needed |

`scribe notify --print` prints the notifications instead, to check a setup.
