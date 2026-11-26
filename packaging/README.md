# Running scribed as a service

**The quick way:** the install scripts put everything in place, from a release archive (`install.sh` /
`install.ps1` in it) or from this repository's release build, and take it out again. They stand in for
the packages of plan phase 13.

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
three on GitHub's runners.

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
