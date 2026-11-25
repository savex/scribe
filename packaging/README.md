# Running scribed as a service

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
