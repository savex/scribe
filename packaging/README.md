# Running scribed as a service

| System | File | Install |
|---|---|---|
| Linux (systemd) | [linux/scribed.service](linux/scribed.service) | copy to `/etc/systemd/system/`, `systemctl enable --now scribed` |
| macOS (launchd) | [macos/io.github.savex.scribed.plist](macos/io.github.savex.scribed.plist) | copy to `/Library/LaunchDaemons/`, `launchctl bootstrap system <file>` |
| Windows | [windows/install-service.ps1](windows/install-service.ps1) | run as Administrator next to `scribed.exe` |

- **systemd:** `Type=notify`: scribed reports `READY=1` when it captures and `STOPPING=1` when it stops.
  `systemctl reload scribed` sends SIGHUP, which re-reads the config.
- **launchd:** runs scribed in the foreground and stops it with SIGTERM.
- **Windows:** the service runs `scribed.exe --service`; Stop and system shutdown end it cleanly.
- **Privileges (Unix):** `[daemon] user = "scribe"` makes scribed continue as that user once storage and the
  sensor are open. `data_dir` must belong to it.

The packages of plan phase 13 install these files with a hardened unit, the `scribe` and `scribe-admin`
groups and the right file modes.
