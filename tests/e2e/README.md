# End-to-end tests

Run before a release on clean lab VMs, as root / Administrator, against installed packages. They need
the local API and CLI from plan phase 10 (`--json` output, `scribe daemon`, `scribe modules`) and the
installers from phase 13, so they fail until then. The *previous* package must also be a release
with the local API.

| Script | Packages | Service |
|---|---|---|
| `linux/run.sh <previous> <new> [--purge]` | `.deb` / `.rpm` | systemd `scribed` |
| `macos/run.sh <previous.pkg> <new.pkg> [--purge]` | notarized `.pkg` | launchd `com.scribe.daemon`; extension pre-approved by MDM profile |
| `windows/run.ps1 -Previous <msi> -Package <msi> [-Purge]` | MSI | Windows service `scribed` |

Each script:
1. Installs the **previous** release, learns the lab traffic, switches to caution.
2. **Upgrades** to the new package and checks hosts, baseline and mode survived, the database
   reached `SCHEMA_VERSION`, the installed config passes `scribed --check-config` and the URL module runs.
3. Checks security: `scribe` / `scribe-admin` groups, file modes (`0600` / `0640`), the API socket
   directory and the hardened systemd unit (Linux); no user-writable config (Windows).
4. Caution mode: plaintext (with its URL note) and raw-IP traffic alert; the known TLS host doesn't.
5. Alert mode: a new host alerts.
6. Daemon commands: `hibernate --for 1m` raises `hibernated` and records nothing; `wakeup` resumes;
   `reset --counters` (Linux) clears runtime counters but not stored ones.
7. Uninstalls: service and binaries gone; data kept unless `--purge` / `-Purge` (on Windows,
   `scribe.toml`, `data\` and `logs\` next to the app are kept).

Waits poll for up to 15 seconds instead of sleeping. Needs `jq`, `sqlite3`, `curl` and `nc`
(Linux, macOS).

**Targets** come from `traffic.env` and must be lab servers; the scripts refuse to run while one is
empty, so a run never reaches the public internet by accident.
