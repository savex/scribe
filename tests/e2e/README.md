# End-to-end tests

Run before a release on clean lab VMs, as root / Administrator, against an installed package.
They need the CLI commands from plan phase 10 (`status`, `hosts`, `mode`, `alerts`) and fail until then.

| Script | Package | Service |
|---|---|---|
| `linux/run.sh <scribe.deb\|scribe.rpm>` | `.deb` / `.rpm` | systemd `scribed` |
| `macos/run.sh <scribe.pkg>` | notarized `.pkg` | launchd `com.scribe.daemon`; extension pre-approved by MDM profile |
| `windows/run.ps1 -Package <scribe.msi>` | MSI | Windows service `scribed` |

Each script:
1. Installs the package and waits for the service to report healthy.
2. Learn mode: generates the traffic in `traffic.env`, checks every host shows up with counters.
3. Caution mode: plaintext and raw-IP traffic raise alerts; known TLS hosts don't.
4. Alert mode: a new host raises an alert.
5. Reinstalls the same package (upgrade path) and checks hosts and baseline survived.
6. Uninstalls and checks no service, binaries or files are left (data dir only if `--purge`).

Traffic targets are set in `traffic.env`; point them at lab servers to keep runs off the internet.
