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

**Windows MSI:** each release has `scribe-<version>-x86_64-pc-windows-msvc.msi`, built with WiX 6 from
[`windows/scribe.wxs`](windows/scribe.wxs) by `scripts/build/windows-msi.ps1` (also part of
`scripts\build\windows.ps1 release` when the .NET SDK is installed). It installs to
`C:\Program Files\scribe`, puts the folder on the system PATH and runs `install-service.ps1` there: the
groups, NT SERVICE\scribed with its ETW and folder grants, started. A newer MSI (or another build of the
same version) upgrades in place; uninstalling in Settings > Apps removes the service, the programs and
the PATH entry and keeps `scribe.toml`, `data\` and `logs\` (delete the folder to remove them).

```powershell
msiexec /i scribe-<version>-x86_64-pc-windows-msvc.msi /qn    # or double-click it
msiexec /x scribe-<version>-x86_64-pc-windows-msvc.msi /qn    # or Settings > Apps
```

**The quick way without packages:** the install scripts put everything in place, from a release archive
(`install.sh` / `install.ps1` in it) or from this repository's release build, and take it out again. On
macOS they stand in for the `.pkg` of plan phase 13; on Windows `install.ps1` refuses to run while the MSI is
installed.

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
unit, agent or script for each user to enable. On Linux and macOS they also add the person who ran `sudo` to
`scribe` (`--no-join` skips it). A build found in this repository's `target/` must be of the checked-out
commit, or the script stops and says to rebuild (an older build installs older code). Options: `--from <dir>` /
`-From` (where the binaries are, installed as they are),
`--as-root` (Linux), `-LocalSystem` and `-Dir` (Windows), `--dry-run` (Linux, macOS). Sensor tests run all
three on GitHub's runners; on Ubuntu they also install, upgrade and purge the `.deb` and install and
remove the `.rpm` in a Fedora container (`scripts/ci/package-check.sh`), and on Windows install, upgrade and
uninstall the MSI (`scripts/ci/msi-check.ps1`).

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

## Checking a download

Each release has `SHA256SUMS`, signed with minisign (`SHA256SUMS.minisig`, public key
[`minisign.pub`](minisign.pub)), and a GitHub build-provenance attestation for every file:

```sh
minisign -Vm SHA256SUMS -p minisign.pub              # the signature
sha256sum -c SHA256SUMS --ignore-missing             # the files you downloaded (shasum -a 256 -c on macOS)
gh attestation verify scribe_<version>_amd64.deb -R savex/scribe   # built by this repository's Release workflow
```

**Setting up the key (once, by the repository owner):**

```sh
minisign -G -W -p packaging/minisign.pub -s ~/scribe-minisign.key   # -W: no password (CI has no prompt)
gh secret set MINISIGN_SECRET_KEY < ~/scribe-minisign.key
git add packaging/minisign.pub
```

Keep `scribe-minisign.key` offline (or delete it: the secret is the copy CI uses). Until
`minisign.pub` is in the repository, releases go out unsigned with a warning; once it is there, a release
without the secret fails. A dry run (Release, dispatched with *dry run* on a branch) builds, packages and
signs that branch without publishing (with a throwaway key if the secret is missing) and leaves the files
as the run's artifact `release-dry-run`.

## The systemd sandbox

`linux/scribed.service` runs scribed with a capability bounding set (BPF, PERFMON, NET_RAW, NET_ADMIN,
SYS_RESOURCE, SETUID, SETGID, CHOWN, FOWNER, DAC_OVERRIDE, DAC_READ_SEARCH, SYS_PTRACE), a read-only file
system except `/var/lib/scribe`, `/var/log/scribe` and `/run/scribe`, no new privileges, private `/tmp` and
devices, kernel, cgroup and clock protection and a system-call filter; `systemd-analyze security scribed`
rates it. A `data_dir` or log file elsewhere needs a drop-in:

```sh
sudo systemctl edit scribed      # [Service] ReadWritePaths=/srv/scribe
```
