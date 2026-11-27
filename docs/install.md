# Install and uninstall

scribe has two programs: **scribed**, the background service, and **scribe**, the command you type.
Installing sets up both, starts scribed at boot, and creates two groups:

- `scribe`: members may read (`scribe status`, `hosts`, `alerts`).
- `scribe-admin`: members may also change things (mode, known hosts, pause).

Downloads are on the [releases page](https://github.com/savex/scribe/releases). Check a download
before you install it: see [Checking a download](../packaging/README.md#checking-a-download).

The install scripts below are in this repository under `scripts/install/`, and inside each release
archive as `install.sh` (`install.ps1` on Windows): unpack the archive and run
`sudo ./install.sh install` in its folder.

## Linux

Needs Linux 5.8 or newer for the native sensor (older kernels fall back to packet capture).

**With a package** (Ubuntu 24.04, Debian 13, Fedora 40 or newer, x86_64):

```bash
sudo apt install ./scribe_<version>_amd64.deb
```

```bash
sudo dnf install ./scribe-<version>.x86_64.rpm
```

The package starts scribed right away. Add yourself to the group, then log out and in again:

```bash
sudo usermod -aG scribe $USER
```

**With the install script** (any systemd Linux; from a release archive or a build of this repository):

```bash
sudo scripts/install/linux.sh install
```

The script adds the person who ran `sudo` to `scribe` (`--no-join` skips it). Run it again to upgrade.

## macOS

There is no `.pkg` yet. Use the install script, from a release archive or a build of this repository:

```bash
sudo scripts/install/macos.sh install
```

scribed runs as root under launchd and uses packet capture. Open a new terminal afterwards so the
`scribe` group membership applies.

## Windows

**With the installer:** double-click `scribe-<version>-x86_64-pc-windows-msvc.msi`, or:

```powershell
msiexec /i scribe-<version>-x86_64-pc-windows-msvc.msi /qn
```

It installs to `C:\Program Files\scribe`, adds it to the PATH, and runs scribed as the service
account `NT SERVICE\scribed`. Add yourself to the group, then sign out and in again:

```powershell
net localgroup scribe $env:USERNAME /add
```

**With the install script** (as Administrator):

```powershell
scripts\install\windows.ps1 install
```

## Check that it works

```bash
scribe status
```

```bash
scribe daemon health
```

You should see `running` and, after a minute of use, hosts in `scribe hosts`. If not, see
[Troubleshooting](troubleshooting.md).

## Desktop notifications

scribed can't show notifications itself (system services have no desktop). Turn on `scribe notify`
for your user:

| System | Command |
|---|---|
| Linux | `systemctl --user enable --now scribe-notify` |
| macOS | `launchctl bootstrap gui/$(id -u) /Library/LaunchAgents/io.github.savex.scribe-notify.plist` |
| Windows | run `install-notify.ps1` from the install folder (no Administrator needed) |

## Where things go

| | Linux | macOS | Windows |
|---|---|---|---|
| Programs | `/usr/bin` | `/usr/local/bin` | `C:\Program Files\scribe` |
| Config | `/etc/scribe/scribe.toml` | `/Library/Application Support/scribe/scribe.toml` | next to the programs |
| Data | `/var/lib/scribe` | `/Library/Application Support/scribe` | `data\` next to the programs |
| Logs | `/var/log/scribe` | `/var/log/scribe`, `/Library/Logs/scribe` | `logs\` next to the programs |

## Upgrade

Install the new version the same way. Your config, known hosts, history and mode are kept.

## Uninstall

Uninstalling keeps your config, data and logs unless you ask to remove them.

| How you installed | Keep data | Remove everything |
|---|---|---|
| `.deb` | `sudo apt remove scribe` | `sudo apt purge scribe` |
| `.rpm` | `sudo dnf remove scribe` | then delete `/etc/scribe`, `/var/lib/scribe`, `/var/log/scribe` |
| Linux script | `sudo scripts/install/linux.sh uninstall` | add `--purge` |
| macOS script | `sudo scripts/install/macos.sh uninstall` | add `--purge` |
| MSI | Settings > Apps > scribe > Uninstall | then delete `C:\Program Files\scribe` |
| Windows script | `scripts\install\windows.ps1 uninstall` | add `-Purge` |

More options (running scribed as root, a different install folder, a dry run) are in
[`packaging/README.md`](../packaging/README.md).
