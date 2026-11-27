# scribe documentation

Guides for people who install and use scribe. For a quick start, see the [readme](../readme.md).

| Page | Read it to… |
|---|---|
| [How scribe works](how-it-works.md) | understand the parts and the path of a connection, with a diagram |
| [Install and uninstall](install.md) | set scribe up on Linux, macOS or Windows, upgrade it or remove it |
| [Status and health](status-and-health.md) | read `scribe status`, and know what each warning means and what to do |
| [Troubleshooting](troubleshooting.md) | fix common problems: no access, not starting, no hosts, too many alerts |
| [Configuration](configuration.md) | change modes, alerts, storage, logs and the other options |
| [Privacy and your data](privacy.md) | know what is stored, for how long, what leaves the computer, how to delete it |
| [Security model](security.md) | see who can do what and how scribe protects itself and its records |
| [Many computers, one database](fleet-postgres.md) | send history from several computers to a central Postgres |
| [Local API](api.md) | call scribed from your own scripts and tools |
| [Writing a module](writing-a-module.md) | add a feature to scribed as a module |
| [Tech stack](tech-stack.md) | see what scribe is built with, and why |

Also useful:

- [`packaging/README.md`](../packaging/README.md): packages, the Windows installer, checking a download,
  desktop notifications at login.
- [`config/scribe.toml`](../config/scribe.toml): every option with its default.
- [`changelog.md`](../changelog.md): what changed in each version.

Design notes for developers (plan, specs, tests) are in [`workfiles/`](../workfiles).
