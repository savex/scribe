# Privacy and your data

scribe records **who your computer talks to**, not **what it says**. This page lists what is kept,
where, for how long, and how to remove it.

## What is stored

| Kept | Example | Not kept |
|---|---|---|
| Time of each connection | `2026-11-27 18:40` | |
| The program that made it | `/usr/bin/curl` | its arguments or files |
| Where it went | `example.com`, `192.0.2.10:443` | |
| Protocol and whether it was encrypted | TCP, TLS | |
| Bytes sent | `1 240` | the bytes themselves |
| For plain (unencrypted) web requests: the address, with values hidden | `/v1/users?token=<redacted>` | page content, cookies, form data |
| Alerts and why they were raised | `raw_ip`, score 60 | |
| Changes made to scribed | who switched the mode, when | |

scribe never decrypts traffic. For encrypted connections it only sees the name the program announces
when it connects. How much of a plain web address is kept is set by `[modules.url] query`
(see [Configuration](configuration.md#modules-modules)); passwords inside addresses are always removed.

## Where it is stored and for how long

| Data | Where | Kept |
|---|---|---|
| Known hosts, totals per host and program, alert state | `state.db` in the data folder | until you delete them |
| Hourly counts per host | `state.db` | 90 days (`[storage.hours] keep`) |
| Every connection, alert and change | `events.db` in the data folder | 30 days (`retention` of the sink) |
| History waiting for a database that is away | `spool/` in the data folder | until sent, or dropped when full |
| Logs | the log folder | 14 files (`[log] keep`) |

The data folder is `/var/lib/scribe` (Linux), `/Library/Application Support/scribe` (macOS) or
`data\` next to the programs (Windows). Only root (or the service account) can read the files.
Members of the `scribe` group can read the data through the `scribe` command.

## What leaves your computer

Nothing, unless you set it up:

| You configure | What is sent |
|---|---|
| A webhook (`[[alerts.webhooks]]`) | each alert: time, host, address, program, reason |
| A threat-list download (`[[policy.threat_lists]] url`) | an ordinary download; nothing about you |
| A Postgres sink (`[[storage.sinks]] kind = "postgres"`) | the history you choose (`events`), over an encrypted connection |

scribe has no telemetry and doesn't check for updates.

## Removing data

- **Forget one host's alerts:** acknowledge them (`sudo scribe alerts ack <id>`).
- **Remove a host from the known list:** `sudo scribe baseline rm example.com`.
- **Keep less:** lower `retention` on the sink and `[storage.hours] keep`. Older data is deleted
  within the hour.
- **Delete everything:** stop scribed, delete `state.db`, `events.db` and `spool/` in the data folder,
  and start it again. It starts learning from scratch. `scribe audit verify` will then report the
  deleted records as missing; that is expected.
- **Remove scribe and its data:** uninstall with `--purge` (see [Install](install.md#uninstall)).

`scribe export` writes your hosts and known list to a file only you can read (`-o file.json`), for
backups or to move to another computer.

## Other people on the computer

scribe sees connections from **every** user on the computer, not only yours. If others use it, tell
them it runs, and give the `scribe` group only to people who should see everyone's connections.
