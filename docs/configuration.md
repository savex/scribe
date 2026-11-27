# Configuration

scribed reads one file, `scribe.toml`. You don't need one: with no file, or an empty one, every option
has a sensible default. Write down only what you want to change.

The full file with every default and a comment per option is [`config/scribe.toml`](../config/scribe.toml).
This page explains what the options are for.

## Where the file lives

scribed uses the first of these it finds:

1. `scribed --config <path>`
2. the `SCRIBE_CONFIG` environment variable
3. the system default:

| System | Config file | Data folder (`data_dir`) |
|---|---|---|
| Linux | `/etc/scribe/scribe.toml` | `/var/lib/scribe` |
| macOS | `/Library/Application Support/scribe/scribe.toml` | `/Library/Application Support/scribe` |
| Windows | `scribe.toml` next to `scribed.exe` | `data` next to `scribed.exe` |

After you edit the file, apply it with `sudo scribe daemon reset --config` (or restart scribed).
A few options, marked below, need a restart.

## How values are written

| Kind | Examples | Notes |
|---|---|---|
| time | `"45s"`, `"10m"`, `"1h"`, `"7d"` | `""` usually means "no limit" |
| size | `"512KiB"`, `"32MiB"`, `"2GiB"`, `"1%"` | A percentage is of total memory (for memory limits) or of the disk (for disk limits). |
| path | `"state.db"`, `"/var/lib/scribe/state.db"` | A short path is inside `data_dir`. On Windows use `'C:\scribe'` or `"C:/scribe"`. |

## The main choice: mode

```toml
mode = "learn"      # learn | caution | alert
```

| Mode | What scribed does |
|---|---|
| `learn` | Records every connection and learns the hosts your computer talks to. No alerts. Start here. |
| `caution` | Alerts when a new host looks suspicious (see [scores](#how-suspicious-is-a-host)), and on any unencrypted connection, even to a known host. |
| `alert` | Alerts on every host it hasn't learned. Strict; best once learning is done. |

`profile` names the list of known hosts in use (`"default"`). You can keep several lists, for example
one for work and one for home.

To leave learn mode on its own after a while:

```toml
[policy]
learn_for = "7d"     # learn for a week…
then = "caution"     # …then switch to caution
```

## Alerts: `[policy]`

| Option | Default | What it does |
|---|---|---|
| `dedupe_window` | `10m` | One alert per host and program in this time, not one per connection. |
| `threshold` | `50` | In caution mode, alert when a host's score reaches this (0–100). |

### How suspicious is a host: `[policy.scores]`

In caution mode each new host gets points for every sign below. The points are added up (at most 100)
and compared with `threshold`. Set a sign to 0 to ignore it.

| Sign | Points | Meaning |
|---|---|---|
| `raw_ip` | 60 | The program connected to an IP address without looking up a name first. |
| `unusual_port` | 30 | The port isn't in the usual list (below). |
| `high_entropy` | 50 | The name looks random, as some malware generates them (`x7k2q9vbz1.example.com`). |
| `new_tld` | 20 | An ending (`.xyz`, `.top`) your computer never used before. |
| `new_process` | 25 | A program that never connected anywhere before. |
| `threat_list` | 100 | The host is on one of your threat lists. |

Modules add their own signs, scored the same way, for example `"url.credentials_in_query" = 40`.

`[policy.usual_ports]` lists the ports that count as normal (web, mail, DNS, SSH, time).
`[policy.entropy]` sets how random a name must look: labels shorter than `min_label_length` are never
flagged.

### Threat lists: `[[policy.threat_lists]]`

Lists of known bad hosts or IPs. There are none by default, because downloading a list is itself
outgoing traffic. A list can be a local file (`path`) or a download (`url`, refreshed every `refresh`).
Formats: `domains`, `hosts` (hosts-file) or `ips` (IPs and ranges). For a download you can require an
exact checksum (`sha256`) or a signature (`minisign_key`). If a download fails, the last good copy is
used.

## Modules: `[modules]`

Extra features that can be turned on or off. Today there is one, `url`, on by default.

```toml
[modules]
enabled = ["url"]
```

`[modules.url]` records the addresses of plain (not encrypted) web requests. Because addresses can
hold private data, `query` chooses how much is kept, shown for
`http://api.example.com/v1/users/1234?token=abc&lang=en`:

| `query` | Stored |
|---|---|
| `full` | `/v1/users/1234?token=abc&lang=en` |
| `redact_values` (default) | `/v1/users/1234?token=<redacted>&lang=<redacted>` |
| `strip` | `/v1/users/1234` |
| `path_only` | `/v1/…` |
| `hash` | `/v1/users/1234?<hash:a41f9c>` (repeats can be matched without storing values) |

Passwords in addresses (`user:password@`) are always removed. Encrypted (https) traffic shows only
the host name; scribed never decrypts anything.

## Capture: `[sensor]`

| Option | Default | What it does |
|---|---|---|
| `interface` | `""` (automatic) | The network device packet capture listens on, such as `en0` or `eth0`. Used on macOS and as the fallback elsewhere. Restart needed. |
| `process_lookup` | `true` | With packet capture, find the program behind each connection in the system's socket table. Restart needed. |

On Linux (eBPF) and Windows (ETW) scribed knows the program directly and these options rarely matter.

## The service: `[daemon]`

| Option | Default | What it does |
|---|---|---|
| `max_hibernate` | `4h` | The longest pause `scribe daemon hibernate` may take. scribed always wakes up on its own. |
| `user` | `""` | Linux and macOS: after opening the capture and databases, run on as this user instead of root. |

## Who may use scribed: `[api]`

| Option | Default | What it does |
|---|---|---|
| `socket` | `""` (system default) | Where the `scribe` command finds scribed. |
| `admin_group` | `scribe-admin` | Members may change things (mode, known hosts, pause). Root and Administrators always may. |

Members of the `scribe` group may read (status, hosts, alerts, export). Everyone else can't reach
scribed at all. Every change is logged, refused ones too.

## Where alerts go: `[alerts]`

Every alert is always stored and shown by `scribe alerts --watch` and the `scribe notify` desktop
notifications. On top of that:

| Option | Default | What it does |
|---|---|---|
| `log` | `true` | Write a line per alert to scribed's log. |
| `max_per_minute` | `30` | At most this many per output per minute; the rest are counted. `0` = no limit. |

`[[alerts.webhooks]]` sends each alert as JSON to a web address (https only), signed so the receiver
can check it came from scribed. Set `name`, `url` and `secret` (a key kept in the system's secret
store or a root-only file). `pin_sha256` accepts only one exact server certificate.

## Storage: `[storage]`

scribed keeps two kinds of data:

- **state**: what it has learned (known hosts, alerts). `[storage.state]`, SQLite file `state.db`.
- **history**: every connection and event, in one or more **sinks**. `[[storage.sinks]]`, by default
  SQLite file `events.db`, kept 30 days.

| Section | What it controls |
|---|---|
| `[storage.cache]` | How many hosts are kept in memory for speed (`max_hosts`, `max_memory`). |
| `[storage.buffer]` | How many writes wait in memory while the state database is away. |
| `[storage.spool]` | How much history waits on disk while a sink is away (`max_size`), and the free disk to leave (`min_free_disk`). |
| `[storage.hours]` | How long hourly counts per host are kept (`keep`, `90d`). |

Each sink has a `name`, a `kind` (`sqlite` or `postgres`), which `events` it takes (`[]` = all),
`retention` (how long to keep, `""` = forever), and how it batches writes.

A **Postgres sink** sends history from many computers to one central database. It always uses an
encrypted, checked connection to another machine. The password never goes in the config file:
`credentials` names a secret in the system's store, saved with `scribed --set-secret`.

## Logs: `[log]`

| Option | Default | What it does |
|---|---|---|
| `level` | `info` | How much to write: `error`, `warn`, `info`, `debug`, `trace`. `SCRIBE_LOG` overrides it. |
| `format` | `text` | `text` for people, `json` for log tools. |
| `output` | `file` | `file`, `system` (journald, macOS log, Windows Event Viewer) or `both`. |
| `file` | system default | The log file. `""` writes to the terminal. |
| `rotate` | `daily` | Start a new file each day (`daily`) or at a size (`size`, with `max_size`). |
| `keep` | `14` | Old log files to keep. |
