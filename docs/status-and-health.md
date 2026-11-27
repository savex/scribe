# Status and health

Two commands tell you how scribed is doing:

- `scribe status` shows everything: what scribed is doing, how busy it is and what needs attention.
- `scribe daemon health` gives a one-word answer for scripts and monitoring:
  **healthy**, **degraded** or **unhealthy**, with the reasons.

Both work without `sudo` for members of the `scribe` group.

## Reading `scribe status`

An example from a Mac:

```text
scribed 0.3.0 (API 1): running, up 2h 10m
! attribution_low: only 1358 of 2921 new flows (46%) got a process; is scribed allowed to read other processes?
mode       learn, profile default
sensor     pcap+sockets, process info, ok
process    1358 of 2921 new flows (46%); socket table: 1273 reads, last 15 ms, max 90 ms, 4 over budget
config     /Library/Application Support/scribe/scribe.toml, loaded 2026-11-27T18:39:52Z
counters   since 2026-11-27T18:39:52Z: 2921 flows (0.4/s), 0.6 events/s, 0 alerts, 147 new hosts, 0 dropped while hibernating, 0 drops
pipeline   0 QUIC flows held, 223 DNS names cached
storage    state: sqlite ok
           sink local-history: sqlite ok
modules    url 1: running, ok
```

| Line | What it tells you |
|---|---|
| first line | The version, the API version (the CLI and scribed must agree), the state (`running`, `hibernating`) and how long it has run. |
| `!` lines | Warnings: something needs your attention. Each one is explained [below](#warnings). No `!` lines means all is well. |
| `mode` | The mode (`learn`, `caution` or `alert`) and the profile, the list of known hosts in use. In learn mode scribed only records; it raises no alerts. |
| `sensor` | Which sensor captures connections and whether it knows the program behind each one. `linux-ebpf` and `windows-etw` are the native sensors; `pcap` is packet capture; `+sockets` means the program is looked up in the system's socket table. |
| `process` | How many new connections got their program. The socket-table numbers show how often scribed read the table and how long a read took; "over budget" reads were slow, so the next one waited a little. |
| `config` | The config file in use and when it was read. |
| `counters` | Since start: connections (`flows`), events per second, alerts, hosts never seen before, and records lost. `drops` should stay 0. |
| `pipeline` | Connections waiting for more packets (QUIC) and DNS answers kept to put names on IP addresses. |
| `storage` | Each database and whether it works. `spooling` means a database was away and its events wait on disk. |
| `modules` | Each module, its version and state. |

## Health levels

| Level | Meaning | Exit code of `scribe daemon health` |
|---|---|---|
| **healthy** | No warnings. | 0 |
| **degraded** | scribed works, but at least one warning is shown. | 0 |
| **unhealthy** | scribed can't do its job: it doesn't answer, the sensor isn't capturing, or the main database is down. | 1 |

The same answer is served as the standard gRPC health check, so monitoring tools that speak it can
ask scribed directly.

## Warnings

| Warning | What it means | What to do |
|---|---|---|
| `sensor_detached` (unhealthy) | The sensor stopped capturing. No connections are recorded. | Look at scribed's log. Often scribed lost its rights to capture; restart it. |
| `state_unhealthy` (unhealthy) | The main database (known hosts, alerts) can't be used. | Check the disk and the database path. scribed keeps the latest writes in memory and catches up when the database is back. |
| `sink_unhealthy` | A history database (an event sink) is down. | Check that database. Its events wait on disk meanwhile. |
| `sink_spooling` | Events for a history database wait on disk. | Nothing, if the database is coming back. They are sent in order when it does. |
| `spool_high` | The disk spool is over 80% full. | Bring the database back, or give the spool more room (`[storage.spool] max_size`). When it is full, the oldest events are dropped. |
| `state_buffering` | Writes to the main database wait in memory. | Nothing, if the database is coming back. |
| `buffer_high` | That memory buffer is over 80% full. | Fix the main database soon; when the buffer is full, the oldest writes are dropped. |
| `drops` | Records were lost since start (a full buffer or spool, or packets the sensor couldn't keep up with). | See which buffer or spool filled up, and give it more room or fix what was down. |
| `fallback_sensor` | The native sensor couldn't start, so packet capture is used instead. Programs come from the socket table, or are unknown. | Look at the log for why the native sensor failed: an old kernel (Linux needs 5.8 or newer), missing rights, or ETW access on Windows. |
| `attribution_low` | Fewer than half of the new connections (out of at least 100) got their program. | See [below](#why-connections-have-no-program). |
| `module_failed` | A module stopped with an error. | The detail names the module and the error; check its settings in `[modules.<name>]`. |
| `hibernating` | Someone paused processing with `scribe daemon hibernate`. | `scribe daemon wakeup`, or wait: it wakes up on its own (at most `[daemon] max_hibernate`, 4 hours by default). |

## Why connections have no program

`attribution_low` asks whether scribed may read other processes. That is the cause when scribed
runs without the rights it needs, but it isn't the only one.

| Cause | Where you see it | Can it be fixed? |
|---|---|---|
| scribed can't read other processes | Linux or Windows with a changed service account; a scribed you started yourself without `sudo` | Yes: run scribed as the installers set it up. |
| Apple's own services use their own network stack, which the socket table doesn't list | macOS: `*.apple.com`, `*.icloud.com`, `api.smoot.apple.com` | Not with the current macOS sensor. A Network Extension sensor (planned as an option) would see them. |
| iCloud Private Relay and VPNs carry other apps' traffic | macOS: `apple-relay.cloudflare.com`; any system: VPN servers | Partly: the program shown is the relay or VPN, not the app behind it. |
| Virtual machines and containers | Traffic that passes through your computer from a VM; no program on your computer owns it | No: the program runs inside the VM. Run scribe inside the VM to see it. |
| Very short connections | A connection opened and closed between two socket-table reads (packet capture only) | Mostly no; the native sensors (Linux eBPF, Windows ETW) don't have this gap. |

On a Mac with many Apple services, about half of the connections getting a program is normal for now.
