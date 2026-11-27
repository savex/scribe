# Troubleshooting

Start with these two commands. They answer most questions:

```bash
scribe status
```

```bash
scribe daemon health
```

Each warning they show is explained in [Status and health](status-and-health.md).

## Where the logs are

| System | Log |
|---|---|
| Linux | `/var/log/scribe/scribed.log`, or `journalctl -u scribed` |
| macOS | `/var/log/scribe/scribed.log`; start-up errors in `/Library/Logs/scribe/scribed.stderr.log` |
| Windows | `logs\scribed.log` in the install folder |

For more detail, set `[log] level = "debug"` and reload (`sudo scribe daemon reset --config`).

## The `scribe` command can't reach scribed

**"cannot open … (permission denied): the scribe group may read it"**

You aren't in the `scribe` group yet, or your login doesn't know it yet.

- Add yourself: Linux `sudo usermod -aG scribe $USER`; macOS
  `sudo dseditgroup -o edit -a $USER -t user scribe`; Windows `net localgroup scribe <you> /add`.
- Then log out and in again (on macOS, a new terminal is enough). `id` (or `whoami /groups`) should
  list `scribe`.

**"scribed is not running or its socket is not reachable"**

scribed isn't running. Look at why it stopped:

| System | Check | Start |
|---|---|---|
| Linux | `systemctl status scribed` | `sudo systemctl start scribed` |
| macOS | `sudo launchctl print system/io.github.savex.scribed` | `sudo launchctl kickstart system/io.github.savex.scribed` |
| Windows | `Get-Service scribed` | `Start-Service scribed` |

**"… is owned by uid …, not root; refusing to talk to it"** (or, on Windows, "the pipe server runs
as …")

Something other than the real scribed holds the socket. `scribe` refuses to talk to it on purpose.
Find and stop that program, then restart scribed.

**"warning: scribed speaks API version …"**

The `scribe` command and scribed are different versions. Install both from the same release.

## scribed won't start

**"… is writable by group or others (mode …); run `chmod go-w …`"**

scribed refuses a config file or data folder that other users could change. Run the `chmod` command
the message shows.

**A config error** shows the file, line and what is wrong. Check the file before restarting:

```bash
sudo scribed --check-config
```

**The install script says the build is stale** ("holds scribed …, but this checkout is …"): the
build in `target/` is from older code. Rebuild (`scripts/build/<system>.sh build --release`), then
install again.

## I see no hosts, or fewer than expected

- **Learn mode records, but doesn't alert.** `scribe hosts` should still fill up as you use the
  computer.
- **`fallback_sensor` warning:** the native sensor didn't start. The log says why (Linux older than
  5.8, missing rights, ETW access on Windows).
- **Windows with packet capture** needs [Npcap](https://npcap.com/) installed.
- **Wrong network device** (packet capture): set `[sensor] interface`, for example `en0`, and restart.
- **`hibernating`:** someone paused scribed. `sudo scribe daemon wakeup`.

## Connections have no program

See [Why connections have no program](status-and-health.md#why-connections-have-no-program). On a
Mac, about half is normal for now.

## Too many alerts

- Stay in learn mode longer, so scribed knows your usual hosts (`[policy] learn_for`).
- Use `caution` instead of `alert`.
- Mark hosts you trust: `sudo scribe baseline add example.com`.
- Acknowledge an alert so it stops repeating: `sudo scribe alerts ack <id>`.
- Raise `[policy] threshold`, or set a score you don't care about to 0
  (see [Configuration](configuration.md#how-suspicious-is-a-host)).

## A database is down

`sink_unhealthy`, `sink_spooling` or `state_buffering` mean a database is away. scribed keeps the
data in memory or on disk and catches up. Fix the database (disk full, Postgres unreachable, wrong
password); if it stays away long, give the spool more room (`[storage.spool] max_size`).

## Reporting a problem

Open an issue on [GitHub](https://github.com/savex/scribe/issues) with:

- `scribe version` and your system version;
- `scribe status --json`;
- the lines around the error in scribed's log.

Remove host names and addresses you don't want to share before posting.
