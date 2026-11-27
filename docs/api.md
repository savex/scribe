# Local API

scribed serves a gRPC API to programs on the same computer. The `scribe` command uses it; so can your
own scripts and tools.

- **Definitions:** [`proto/scribe/v1/api.proto`](../proto/scribe/v1/api.proto) (service `scribe.v1.Scribe`)
  and [`proto/scribe/v1/modules/url.proto`](../proto/scribe/v1/modules/url.proto) (service `scribe.v1.modules.url.Url`).
- **API version:** 1 (`Status.api_version`). It goes up only on a change that breaks clients.

## Connecting

| System | Address |
|---|---|
| Linux | Unix socket `/run/scribe/api.sock` |
| macOS | Unix socket `/var/run/scribe/api.sock` |
| Windows | Named pipe `\\.\pipe\scribed` |

There is no network port. Set another path with `[api] socket`.

## Who may call what

The system tells scribed who is calling; no tokens or passwords.

| Caller | May |
|---|---|
| Members of `scribe` | read calls |
| Members of `scribe-admin` (`[api] admin_group`), root, Administrators | read and control calls |
| Anyone else | can't open the socket |

Every control call is stored as an audit event, refused ones too.

## Conventions

- Times are Unix epoch milliseconds (`*_ms`); durations are whole seconds (`*_s`).
- Lists take `offset` and `limit` (`0` = all remaining) and return `total`.
- Limits per connection: messages up to 4 MiB, 16 calls at once, 8 open streams, 30 s per call.

## Read calls

| Call | Returns | CLI |
|---|---|---|
| `GetStatus` | Version, mode, sensor, storage, counters, warnings (`critical`), modules | `scribe status` |
| `Health` | `level` (healthy, degraded, unhealthy) and `reasons` | `scribe daemon health` |
| `ListHosts(name_contains, offset, limit)` | Hosts with counters, programs, TLS/plaintext flags | `scribe hosts` |
| `ListHostHours(host, since_ms)` | One host's counters per hour (default: last 24 h) | `scribe hosts --hourly` |
| `ListAlerts(offset, limit, since_ms)` | Stored alerts | `scribe alerts` |
| `WatchAlerts` | Stream of new alerts | `scribe alerts --watch`, `scribe notify` |
| `GetBaseline(profile)` | Known hosts, each `learned` or `manual` | `scribe baseline` |
| `Export` | Stream of all hosts and baseline entries | `scribe export` |
| `VerifyAudit` | Checks the audit chain; lists gaps and changed records | `scribe audit verify` |
| `ListModules`, `GetModule(id)` | Module state, health, drops | `scribe modules` |
| `Url.List(host, limit, since_ms)` | Stored plaintext HTTP requests (URL module only) | `scribe url list` |

The standard `grpc.health.v1.Health` service is served too, with the same answer as `Health`.

## Control calls

| Call | Does | CLI |
|---|---|---|
| `SetMode(mode)` | Switches to `learn`, `caution` or `alert` | `scribe mode <mode>` |
| `AckAlert(id)` | Acknowledges an alert so it stops repeating | `scribe alerts ack <id>` |
| `EditBaseline(add, remove)` | Adds or removes known hosts | `scribe baseline add` / `rm` |
| `Reset(counters, caches, config)` | Zeroes counters, clears caches, reloads the config (none set = all); says which config keys need a restart | `scribe daemon reset` |
| `Hibernate(for_s)` | Pauses processing; wakes up on its own (default and maximum `[daemon] max_hibernate`) | `scribe daemon hibernate` |
| `Wakeup` | Resumes processing | `scribe daemon wakeup` |

## Example

With [grpcurl](https://github.com/fullstorydev/grpcurl) on Linux or macOS, from the repository root:

```bash
grpcurl -plaintext -unix -import-path proto -proto scribe/v1/api.proto /var/run/scribe/api.sock scribe.v1.Scribe/GetStatus
```

```bash
grpcurl -plaintext -unix -import-path proto -proto scribe/v1/api.proto -d '{"limit": 10}' /var/run/scribe/api.sock scribe.v1.Scribe/ListAlerts
```

Most commands also print JSON with `--json`, which is often simpler than calling the API.
