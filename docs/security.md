# Security model

scribed runs with high rights and reads untrusted network data, so it is built to limit what can go
wrong. This page explains who can do what, and how scribe protects itself and its records.

## Who can do what

| Who | Can |
|---|---|
| root, Administrators | everything |
| `scribe-admin` group | change the mode, edit known hosts, acknowledge alerts, reset, pause and wake scribed |
| `scribe` group | read status, hosts, alerts and history |
| anyone else | nothing: they can't open scribed's socket or pipe |

There are no passwords or tokens: the system tells scribed who is calling. There is no network port;
the API is reachable only from the same computer. Every change, and every refused attempt, is
recorded.

## Protecting against a fake scribed

Before sending anything, the `scribe` command checks the other side: the socket must belong to root,
or on Windows the pipe must be served by SYSTEM or `NT SERVICE\scribed`. A program that pretends to
be scribed is refused.

## Fewest rights needed

| System | How |
|---|---|
| Linux | As set up by the package or install script, scribed runs on as the user `scribe` once the capture starts, and keeps only the capture rights. The systemd unit adds a sandbox: read-only system, private `/tmp`, a list of allowed system calls (`systemd-analyze security scribed` rates it). |
| Windows | scribed runs as its own service account `NT SERVICE\scribed`, not SYSTEM, with only the rights to read the system's network events and write its own folders. |
| macOS | scribed runs as root for now, because packet capture needs it. |

## Untrusted network data

Everything scribed reads from the network (DNS, TLS, QUIC, HTTP) is treated as hostile. The readers
are written in Rust, which rules out most memory bugs, and are tested with random inputs (fuzzing). Modules have a time budget; a module that crashes is turned off, not scribed.

## Records you can trust

- **Audit chain.** Every change to scribed and every alert is linked to the one before it with a
  keyed checksum (HMAC). If someone deletes or edits a record, `scribe audit verify` shows where.
  The key (`audit.key`) is readable by root only.
- **Stops are recorded.** Starts, stops and crashes are stored, so a gap is visible.
- **Pauses end on their own.** `scribe daemon hibernate` has a maximum (4 hours by default) and
  raises an alert when it starts, so it can't be used to silence scribed quietly.

## Files and secrets

- scribed refuses to start if its config or data folder can be changed by other users.
- Passwords and keys never go in the config file. They are kept in the system's secret store
  (macOS Keychain, Windows DPAPI, Linux Secret Service) or in a file only root can read, and the
  config names them, for example `credentials = "keychain:scribe-postgres"`.

## Connections scribed makes

| Connection | Protection |
|---|---|
| Webhooks | https only, certificates checked (or pinned), each request signed with HMAC so the receiver can check it |
| Threat-list downloads | https only, size limits, optional exact checksum or minisign signature; a bad download keeps the last good list |
| Postgres | always encrypted and certificate-checked when the server is on another machine |

## Releases

Every released file is listed in `SHA256SUMS`, which is signed with minisign, and has a GitHub
attestation that proves which workflow built it. See
[Checking a download](../packaging/README.md#checking-a-download). The tests also check dependencies for known
problems and licences (`cargo deny`).

## What scribe does not protect against

- **Root on the same computer.** Someone with root can stop scribed, change its files or its key.
  The audit chain shows tampering only if the records were copied elsewhere first (for example, to a
  central Postgres).
- **Traffic scribed can't see:** inside VMs, or hidden behind a VPN or relay (see
  [Status and health](status-and-health.md#why-connections-have-no-program)).
- **Encrypted content.** scribed knows where data went, not what it was.

## Reporting a security problem

Please don't open a public issue. Contact the maintainer privately through
[GitHub](https://github.com/savex) and describe the problem; a fix comes before any public details.
