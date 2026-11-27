# Tech stack

What scribe is built with, and why.

## Language: Rust

All of scribe is written in [Rust](https://www.rust-lang.org/). A service that runs as root and reads
network traffic has to be fast and must not crash or be tricked by odd input. Rust catches whole kinds
of memory bugs before the program runs, and compiles to one small program per system, with no runtime
to install. The minimum Rust version is in `rust-version` in [`Cargo.toml`](../Cargo.toml).

The code is split into small packages (*crates*) under [`crates/`](../crates): one for each sensor,
each database, the API, the CLI, and so on.

## Watching connections

| System | Technology | In short |
|---|---|---|
| Linux | **eBPF** (`libbpf-rs`) | A tiny, safety-checked program that runs inside the Linux kernel and reports each new connection with its program. Needs Linux 5.8 or newer. |
| Windows | **ETW** (`windows-sys`) | Event Tracing for Windows, the system's built-in event stream, which reports network activity per program. |
| macOS, and fallback | **libpcap** | Classic packet capture. The program behind a connection comes from the system's socket table (`libproc` on macOS). |

## Reading the traffic

scribed reads just enough of each connection to learn the host name:

- **DNS** answers, to put names on IP addresses;
- the **TLS** handshake's server name, sent before encryption starts;
- **QUIC** (HTTP/3) handshakes, which need a small decryption of the first packet, done with
  [`ring`](https://github.com/briansmith/ring);
- plain **HTTP** requests, read with `httparse`, for the URL module.

All of this is parsed by scribe's own code, tested with fuzzing (random input) so bad packets can't
break it.

## Running the service

| Piece | Used for |
|---|---|
| **tokio** | Doing many things at once (capture, storage, API) without one blocking another. |
| **tracing** | Logs: to a file, journald (Linux), unified logging (macOS) or Event Viewer (Windows). |
| **systemd / launchd / Windows services** | Start scribed at boot and restart it if it stops. |

## Storing data

| Piece | Used for |
|---|---|
| **SQLite** (`rusqlite`) | The default database: one file on disk, nothing to set up. |
| **PostgreSQL** (`tokio-postgres`) | Optional central database that many computers send their history to. |
| **serde, TOML, JSON** | The config file (TOML) and exports, webhooks, `--json` output (JSON). |

## Talking to scribed

| Piece | Used for |
|---|---|
| **gRPC** (`tonic`, `prost`) | The local API between scribed and the `scribe` command. Typed messages defined in `.proto` files. |
| **Unix sockets / named pipes** | Carry the API on the same computer only, so no network port is open. |
| **clap** | The `scribe` command line: commands, options and help. |
| **notify-rust** | Desktop notifications from `scribe notify`. |

## Security

| Piece | Used for |
|---|---|
| **rustls** with the system's certificate store | Encrypted connections for webhooks, threat-list downloads and Postgres. |
| **ring** | Signatures on webhooks (HMAC) and the audit chain that shows edits to scribed's records. |
| **Keychain, DPAPI, Secret Service** | Keep passwords and keys in the system's own secret store, not in the config file. |
| **minisign** | Signs released files, and checks signed threat lists. |

## Building, testing and releasing

| Piece | Used for |
|---|---|
| **cargo** | Building and testing. `cargo nextest` runs the tests faster. |
| **proptest**, **cargo-fuzz** | Tests with generated and random input. |
| **GitHub Actions** | Builds and tests on Linux, macOS and Windows, including several Linux kernel versions for eBPF. |
| **nfpm** | Builds the Linux `.deb` and `.rpm` packages. |
| **WiX** | Builds the Windows `.msi` installer. |
| **GitHub attestations** | Proof of which workflow built each released file. |

A desktop app (Tauri) is planned in [`ui/`](../ui); it will use the same local API.
