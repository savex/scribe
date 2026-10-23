# scribe

Cross-platform (macOS, Linux, Windows) tool that logs and tracks every outgoing
connection from a host: which hosts and URLs are contacted, by which process,
how often, and whether the traffic uses TLS.

## Modes

- **learn** — record everything and build the list of known hosts; no alerts.
- **caution** — alert on unknown hosts that look unusual, and on any non-TLS traffic.
- **alert** — alert on every host or request that is not on the list.

## Layout

```
crates/
  core/                 shared types: FlowEvent, Mode, Sensor trait
  enrich/               DNS cache, TLS SNI / HTTP Host parsing, TLS detection
  sensor-linux/         eBPF sensor (Linux)
  sensor-windows/       ETW sensor (Windows)
  sensor-pcap/          libpcap / Npcap fallback (all OSes)
  storage-api/          storage plugin traits: StateStore, EventSink, StorageFactory
  storage-manager/      backend registry, fan-out to sinks
  storage-sqlite/       default backend
  storage-postgres/     PostgreSQL backend (feature `postgres`)
  storage-conformance/  shared test suite every backend must pass
  daemon/               `scribed` service
  cli/                  `scribe` command line client
macos/ScribeExtension/  Network Extension (Swift), planned
ui/                     optional Tauri UI, planned
config/                 example configuration
```

## Build

```sh
cargo build                       # SQLite backend only
cargo build --features postgres   # add PostgreSQL
cargo test
```

## Status

Skeleton. Interfaces and the storage conformance suite are in place; sensors,
storage backends, the policy engine and the local API are not implemented yet.
