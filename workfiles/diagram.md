# scribe program diagrams

*Last updated 2026-11-22, after phase 1. Built parts are drawn with solid borders in the text and
marked **built**; everything else is planned. Details: [specs.md](specs.md), progress:
[status.md](status.md).*

| # | Diagram | Shows |
|---|---|---|
| 1 | Components | Crates and how data moves between them |
| 2 | Flow of one connection | One outgoing connection from the kernel to storage and alerts |
| 3 | Policy decision | How a mode turns a flow into a record or an alert |
| 4 | Storage classes | Storage interfaces, registry, manager, backends, row codec |
| 5 | Module framework | Module interface and the daemon's module host |
| 6 | Daemon run states | Running, degraded, hibernating, stopping |
| 7 | Stored data (schema v2) | Tables in the state store and event sink files |
| 8 | Local API trust boundary | Who may call what, and how it is checked |

## 1. Components

```mermaid
flowchart TB
    subgraph clients["Clients (planned, phase 10)"]
        ui["UI (Tauri)"]
        cli["scribe CLI — crates/cli<br/>parsing built"]
    end

    subgraph daemon["scribed — crates/daemon (root / SYSTEM service)"]
        api["Local API — crates/api<br/>gRPC over Unix socket / named pipe"]
        ingest["Ingest<br/>Observation = FlowEvent + first client bytes"]
        enrich["Enrichment — crates/enrich<br/>DNS cache · SNI · HTTP Host · QUIC Initial · TLS / QUIC detection"]
        subgraph mods["Modules — built (phase 0b)"]
            host["ModuleHost<br/>budget · panic isolation · pause / resume"]
            url["URL module — crates/module-url<br/>notes.url · url.request · query privacy (hash key via scribe-secrets)"]
            later["later modules<br/>e.g. kernel metrics (kperf)"]
            queue["OutputQueue<br/>records · metrics · state"]
        end
        agg["Counters<br/>per host / process"]
        policy["Policy engine — crates/policy<br/>learn · caution · alert"]
        alerts["Alert outputs — crates/alerts<br/>notification · log · webhook"]

        subgraph storage["Storage — crates/storage-*"]
            manager["Storage manager<br/>registry · routing built;<br/>cache · batching · spool · retention planned"]
            api_traits["storage-api — built<br/>StateStore · EventSink · StorageFactory · codec"]
        end
    end

    subgraph backends["Storage backends"]
        sqlite[("SQLite — built<br/>default")]
        pg[("PostgreSQL<br/>feature postgres, phase 12")]
    end

    subgraph conformance["Conformance suites — built"]
        sconf["storage-conformance"]
        mconf["module-conformance"]
        snconf["sensor-conformance"]
    end

    subgraph sensors["Capture layer — Sensor trait (crates/core)"]
        linux["Linux<br/>eBPF (libbpf-rs)"]
        win["Windows<br/>ETW (+ Npcap)"]
        mac["macOS<br/>Network Extension (Swift)"]
        pcap["Fallback<br/>libpcap / Npcap"]
    end

    kernel["OS TCP/IP stack"]

    ui --> api
    cli --> api
    api --> policy
    api --> manager
    api --> host

    kernel --> linux & win & mac & pcap
    linux & win & pcap --> ingest
    mac -- XPC --> ingest

    ingest --> enrich --> host
    host --> url & later
    host -- notes · signals --> agg --> policy
    url & later --> queue --> manager
    policy --> alerts
    policy <--> manager
    agg --> manager
    manager --- api_traits
    api_traits --> sqlite & pg
    sconf -. verifies .-> sqlite & pg
    mconf -. verifies .-> url & later
    snconf -. verifies .-> linux & win & mac & pcap
```

## 2. Flow of one outgoing connection

```mermaid
sequenceDiagram
    autonumber
    participant K as OS TCP/IP stack
    participant S as Sensor
    participant E as Enrichment
    participant H as ModuleHost
    participant P as Policy engine
    participant M as Storage manager
    participant St as StateStore
    participant Sk as EventSinks
    participant A as Alert outputs

    K->>S: connect / first packets
    S->>E: Observation (FlowEvent + up to 4 KiB of client bytes)
    E->>E: hostname from SNI / Host / DNS cache
    E->>E: security = Tls | Quic | Plaintext | Unknown
    E->>H: enriched observation
    H->>H: each module's flow hook (time budget, panics isolated)
    H-->>E: notes (e.g. notes.url) + signals (e.g. url.*)
    H->>M: module records, metric samples, module state (via OutputQueue)
    E->>P: FlowEvent with notes + signals
    P->>M: lookup host + baseline (cached)
    M->>St: on cache miss
    St-->>M: Host, Baseline
    M-->>P: known? counters?
    P->>P: apply mode rules + score (signals included)
    P->>M: HostDelta (+1 conn, bytes)
    M->>St: upsert_host (delta)
    P->>M: StoredEvent::Flow
    M->>Sk: write_batch (batched, per sink, by subscribed kind)
    opt alert decided
        P->>M: StoredEvent::Alert + AlertState
        P->>A: notify (deduped / rate-limited)
    end
```

## 3. Policy decision

```mermaid
flowchart TD
    start(["Enriched flow<br/>+ module signals"]) --> hib{"Hibernating?"}
    hib -- yes --> drop(["Not recorded,<br/>no alert"])
    hib -- no --> listed{"Host on<br/>baseline?"}

    listed -- no --> mode1{"Mode"}
    mode1 -- learn --> add["Add to baseline<br/>(source = learned)"] --> record
    mode1 -- alert --> raise["Raise alert<br/>reason = unlisted_host"]
    mode1 -- caution --> score["Score = sum of matching signals, max 100<br/>raw_ip 60 · unusual_port 30 · high_entropy 50<br/>new_tld 20 · new_process 25 · threat_list 100<br/>+ module signals (url.*, …)"]
    score --> thr{"Score ≥ threshold<br/>(default 50)?"}
    thr -- yes --> raise2["Raise alert<br/>reason = top signal"]
    thr -- no --> plain

    listed -- yes --> plain{"Plaintext?"}
    plain -- "yes, mode = caution / alert" --> raise3["Raise alert<br/>reason = plaintext"]
    plain -- "no, or mode = learn" --> record

    raise & raise2 & raise3 --> dedupe["Dedupe per host + process<br/>(window 10m, acknowledged = silent)"] --> record
    record(["Update counters<br/>write flow event"])
```

## 4. Storage classes

```mermaid
classDiagram
    class StorageFactory {
        <<trait>>
        +kind() str
        +build_state(options) StateStore
        +build_sink(name, options) EventSink
    }
    class StateStore {
        <<trait>>
        +capabilities() StoreCaps
        +migrate()
        +upsert_host(HostDelta) HostId
        +get_host(name) Host
        +link_ip(host, ip, ttl)
        +list_hosts(HostQuery) Page
        +baseline(profile) Baseline
        +add_to_baseline(profile, entry)
        +put_alert_state(AlertState)
        +get_alert_state(key) AlertState
        +module_state(module) ModuleState
        +put_module_state(module, key, value)
        +health() Health
    }
    class EventSink {
        <<trait>>
        +name() str
        +capabilities() SinkCaps
        +migrate()
        +write_batch(StoredEvent[])
        +query(EventQuery) Page
        +flush()
        +health() Health
    }
    class StoredEvent {
        <<enum>>
        Flow(FlowEvent)
        Alert(AlertRecord)
        Audit(AuditRecord)
        Metric(MetricSample)
        Module(ModuleRecord)
        +kind() EventKind
    }
    class EventKind {
        <<enum>>
        Flow
        Alert
        Audit
        Metric
        Module(name)
        +name() str
        +parse(str) EventKind
    }
    class codec {
        <<module>>
        +encode(StoredEvent) Row
        +decode(Row) StoredEvent
        +to_millis() / from_millis()
    }
    class Registry {
        +new() Registry
        +with_builtin() Registry
        +register(StorageFactory)
        +kinds() str[]
        +build_state(BackendConfig)
        +build_sink(SinkConfig)
    }
    class StorageManager {
        +from_config(Registry, StorageConfig)
        +state() StateStore
        +sinks() EventSink[]
        +migrate()
        +publish(StoredEvent[])
    }
    class SqliteStore {
        built
        +schema_version() u32
        +with_clock(Clock)
    }
    class SqliteSink {
        built
        +schema_version() u32
        +with_clock(Clock)
    }
    class PostgresStore {
        stub, phase 12
    }
    class PostgresSink {
        stub, phase 12
    }

    StorageFactory <|.. SqliteFactory
    StorageFactory <|.. PostgresFactory
    StateStore <|.. SqliteStore
    StateStore <|.. PostgresStore
    EventSink <|.. SqliteSink
    EventSink <|.. PostgresSink
    Registry o-- StorageFactory
    StorageManager --> Registry : builds from
    StorageManager o-- "1" StateStore
    StorageManager o-- "0..*" EventSink
    EventSink ..> StoredEvent : writes / reads
    StoredEvent ..> EventKind
    SqliteSink ..> codec : row layout
    PostgresSink ..> codec : row layout
```

## 5. Module framework

```mermaid
classDiagram
    class Module {
        <<trait>>
        +manifest() Manifest
        +configure(ConfigDoc) Reload
        +start(ModuleContext)
        +pause()
        +resume()
        +stop()
        +health() ModuleHealth
        +effective_config() Table
        +flow_hook() FlowHook
        +source() Source
    }
    class FlowHook {
        <<trait>>
        +on_flow(FlowContext) HookOutput
    }
    class Source {
        <<trait>>
        +interval() Duration
        +tick(now)
    }
    class Emitter {
        <<trait>>
        +record(ModuleRecord)
        +metric(MetricSample)
        +put_state(key, value)
    }
    class Manifest {
        id
        version
        records: RecordKind[]
        metrics: str[]
        calls: Call[] (read / control)
        needs: payload, privileges
        +validate()
    }
    class ConfigDoc {
        +section(id) T
        +get(path) T
        +span_of(path)
    }
    class ModuleContext {
        clock: Clock
        emitter: Emitter
        state: stored key → value
    }
    class HookOutput {
        note: JSON value
        signals: Signal[]
    }
    class ModuleHost {
        <<scribed>>
        +new(modules, ConfigDoc)
        +start(clock, emitter_for, state)
        +on_flow(Observation) Notes, Signal[]
        +tick()
        +reconfigure(ConfigDoc)
        +pause() / resume() / stop()
        +status() ModuleStatus[]
    }
    class OutputQueue {
        <<scribed>>
        bounded, drops counted
        +emitter(module) Emitter
        +take() Output[]
    }

    Module --> Manifest
    Module ..> ConfigDoc : reads [modules.id]
    Module ..> ModuleContext : started with
    Module o-- FlowHook
    Module o-- Source
    FlowHook ..> HookOutput
    ModuleContext o-- Emitter
    ModuleHost o-- "0..*" Module
    ModuleHost ..> OutputQueue : emitters
    OutputQueue ..|> Emitter
    Module <|.. UrlModule
    Module <|.. KperfModule : later
```

`scribe-module-conformance` checks every module (manifest, config lines, reload, restart, pause,
time budget, random payloads, declared outputs) before it joins `scribe_daemon::modules::builtin()`.

## 6. Daemon run states

Planned for phase 5 (specs 8.5); `ModuleHost` already provides pause, resume and stop.

```mermaid
stateDiagram-v2
    [*] --> starting
    starting --> running : config, logging, storage, modules started
    running --> degraded : fallback sensor, spooling, buffering, drops
    degraded --> running : fault cleared
    running --> hibernating : scribe daemon hibernate [--for]
    degraded --> hibernating : scribe daemon hibernate [--for]
    hibernating --> running : wakeup, or --for / max_hibernate elapsed
    running --> stopping : SIGTERM, Ctrl-C, service stop
    degraded --> stopping : SIGTERM, Ctrl-C, service stop
    hibernating --> stopping : SIGTERM, Ctrl-C, service stop
    stopping --> [*] : modules stopped, sinks flushed

    note right of hibernating
        sensor detached, modules paused,
        nothing recorded or alerted,
        API and spool replay keep running,
        hibernated alert at start
    end note
```

## 7. Stored data (schema v2)

`state.db` holds the state store tables, `events.db` the event sink tables (one file can hold both).
Timestamps are epoch milliseconds in SQLite and `TIMESTAMPTZ` in Postgres.

```mermaid
erDiagram
    hosts ||--o{ host_ips : "resolves to"
    hosts {
        int id PK
        text name UK
        ms first_seen
        ms last_seen
        int conn_count
        int req_count
        int bytes_out
        bool tls_seen
        bool plaintext_seen
    }
    host_ips {
        int host_id FK
        text ip
        ms expires_at
    }
    baseline_entries {
        text profile PK
        text host PK
        text source "learned | manual"
        ms added_at
    }
    alert_state {
        text key PK "host|process"
        ms last_alerted
        bool acknowledged
    }
    module_state {
        text module PK
        text key PK
        json value
        ms updated_at
    }
    events {
        int id PK
        ms ts
        text kind "flow | alert | audit | module.kind"
        text module "null for core kinds"
        text host
        int schema_version
        json payload
    }
    metrics {
        int id PK
        ms ts
        text module
        text name "module.name"
        json labels
        real value
    }
    schema_migrations {
        int version PK
        ms applied_at
    }
```

## 8. Local API trust boundary

Planned for phase 10 (specs 6.3, 12.1.1).

```mermaid
flowchart LR
    subgraph callers["Local callers"]
        viewer["User in group scribe"]
        admin["root / Administrators<br/>or group scribe-admin"]
        other["Anyone else"]
    end

    subgraph transport["Transport"]
        sock["Unix socket in root:scribe 0750 dir<br/>or named pipe with explicit ACL,<br/>first instance, no remote clients"]
    end

    subgraph scribed["scribed"]
        ident["Caller identity from the OS<br/>SO_PEERCRED · getpeereid · pipe token"]
        check{"Call declared<br/>read or control?"}
        read["Read calls<br/>status · health · hosts · alerts · export"]
        control["Control calls<br/>mode · ack · baseline · reset ·<br/>hibernate · wakeup"]
        audit[("audit events")]
    end

    viewer --> sock
    admin --> sock
    other -. cannot open .-> sock
    sock --> ident --> check
    check -- read --> read
    check -- "control, caller is admin" --> control
    check -- "control, caller is not admin" --> refused["Refused (permission denied)"]
    control --> audit
    refused --> audit
    cliCheck["CLI / UI check the server first:<br/>socket owned by root, pipe server is SYSTEM"] -.-> sock
```
