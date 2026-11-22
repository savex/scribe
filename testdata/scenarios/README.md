# Daemon scenarios

Each file describes one isolated daemon test: the pipeline runs with `FakeSensor`,
`MemoryStore`, `MemorySink`, `RecordingAlertSink` and `FakeClock`, plays `events`, and
compares the final state with `expect`. The runner arrives with the policy engine (plan phase 4).

## Format

```yaml
name: caution-raw-ip-alerts          # unique, matches the file name
description: One sentence on what is being proven.
mode: caution                        # learn | caution | alert
learn_for: 7d                        # optional; learn mode only
then: caution                        # mode to switch to when learn_for ends
profile: default                     # baseline profile
baseline:                            # hosts already on the list
  - api.example.com
dedupe_window: 10m                   # optional, default 10m
max_hibernate: 4h                    # optional, default 4h (daemon.max_hibernate)
modules: [url]                       # optional, default [url]; test modules: tag, ticks
threat_list: [evil.example.net]      # optional: hosts / IPs on a configured threat list
scores: { "tag.large_head": 60 }     # optional: scores for module signals

events:                              # played in order
  - at: 0s                           # offset from the scenario start (FakeClock)
    dst: "192.0.2.10:443"            # ip:port, IPv6 as "[2001:db8::1]:443"
    proto: tcp                       # tcp | udp | quic (default tcp)
    host: api.example.com            # optional, as the enrichment layer would set it
    security: tls                    # tls | quic | plaintext | unknown
    ech: true                        # optional: host is only the ECH outer name
    head_bytes: 2048                 # optional: size of the client bytes the sensor passes on
    process: /usr/bin/curl           # optional
    pid: 100                         # optional
    bytes: 512                       # optional, default 0
    kind: new_flow                   # new_flow | request | close (default new_flow)
    url: "http://..."                # optional, request events only
  - api: { set_mode: alert }         # optional: call the local API at this point
    at: 5m
  # Other API actions: { ack: <alert index, 0-based> }, { baseline_add: host }, { baseline_rm: host },
  # { hibernate: { for: 30m } }, { wakeup: true }, { reset: [counters, caches, config] }

expect:
  mode: caution                      # optional: mode at the end
  run_state: running                 # optional: running | degraded | hibernating
  alerts:                            # exact list, in order; [] means no alerts at all
    - host: null
      dst: "198.51.100.7:8443"
      process: /opt/agent/bin/agent  # optional
      reason: raw_ip                 # rule id from the policy engine
                                     # daemon alerts (hibernated) have host and dst null
      notes: { url: "http://..." }   # optional: notes the alert must carry
  baseline_added: []                 # hosts added during the run
  hosts:                             # optional: counters for listed hosts only;
                                     # flows with no hostname are keyed by IP
    api.example.com: { connections: 1, requests: 0, bytes: 512, tls_seen: true, plaintext_seen: false }
    192.0.2.60: { connections: 1, unresolved: true }   # unresolved = no name, or only an ECH outer name
  processes:                         # optional: per process + host counters (FR-9)
    /usr/bin/curl: { api.example.com: { connections: 1, bytes: 512 } }
  signals: [tag.large_head]          # optional: module signals the policy engine received
  runtime: { flows: 0 }              # optional: runtime counters from `scribe daemon status`
```

`kind: request` with `url` is shorthand: the runner builds the HTTP GET bytes a sensor would pass on
(`FlowBuilder::http_get`, a `FlowKind::Payload` observation) and the URL module turns them into the
`url` note. Alerts that show a URL read it from that note.

Reason ids used so far: `unlisted_host`, `raw_ip`, `unusual_port`, `high_entropy`,
`plaintext`, `new_process`, `new_tld`, `threat_list`, `hibernated`, and module reasons such as
`tag.large_head`.

**Depends on later phases.** Request counters and URL notes need the URL module's parser (phase 3);
the runner needs the policy engine (phase 4); `hibernate`, `wakeup` and `reset` need the daemon run
states (phase 5). Scenarios that use them say so in their description.
