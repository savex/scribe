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

events:                              # played in order
  - at: 0s                           # offset from the scenario start (FakeClock)
    dst: "192.0.2.10:443"            # ip:port, IPv6 as "[2001:db8::1]:443"
    proto: tcp                       # tcp | udp | quic (default tcp)
    host: api.example.com            # optional, as the enrichment layer would set it
    security: tls                    # tls | quic | plaintext | unknown
    process: /usr/bin/curl           # optional
    pid: 100                         # optional
    bytes: 512                       # optional, default 0
    kind: new_flow                   # new_flow | request | close (default new_flow)
    url: "http://..."                # optional, request events only
  - api: { set_mode: alert }         # optional: call the local API at this point
    at: 5m

expect:
  mode: caution                      # optional: mode at the end
  alerts:                            # exact list, in order; [] means no alerts at all
    - host: null
      dst: "198.51.100.7:8443"
      process: /opt/agent/bin/agent  # optional
      reason: raw_ip                 # rule id from the policy engine
  baseline_added: []                 # hosts added during the run
  hosts:                             # optional: counters for listed hosts only;
                                     # flows with no hostname are keyed by IP
    api.example.com: { connections: 1, requests: 0, bytes: 512, tls_seen: true, plaintext_seen: false }
```

Reason ids used so far: `unlisted_host`, `raw_ip`, `unusual_port`, `high_entropy`,
`plaintext`, `new_process`, `threat_list`.
