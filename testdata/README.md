# Test data

All data here is generated in the lab or written by hand. **Never commit traffic captured
from a real user.** Addresses come from documentation ranges (192.0.2.0/24, 198.51.100.0/24,
2001:db8::/32) and names use `example.com` / `example.net`, with no exceptions. Real services
are stood in for by documentation addresses (the DoH resolver is `doh.example.net` at
198.51.100.53, put on the resolver list by the test).

| Folder | Contents | Produced by | Used by |
|---|---|---|---|
| `pcap/` | Ethernet pcap fixtures + `<name>.json` expected flows | `cargo run -p scribe-test-support --bin gen-fixtures` | decoder / enrichment tests, pcap sensor |
| `scenarios/` | Daemon scenarios (YAML): mode, baseline, events, expected alerts and counters | hand-written | daemon scenario runner (with the policy engine) |
| `events/` | Raw sensor records per OS (draft formats) | hand-written now, recorded from lab VMs later | eBPF / ETW / Network Extension decoding tests |
| `db/` | Saved databases for each past schema version | `db/build.sh` | migration tests |

Rules:
- `pcap/` is generated: edit `crates/test-support/src/fixtures.rs`, then rerun the generator.
  The test `fixtures_up_to_date` fails if the committed files drift from the generator.
- Every bug fix adds a fixture or scenario that reproduces it.
- Keep files small; large volume data is generated at test time.
