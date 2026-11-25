# Raw sensor records

Input for the decoding half of each native sensor: the raw records the OS hands us, the
`Observation`s the decoder must produce, and what enrichment and modules add on top. Decoding tests
need no privileges.

**Status:** `linux-ebpf` is **synthetic** in the final layout (phase 7): kernel records
(`struct scribe_flow` v2, `crates/sensor-linux/src/bpf/scribe.h`) plus a pcap fixture with the
packets the socket filter passes; test FUN-SN02 joins them. `windows-etw` is **synthetic** too
(phase 8): Kernel-Network and DNS-Client events, with a pcap fixture for what Npcap would capture or
without one (ETW alone); test FUN-SN03. `macos-ne` is **draft**: its layout follows the planned
design (XPC message). Replace samples with records captured in lab VMs where they differ.

File layout:

```json
{
  "source": "linux-ebpf | windows-etw | macos-ne",
  "status": "draft | synthetic",
  "description": "...",
  "records": [ ... raw records, in arrival order ... ],
  "observations": [ ... decoder output: FlowEvent fields plus "head" ... ],
  "enriched": [ ... after enrichment and modules: hostname, security, ech, notes ... ]
}
```

- Omitted fields are not checked.
- `head` is `null` (no client bytes) or `{ "pcap": "<fixture>", "client_segment": n }`: the n-th client
  payload segment of that pcap fixture, cut to `HEAD_MAX` (4 KiB). Windows ETW gives no payload, so its
  heads are `null` until Npcap is used (plan phase 8).
- The decoder sets only what the OS reports. Host names from SNI, `Host` or DNS appear in `enriched`;
  the macOS Network Extension is the exception, since the OS hands over `remote_hostname` itself.
- `linux-ebpf` files have `records` (`kind` `tcp_connect` / `udp_send`, `tgid`, `pid`, `uid`, `comm`,
  `exe` (the path the kernel reads), `cgroup_id`, `src`, `dst`), `packets` (a pcap fixture) and `observations` (all but closes,
  which must carry the process too; `head` true / false for whether client bytes came along).
- `windows-etw` files have `events` (`event` `tcp_connect` / `udp_send` with `pid`, `exe` (what the path
  lookup returns), `src`, `dst`; `dns_query` with `pid`, `name`, `qtype`, `status`, `results` as
  Windows formats them; optional `at_ms` since the first event), `packets` (a pcap fixture, or `null`
  without Npcap: flows from the events alone) and `observations`; `enriched` is checked through the
  DNS cache and enrichment.
- `http_keepalive.json` covers the second request on a kept-alive connection (a `payload` observation).
