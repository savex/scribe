# Raw sensor records

Input for the decoding half of each native sensor: the raw records the OS hands us, the
`Observation`s the decoder must produce, and what enrichment and modules add on top. Decoding tests
need no privileges.

**Status:** `linux-ebpf` is **synthetic** in the final layout (phase 7): kernel records
(`struct scribe_flow` v1, `crates/sensor-linux/src/bpf/scribe.h`) plus a pcap fixture with the
packets the socket filter passes; test FUN-SN02 joins them. `windows-etw` and `macos-ne` are
**draft**: their layouts follow the planned designs (ETW provider fields, XPC message). Replace
them with records captured in lab VMs once each sensor exists.

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
  `exe`, `cgroup_id`, `src`, `dst`), `packets` (a pcap fixture) and `observations` (all but closes,
  which must carry the process too; `head` true / false for whether client bytes came along).
- `http_keepalive.json` covers the second request on a kept-alive connection (a `payload` observation).
