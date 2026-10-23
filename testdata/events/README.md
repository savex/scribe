# Raw sensor records

Input for the decoding half of each native sensor: the raw record the OS hands us, and the
`FlowEvent` fields the decoder must produce. Decoding tests need no privileges.

**Status: draft.** The record layouts follow the planned designs (eBPF struct, ETW provider
fields, XPC message). Replace them with records captured in lab VMs once each sensor exists.

File layout:

```json
{
  "source": "linux-ebpf | windows-etw | macos-ne",
  "status": "draft",
  "description": "...",
  "records": [ ... raw records, in arrival order ... ],
  "expected": [ ... FlowEvent fields; omitted fields are not checked ... ]
}
```
