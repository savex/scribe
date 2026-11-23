# UI tests

The UI talks to `scribed` only through the local API, so every UI test runs against
`MockApiServer` and never needs a daemon, capture rights or real traffic.

| Folder | Tool | Contents |
|---|---|---|
| `components/` | Vitest + Testing Library | Host table, counters, mode switch, alert list; empty / loading / error states |
| `e2e/` | Playwright against the mock API | Switch mode, add host to list from an alert, acknowledge alert, filter and search |
| `visual/` | Playwright screenshots | Light / dark, narrow window, long host names |
| `mocks/api-scenarios/` | JSON | What the mock API returns for each scenario below |

Desktop smoke test (`tauri-driver`) runs on Linux and Windows only; on macOS it is manual.

## Mock API scenarios

Each JSON file sets the mock's responses. The API sections (`status`, `hosts`, `alerts`, `baseline`, an
alert `template`, a `status_override`) are the messages of `proto/scribe/v1/api.proto` as JSON: same field
names, times as epoch milliseconds (`*_ms`). The smoke test `ui_mocks` parses every file against them and
refuses unknown fields, so the mocks change together with `proto/`. `degraded` is a health result, never a
`run_state` (`running` or `hibernating`).

`MockApiServer` (`crates/test-support`, feature `mock-api`) serves a scenario over the real transport;
control calls change its state. For UI development:

```bash
cargo run -p scribe-test-support --features mock-api --bin scribe-mock-api -- typical /tmp/scribe-mock.sock
```

then `SCRIBE_SOCKET=/tmp/scribe-mock.sock scribe status` (or point the UI at the socket). `connect`,
`stream` and `timeline` are for the UI's own harness and aren't played by the mock server.

| File | Proves the UI handles |
|---|---|
| `daemon-down.json` | Connection refused: clear message, retry, no crash |
| `empty-first-launch.json` | Learn mode, no hosts yet |
| `typical.json` | Normal day in caution mode with a few alerts |
| `many-hosts.json` | 10,000 generated hosts: paging and scrolling stay fast |
| `alert-burst.json` | 100 alerts per second for 10 s: list stays responsive, notifications grouped |
| `daemon-restart.json` | Stream drops and reconnects while the UI is open |
| `version-mismatch.json` | Daemon API newer than the UI: upgrade message |
| `hibernating.json` | Daemon hibernating on purpose: banner with the planned end, `hibernated` alert, wakeup action |
| `degraded-drops.json` | Degraded daemon: fallback sensor, spooling sink, drops; critical metrics listed first |
| `module-failed.json` | A module switched off after a fault; the rest keeps working |

Status messages carry the run state, live counters, critical metrics and a per-module section
(`scribe daemon status`, specs 6.2.1); alerts carry module notes (the URL for plaintext alerts), and
hosts carry `unresolved` and `ech`.
