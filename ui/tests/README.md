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

Each JSON file sets the mock's responses. Field names follow the planned API messages
(`Status`, `Host`, `Alert`) and change with `proto/` once it exists.

| File | Proves the UI handles |
|---|---|
| `daemon-down.json` | Connection refused: clear message, retry, no crash |
| `empty-first-launch.json` | Learn mode, no hosts yet |
| `typical.json` | Normal day in caution mode with a few alerts |
| `many-hosts.json` | 10,000 generated hosts: paging and scrolling stay fast |
| `alert-burst.json` | 100 alerts per second for 10 s: list stays responsive, notifications grouped |
| `daemon-restart.json` | Stream drops and reconnects while the UI is open |
| `version-mismatch.json` | Daemon API newer than the UI: upgrade message |
