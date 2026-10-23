-- Timestamps are unix epoch milliseconds.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id             INTEGER PRIMARY KEY,
    name           TEXT    NOT NULL UNIQUE,
    first_seen     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    conn_count     INTEGER NOT NULL DEFAULT 0,
    req_count      INTEGER NOT NULL DEFAULT 0,
    bytes_out      INTEGER NOT NULL DEFAULT 0,
    tls_seen       INTEGER NOT NULL DEFAULT 0,
    plaintext_seen INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS host_ips (
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ip         TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (host_id, ip)
);
CREATE INDEX IF NOT EXISTS host_ips_ip ON host_ips(ip);

CREATE TABLE IF NOT EXISTS baseline_entries (
    profile  TEXT    NOT NULL,
    host     TEXT    NOT NULL,
    source   TEXT    NOT NULL CHECK (source IN ('learned', 'manual')),
    added_at INTEGER NOT NULL,
    PRIMARY KEY (profile, host)
);

CREATE TABLE IF NOT EXISTS alert_state (
    key          TEXT    PRIMARY KEY,
    last_alerted INTEGER NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

-- Event sink table: flow / alert / audit records, payload as JSON.
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY,
    ts             INTEGER NOT NULL,
    kind           TEXT    NOT NULL CHECK (kind IN ('flow', 'alert', 'audit')),
    host           TEXT,
    schema_version INTEGER NOT NULL,
    payload        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_host_ts ON events(host, ts);
