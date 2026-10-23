CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER     PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hosts (
    id             BIGSERIAL   PRIMARY KEY,
    name           TEXT        NOT NULL UNIQUE,
    first_seen     TIMESTAMPTZ NOT NULL,
    last_seen      TIMESTAMPTZ NOT NULL,
    conn_count     BIGINT      NOT NULL DEFAULT 0,
    req_count      BIGINT      NOT NULL DEFAULT 0,
    bytes_out      BIGINT      NOT NULL DEFAULT 0,
    tls_seen       BOOLEAN     NOT NULL DEFAULT false,
    plaintext_seen BOOLEAN     NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS host_ips (
    host_id    BIGINT      NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ip         INET        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host_id, ip)
);
CREATE INDEX IF NOT EXISTS host_ips_ip ON host_ips(ip);

CREATE TABLE IF NOT EXISTS baseline_entries (
    profile  TEXT        NOT NULL,
    host     TEXT        NOT NULL,
    source   TEXT        NOT NULL CHECK (source IN ('learned', 'manual')),
    added_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (profile, host)
);

CREATE TABLE IF NOT EXISTS alert_state (
    key          TEXT        PRIMARY KEY,
    last_alerted TIMESTAMPTZ NOT NULL,
    acknowledged BOOLEAN     NOT NULL DEFAULT false
);

-- Event sink table: flow / alert / audit records.
CREATE TABLE IF NOT EXISTS events (
    id             BIGSERIAL   PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL,
    kind           TEXT        NOT NULL CHECK (kind IN ('flow', 'alert', 'audit')),
    host           TEXT,
    schema_version INTEGER     NOT NULL,
    payload        JSONB       NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_host_ts ON events(host, ts);
