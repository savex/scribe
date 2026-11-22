-- Schema v3: per process + host counters (FR-9) and the unresolved flag on hosts (FR-7).
-- Runs once (the migration runner records it in schema_migrations).

-- 1 when the host is an IP or only an ECH outer name was seen; only ever turns on.
ALTER TABLE hosts ADD COLUMN unresolved INTEGER NOT NULL DEFAULT 0;
-- Hosts stored before v3 that are IPs are unresolved by definition.
UPDATE hosts SET unresolved = 1
    WHERE name GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' OR name LIKE '%:%';

CREATE TABLE IF NOT EXISTS process_hosts (
    process    TEXT    NOT NULL,
    host       TEXT    NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    conn_count INTEGER NOT NULL DEFAULT 0,
    req_count  INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (process, host)
);
CREATE INDEX IF NOT EXISTS process_hosts_host ON process_hosts(host);
