-- Schema v3: per process + host counters (FR-9) and the unresolved flag on hosts (FR-7).

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS unresolved BOOLEAN NOT NULL DEFAULT false;
UPDATE hosts SET unresolved = true
    WHERE name ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' OR name LIKE '%:%';

CREATE TABLE IF NOT EXISTS process_hosts (
    process    TEXT        NOT NULL,
    host       TEXT        NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    conn_count BIGINT      NOT NULL DEFAULT 0,
    req_count  BIGINT      NOT NULL DEFAULT 0,
    bytes_out  BIGINT      NOT NULL DEFAULT 0,
    PRIMARY KEY (process, host)
);
CREATE INDEX IF NOT EXISTS process_hosts_host ON process_hosts(host);
