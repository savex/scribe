-- Schema v4: hourly counter buckets per host (FR-9). `hour` is the start of the hour, epoch ms.
-- Runs once (the migration runner records it in schema_migrations).

CREATE TABLE IF NOT EXISTS host_hours (
    host       TEXT    NOT NULL,
    hour       INTEGER NOT NULL,
    conn_count INTEGER NOT NULL DEFAULT 0,
    req_count  INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host, hour)
);
CREATE INDEX IF NOT EXISTS host_hours_hour ON host_hours(hour);
