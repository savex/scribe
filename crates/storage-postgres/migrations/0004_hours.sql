-- Schema v4: hourly counter buckets per host (FR-9). `hour` is the start of the hour.

CREATE TABLE IF NOT EXISTS host_hours (
    host       TEXT        NOT NULL,
    hour       TIMESTAMPTZ NOT NULL,
    conn_count BIGINT      NOT NULL DEFAULT 0,
    req_count  BIGINT      NOT NULL DEFAULT 0,
    bytes_out  BIGINT      NOT NULL DEFAULT 0,
    PRIMARY KEY (host, hour)
);
CREATE INDEX IF NOT EXISTS host_hours_hour ON host_hours(hour);
