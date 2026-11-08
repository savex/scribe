-- Schema v2: module records, metric samples and module state (specs 10.3).
-- Runs once (the migration runner records it in schema_migrations).
-- Rows written with schema_version 1 keep their payload layout: v1 flows carry "url", v2 flows
-- carry "notes" ({"url": ...}); readers convert v1 rows.

-- events: `kind` is no longer limited to the core kinds; module records name their module.
CREATE TABLE events_v2 (
    id             INTEGER PRIMARY KEY,
    ts             INTEGER NOT NULL,
    kind           TEXT    NOT NULL CHECK (
                       kind IN ('flow', 'alert', 'audit')
                       OR (module IS NOT NULL AND kind LIKE module || '.%')
                   ),
    module         TEXT,
    host           TEXT,
    schema_version INTEGER NOT NULL,
    payload        TEXT    NOT NULL
);
INSERT INTO events_v2 (id, ts, kind, module, host, schema_version, payload)
    SELECT id, ts, kind, NULL, host, schema_version, payload FROM events;
DROP TABLE events;
ALTER TABLE events_v2 RENAME TO events;
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_host_ts ON events(host, ts);
CREATE INDEX IF NOT EXISTS events_module_kind_ts ON events(module, kind, ts);

-- Metric samples from any module; names are `<module>.<name>`.
CREATE TABLE IF NOT EXISTS metrics (
    id     INTEGER PRIMARY KEY,
    ts     INTEGER NOT NULL,
    module TEXT    NOT NULL,
    name   TEXT    NOT NULL CHECK (name LIKE module || '.%'),
    labels TEXT    NOT NULL DEFAULT '{}',
    value  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS metrics_name_ts ON metrics(name, ts);

-- Each module's own state: key -> JSON value.
CREATE TABLE IF NOT EXISTS module_state (
    module     TEXT    NOT NULL,
    key        TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (module, key)
);
