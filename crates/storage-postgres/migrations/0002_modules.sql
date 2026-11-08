-- Schema v2: module records, metric samples and module state (specs 10.3). Idempotent.
-- Rows written with schema_version 1 keep their payload layout: v1 flows carry "url", v2 flows
-- carry "notes" ({"url": ...}); readers convert v1 rows.

-- events: `kind` is no longer limited to the core kinds; module records name their module.
ALTER TABLE events ADD COLUMN IF NOT EXISTS module TEXT;
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_kind_check;
ALTER TABLE events ADD CONSTRAINT events_kind_check CHECK (
    kind IN ('flow', 'alert', 'audit')
    OR (module IS NOT NULL AND kind LIKE module || '.%')
);
CREATE INDEX IF NOT EXISTS events_module_kind_ts ON events(module, kind, ts);

-- Metric samples from any module; names are `<module>.<name>`.
CREATE TABLE IF NOT EXISTS metrics (
    id     BIGSERIAL        PRIMARY KEY,
    ts     TIMESTAMPTZ      NOT NULL,
    module TEXT             NOT NULL,
    name   TEXT             NOT NULL CHECK (name LIKE module || '.%'),
    labels JSONB            NOT NULL DEFAULT '{}',
    value  DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS metrics_name_ts ON metrics(name, ts);

-- Each module's own state: key -> JSON value.
CREATE TABLE IF NOT EXISTS module_state (
    module     TEXT        NOT NULL,
    key        TEXT        NOT NULL,
    value      JSONB       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (module, key)
);
