//! State store queries. Counters are applied as deltas in one statement (no read-modify-write);
//! `tls_seen` / `plaintext_seen` only turn on.

use std::net::IpAddr;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Row};
use scribe_core::Security;
use scribe_storage_api::codec::{from_millis, to_millis};
use scribe_storage_api::{
    AlertState, Baseline, BaselineEntry, EntrySource, Host, HostDelta, HostId, HostQuery,
    ModuleState, Page,
};

/// SQLite integers are signed; counters beyond `i64::MAX` saturate.
fn int(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn uint(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

const HOST_COLUMNS: &str =
    "id, name, first_seen, last_seen, conn_count, req_count, bytes_out, tls_seen, plaintext_seen";

fn host(r: &Row<'_>) -> rusqlite::Result<Host> {
    Ok(Host {
        id: r.get(0)?,
        name: r.get(1)?,
        first_seen: from_millis(r.get(2)?),
        last_seen: from_millis(r.get(3)?),
        conn_count: uint(r.get(4)?),
        req_count: uint(r.get(5)?),
        bytes_out: uint(r.get(6)?),
        tls_seen: r.get(7)?,
        plaintext_seen: r.get(8)?,
    })
}

pub(crate) fn upsert_host(c: &Connection, d: &HostDelta) -> rusqlite::Result<HostId> {
    let seen = to_millis(d.seen_at);
    c.query_row(
        "INSERT INTO hosts (name, first_seen, last_seen, conn_count, req_count, bytes_out, tls_seen, plaintext_seen)
         VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (name) DO UPDATE SET
             first_seen     = min(first_seen, excluded.first_seen),
             last_seen      = max(last_seen, excluded.last_seen),
             conn_count     = conn_count + excluded.conn_count,
             req_count      = req_count + excluded.req_count,
             bytes_out      = bytes_out + excluded.bytes_out,
             tls_seen       = tls_seen OR excluded.tls_seen,
             plaintext_seen = plaintext_seen OR excluded.plaintext_seen
         RETURNING id",
        params![
            d.name,
            seen,
            int(d.connections),
            int(d.requests),
            int(d.bytes_out),
            d.security == Security::Tls,
            d.security == Security::Plaintext,
        ],
        |r| r.get(0),
    )
}

pub(crate) fn get_host(c: &Connection, name: &str) -> rusqlite::Result<Option<Host>> {
    c.query_row(
        &format!("SELECT {HOST_COLUMNS} FROM hosts WHERE name = ?1"),
        [name],
        host,
    )
    .optional()
}

pub(crate) fn link_ip(
    c: &Connection,
    host: HostId,
    ip: IpAddr,
    ttl: Duration,
    now: i64,
) -> rusqlite::Result<()> {
    let expires = now.saturating_add(i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX));
    c.execute(
        "INSERT INTO host_ips (host_id, ip, expires_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (host_id, ip) DO UPDATE SET expires_at = max(expires_at, excluded.expires_at)",
        params![host, ip.to_string(), expires],
    )?;
    Ok(())
}

/// `%` and `_` in the filter match themselves.
fn like_pattern(text: &str) -> String {
    let escaped = text
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

pub(crate) fn list_hosts(c: &Connection, q: &HostQuery) -> rusqlite::Result<Page<Host>> {
    let pattern = like_pattern(q.name_contains.as_deref().unwrap_or(""));
    let total: i64 = c.query_row(
        "SELECT count(*) FROM hosts WHERE name LIKE ?1 ESCAPE '\\'",
        [&pattern],
        |r| r.get(0),
    )?;
    let limit = q.limit.map_or(-1, |n| i64::try_from(n).unwrap_or(i64::MAX));
    let mut stmt = c.prepare(&format!(
        "SELECT {HOST_COLUMNS} FROM hosts WHERE name LIKE ?1 ESCAPE '\\'
         ORDER BY name LIMIT ?2 OFFSET ?3"
    ))?;
    let items = stmt
        .query_map(params![pattern, limit, int(q.offset as u64)], host)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Page {
        items,
        total: Some(uint(total)),
    })
}

pub(crate) fn baseline(c: &Connection, profile: &str) -> rusqlite::Result<Baseline> {
    let mut stmt = c.prepare(
        "SELECT host, source, added_at FROM baseline_entries WHERE profile = ?1 ORDER BY host",
    )?;
    let entries = stmt
        .query_map([profile], |r| {
            let source: String = r.get(1)?;
            Ok(BaselineEntry {
                host: r.get(0)?,
                source: if source == "manual" {
                    EntrySource::Manual
                } else {
                    EntrySource::Learned
                },
                added_at: from_millis(r.get(2)?),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Baseline {
        profile: profile.to_owned(),
        entries,
    })
}

/// Adding a host that is already listed keeps the first entry.
pub(crate) fn add_to_baseline(
    c: &Connection,
    profile: &str,
    e: &BaselineEntry,
) -> rusqlite::Result<()> {
    let source = match e.source {
        EntrySource::Learned => "learned",
        EntrySource::Manual => "manual",
    };
    c.execute(
        "INSERT INTO baseline_entries (profile, host, source, added_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (profile, host) DO NOTHING",
        params![profile, e.host, source, to_millis(e.added_at)],
    )?;
    Ok(())
}

pub(crate) fn put_alert_state(c: &Connection, s: &AlertState) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO alert_state (key, last_alerted, acknowledged) VALUES (?1, ?2, ?3)
         ON CONFLICT (key) DO UPDATE SET
             last_alerted = excluded.last_alerted, acknowledged = excluded.acknowledged",
        params![s.key, to_millis(s.last_alerted), s.acknowledged],
    )?;
    Ok(())
}

pub(crate) fn get_alert_state(c: &Connection, key: &str) -> rusqlite::Result<Option<AlertState>> {
    c.query_row(
        "SELECT key, last_alerted, acknowledged FROM alert_state WHERE key = ?1",
        [key],
        |r| {
            Ok(AlertState {
                key: r.get(0)?,
                last_alerted: from_millis(r.get(1)?),
                acknowledged: r.get(2)?,
            })
        },
    )
    .optional()
}

pub(crate) fn module_state(c: &Connection, module: &str) -> rusqlite::Result<ModuleState> {
    let mut stmt = c.prepare("SELECT key, value FROM module_state WHERE module = ?1")?;
    let rows = stmt.query_map([module], |r| {
        let key: String = r.get(0)?;
        let text: String = r.get(1)?;
        Ok((key, text))
    })?;
    let mut state = ModuleState::new();
    for row in rows {
        let (key, text) = row?;
        let value = serde_json::from_str(&text).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
        })?;
        state.insert(key, value);
    }
    Ok(state)
}

pub(crate) fn put_module_state(
    c: &Connection,
    module: &str,
    key: &str,
    value: &serde_json::Value,
    now: i64,
) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO module_state (module, key, value, updated_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (module, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![module, key, value.to_string(), now],
    )?;
    Ok(())
}
