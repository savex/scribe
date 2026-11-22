//! Event sink: rows in `events` (flow, alert, audit, module records) and `metrics`, in the layout of
//! [`scribe_storage_api::codec`]. A batch is one transaction.

use rusqlite::types::ToSql;
use rusqlite::{params, params_from_iter, Connection};
use scribe_storage_api::codec::{decode, encode, from_millis, to_millis, Row};
use scribe_storage_api::{EventKind, EventQuery, Page, StorageError, StoredEvent, SCHEMA_VERSION};
use serde_json::Value;

/// Delete events and metric samples older than `cutoff` (epoch ms) in one transaction.
pub(crate) fn delete_before(c: &mut Connection, cutoff: i64) -> rusqlite::Result<u64> {
    let tx = c.transaction()?;
    let events = tx.execute("DELETE FROM events WHERE ts < ?1", [cutoff])?;
    let metrics = tx.execute("DELETE FROM metrics WHERE ts < ?1", [cutoff])?;
    tx.commit()?;
    Ok((events + metrics) as u64)
}

pub(crate) fn write_batch(c: &mut Connection, batch: &[StoredEvent]) -> rusqlite::Result<()> {
    let tx = c.transaction()?;
    {
        let mut event = tx.prepare_cached(
            "INSERT INTO events (ts, kind, module, host, schema_version, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        let mut metric = tx.prepare_cached(
            "INSERT INTO metrics (ts, module, name, labels, value) VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for e in batch {
            let row = encode(e);
            if let StoredEvent::Metric(m) = e {
                let labels = serde_json::to_string(&m.labels).expect("string map");
                metric.execute(params![
                    to_millis(m.ts),
                    m.module.as_ref(),
                    m.name.as_ref(),
                    labels,
                    m.value
                ])?;
            } else {
                event.execute(params![
                    to_millis(row.ts),
                    row.kind,
                    row.module,
                    row.host,
                    row.schema,
                    row.payload.to_string()
                ])?;
            }
        }
    }
    tx.commit()
}

/// Events and metric samples matching `q`, oldest first (by time, then events before metrics,
/// then insertion order), with the total count.
pub(crate) fn query(c: &Connection, q: &EventQuery) -> Result<Page<StoredEvent>, StorageError> {
    let wants = |k: &EventKind| q.kinds.is_empty() || q.kinds.contains(k);
    let event_kinds: Vec<&str> = q
        .kinds
        .iter()
        .filter(|k| **k != EventKind::Metric)
        .map(EventKind::name)
        .collect();
    let with_events = q.kinds.is_empty() || !event_kinds.is_empty();
    let with_metrics = wants(&EventKind::Metric);

    let mut args: Vec<Box<dyn ToSql>> = Vec::new();
    let time_filter = |args: &mut Vec<Box<dyn ToSql>>| {
        let mut parts = Vec::new();
        if let Some(t) = q.since {
            args.push(Box::new(to_millis(t)));
            parts.push(format!("ts >= ?{}", args.len()));
        }
        if let Some(t) = q.until {
            args.push(Box::new(to_millis(t)));
            parts.push(format!("ts < ?{}", args.len()));
        }
        parts
    };

    let mut selects = Vec::new();
    if with_events {
        let mut filter = time_filter(&mut args);
        if !q.kinds.is_empty() {
            let marks: Vec<String> = event_kinds
                .iter()
                .map(|k| {
                    args.push(Box::new(k.to_string()));
                    format!("?{}", args.len())
                })
                .collect();
            filter.push(format!("kind IN ({})", marks.join(", ")));
        }
        selects.push(format!(
            "SELECT ts, kind, module, host, schema_version, payload, 0 AS src, id FROM events{}",
            where_clause(&filter)
        ));
    }
    if with_metrics {
        let filter = time_filter(&mut args);
        selects.push(format!(
            "SELECT ts, 'metric', module, NULL, {SCHEMA_VERSION},
                    json_object('name', name, 'labels', json(labels), 'value', value), 1 AS src, id
             FROM metrics{}",
            where_clause(&filter)
        ));
    }
    if selects.is_empty() {
        return Ok(Page {
            items: Vec::new(),
            total: Some(0),
        });
    }
    let union = selects.join(" UNION ALL ");

    let backend = StorageError::backend;
    let total: i64 = c
        .query_row(
            &format!("SELECT count(*) FROM ({union})"),
            params_from_iter(args.iter()),
            |r| r.get(0),
        )
        .map_err(backend)?;

    let limit = q.limit.map_or(-1, |n| i64::try_from(n).unwrap_or(i64::MAX));
    let offset = i64::try_from(q.offset).unwrap_or(i64::MAX);
    args.push(Box::new(limit));
    args.push(Box::new(offset));
    let sql = format!(
        "SELECT * FROM ({union}) ORDER BY ts, src, id LIMIT ?{} OFFSET ?{}",
        args.len() - 1,
        args.len()
    );
    let mut stmt = c.prepare(&sql).map_err(backend)?;
    let rows = stmt
        .query_map(params_from_iter(args.iter()), |r| {
            let payload: String = r.get(5)?;
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, u32>(4)?,
                payload,
            ))
        })
        .map_err(backend)?;
    let mut items = Vec::new();
    for row in rows {
        let (ts, kind, module, host, schema, payload) = row.map_err(backend)?;
        let payload: Value = serde_json::from_str(&payload)
            .map_err(|e| StorageError::Data(format!("{kind} record payload: {e}")))?;
        items.push(decode(Row {
            ts: from_millis(ts),
            kind,
            module,
            host,
            schema,
            payload,
        })?);
    }
    Ok(Page {
        items,
        total: u64::try_from(total).ok(),
    })
}

fn where_clause(parts: &[String]) -> String {
    if parts.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", parts.join(" AND "))
    }
}
