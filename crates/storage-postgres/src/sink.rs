//! The Postgres event sink (plan option 12C): flow, alert, audit, module and metric records for
//! a fleet-wide history (UC-9).
//!
//! A worker thread owns the connection and runs a small tokio runtime of its own, so the sink
//! works under scribed's runtime and under the conformance suite's plain `block_on` alike; the
//! storage manager's writer task, spool and retention sit in front of it as for any sink. A lost
//! connection is opened again on the next request.

use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, SystemTime};

use scribe_storage_api::codec::{decode, encode, from_millis, to_millis, Row};
use scribe_storage_api::{
    EventKind, EventQuery, Health, Page, Result, StorageError, StoredEvent, SCHEMA_VERSION,
};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;

use crate::conn::Settings;
use crate::{KIND, MIGRATIONS};

/// Serialises scribed processes that migrate the same database.
const MIGRATION_LOCK: i64 = 0x7363_7269_6265; // "scribe"
/// Longest wait for the health check.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

enum Request {
    Migrate(oneshot::Sender<Result<()>>),
    Write(Vec<StoredEvent>, oneshot::Sender<Result<()>>),
    Query(EventQuery, oneshot::Sender<Result<Page<StoredEvent>>>),
    DeleteBefore(SystemTime, oneshot::Sender<Result<u64>>),
    Health(oneshot::Sender<Health>),
}

fn backend(context: &str, e: tokio_postgres::Error) -> StorageError {
    StorageError::Backend(format!("{KIND}: {context}: {e}").into())
}

/// The worker side: one connection, opened when needed.
struct Worker {
    settings: Settings,
    client: Option<Client>,
}

impl Worker {
    async fn client(&mut self) -> Result<&Client> {
        if self.client.as_ref().is_none_or(Client::is_closed) {
            self.client = Some(self.settings.connect().await?);
        }
        Ok(self.client.as_ref().expect("connected above"))
    }

    async fn handle(&mut self, request: Request) {
        match request {
            Request::Migrate(reply) => {
                let _ = reply.send(self.migrate().await);
            }
            Request::Write(batch, reply) => {
                let _ = reply.send(self.write(&batch).await);
            }
            Request::Query(q, reply) => {
                let _ = reply.send(self.query(&q).await);
            }
            Request::DeleteBefore(cutoff, reply) => {
                let _ = reply.send(self.delete_before(cutoff).await);
            }
            Request::Health(reply) => {
                let health = match tokio::time::timeout(HEALTH_TIMEOUT, self.ping()).await {
                    Ok(Ok(())) => Health::Ok,
                    Ok(Err(e)) => Health::Down(e.to_string()),
                    Err(_) => Health::Down(format!(
                        "{KIND} {}: no answer in {}s",
                        self.settings.label,
                        HEALTH_TIMEOUT.as_secs()
                    )),
                };
                let _ = reply.send(health);
            }
        }
    }

    async fn ping(&mut self) -> Result<()> {
        self.client()
            .await?
            .simple_query("SELECT 1")
            .await
            .map(drop)
            .map_err(|e| backend("health", e))
    }

    /// Apply the migrations the database lacks, each in its own transaction, under an advisory
    /// lock; a database newer than this scribed is refused.
    async fn migrate(&mut self) -> Result<()> {
        let label = self.settings.label.clone();
        let client = self.client().await?;
        client
            .execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK])
            .await
            .map_err(|e| backend("migration lock", e))?;
        let result = async {
            let exists: Option<String> = client
                .query_one("SELECT to_regclass('schema_migrations')::text", &[])
                .await
                .map_err(|e| backend("schema version", e))?
                .get(0);
            let current: i32 = if exists.is_some() {
                client
                    .query_one("SELECT coalesce(max(version), 0) FROM schema_migrations", &[])
                    .await
                    .map_err(|e| backend("schema version", e))?
                    .get(0)
            } else {
                0
            };
            let latest = MIGRATIONS.len() as i32;
            if current > latest {
                return Err(StorageError::Data(format!(
                    "{KIND} {label} has schema version {current}, newer than this scribed reads ({latest})"
                )));
            }
            for version in current + 1..=latest {
                let sql = MIGRATIONS[(version - 1) as usize];
                client
                    .batch_execute(&format!(
                        "BEGIN;\n{sql}\nINSERT INTO schema_migrations (version) VALUES ({version}) ON CONFLICT DO NOTHING;\nCOMMIT;"
                    ))
                    .await
                    .map_err(|e| backend(&format!("migration {version}"), e))?;
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = client.batch_execute("ROLLBACK").await;
        }
        let _ = client
            .execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK])
            .await;
        result
    }

    /// One statement for the whole batch, so it is stored entirely or not at all.
    async fn write(&mut self, batch: &[StoredEvent]) -> Result<()> {
        let (mut ts, mut kind, mut module, mut host, mut schema, mut payload) =
            (vec![], vec![], vec![], vec![], vec![], vec![]);
        let (mut m_ts, mut m_module, mut m_name, mut m_labels, mut m_value) =
            (vec![], vec![], vec![], vec![], vec![]);
        for e in batch {
            if let StoredEvent::Metric(m) = e {
                m_ts.push(from_millis(to_millis(m.ts)));
                m_module.push(m.module.to_string());
                m_name.push(m.name.to_string());
                m_labels.push(serde_json::to_value(&m.labels).expect("string map"));
                m_value.push(m.value);
            } else {
                let row = encode(e);
                // Millisecond times, as SQLite stores them, so both backends read back alike.
                ts.push(from_millis(to_millis(row.ts)));
                kind.push(row.kind);
                module.push(row.module);
                host.push(row.host);
                schema.push(row.schema as i32);
                payload.push(row.payload);
            }
        }
        let client = self.client().await?;
        client
            .execute(
                "WITH e AS (
                     INSERT INTO events (ts, kind, module, host, schema_version, payload)
                     SELECT * FROM unnest($1::timestamptz[], $2::text[], $3::text[], $4::text[],
                                          $5::int4[], $6::jsonb[])
                 ), m AS (
                     INSERT INTO metrics (ts, module, name, labels, value)
                     SELECT * FROM unnest($7::timestamptz[], $8::text[], $9::text[], $10::jsonb[],
                                          $11::float8[])
                 )
                 SELECT 1",
                &[
                    &ts, &kind, &module, &host, &schema, &payload, &m_ts, &m_module, &m_name,
                    &m_labels, &m_value,
                ],
            )
            .await
            .map(drop)
            .map_err(|e| backend("write", e))
    }

    /// Events and metric samples matching `q`, oldest first (by time, then events before
    /// metrics, then insertion order), with the total count, as the SQLite sink returns them.
    async fn query(&mut self, q: &EventQuery) -> Result<Page<StoredEvent>> {
        let event_kinds: Vec<String> = q
            .kinds
            .iter()
            .filter(|k| **k != EventKind::Metric)
            .map(|k| k.name().to_string())
            .collect();
        let with_events = q.kinds.is_empty() || !event_kinds.is_empty();
        let with_metrics = q.kinds.is_empty() || q.kinds.contains(&EventKind::Metric);
        if !with_events && !with_metrics {
            return Ok(Page {
                items: Vec::new(),
                total: Some(0),
            });
        }
        let since = q.since.map(|t| from_millis(to_millis(t)));
        let until = q.until.map(|t| from_millis(to_millis(t)));
        let mut args: Vec<Box<dyn ToSql + Sync + Send>> = vec![Box::new(since), Box::new(until)];
        let time = "($1::timestamptz IS NULL OR ts >= $1) AND ($2::timestamptz IS NULL OR ts < $2)";
        let mut selects = Vec::new();
        if with_events {
            let mut filter = time.to_owned();
            if !q.kinds.is_empty() {
                args.push(Box::new(event_kinds));
                filter.push_str(&format!(" AND kind = ANY(${}::text[])", args.len()));
            }
            selects.push(format!(
                "SELECT ts, kind, module, host, schema_version, payload, 0 AS src, id
                 FROM events WHERE {filter}"
            ));
        }
        if with_metrics {
            selects.push(format!(
                "SELECT ts, 'metric'::text, module, NULL::text, {SCHEMA_VERSION}::int4,
                        jsonb_build_object('name', name, 'labels', labels, 'value', value), 1, id
                 FROM metrics WHERE {time}"
            ));
        }
        let union = selects.join(" UNION ALL ");
        let client = self.client().await?;
        let params: Vec<&(dyn ToSql + Sync)> = args
            .iter()
            .map(|a| a.as_ref() as &(dyn ToSql + Sync))
            .collect();
        let total: i64 = client
            .query_one(&format!("SELECT count(*) FROM ({union}) u"), &params)
            .await
            .map_err(|e| backend("count", e))?
            .get(0);
        let limit = q.limit.map(|n| i64::try_from(n).unwrap_or(i64::MAX));
        let offset = i64::try_from(q.offset).unwrap_or(i64::MAX);
        let n = args.len();
        let mut paged = params.clone();
        paged.push(&limit);
        paged.push(&offset);
        let rows = client
            .query(
                &format!(
                    "SELECT * FROM ({union}) u ORDER BY 1, 7, 8 LIMIT ${} OFFSET ${}",
                    n + 1,
                    n + 2
                ),
                &paged,
            )
            .await
            .map_err(|e| backend("query", e))?;
        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            let ts: SystemTime = r.get(0);
            let schema: i32 = r.get(4);
            items.push(decode(Row {
                ts,
                kind: r.get(1),
                module: r.get(2),
                host: r.get(3),
                schema: schema as u32,
                payload: r.get::<_, Value>(5),
            })?);
        }
        Ok(Page {
            items,
            total: u64::try_from(total).ok(),
        })
    }

    async fn delete_before(&mut self, cutoff: SystemTime) -> Result<u64> {
        let cutoff = from_millis(to_millis(cutoff));
        let client = self.client().await?;
        let removed: i64 = client
            .query_one(
                "WITH e AS (DELETE FROM events WHERE ts < $1 RETURNING 1),
                      m AS (DELETE FROM metrics WHERE ts < $1 RETURNING 1)
                 SELECT (SELECT count(*) FROM e) + (SELECT count(*) FROM m)",
                &[&cutoff],
            )
            .await
            .map_err(|e| backend("retention", e))?
            .get(0);
        Ok(removed as u64)
    }
}

/// The caller side: requests go to the worker thread, which is started on first use and ends
/// when the sink is dropped.
pub struct Connection {
    settings: Settings,
    worker: OnceLock<mpsc::UnboundedSender<Request>>,
}

impl Connection {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            worker: OnceLock::new(),
        }
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    fn worker(&self) -> &mpsc::UnboundedSender<Request> {
        self.worker.get_or_init(|| {
            let (tx, mut rx) = mpsc::unbounded_channel::<Request>();
            let settings = self.settings.clone();
            thread::Builder::new()
                .name(format!("postgres:{}", settings.label))
                .spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    runtime.block_on(async move {
                        let mut worker = Worker {
                            settings,
                            client: None,
                        };
                        while let Some(request) = rx.recv().await {
                            worker.handle(request).await;
                        }
                    });
                })
                .expect("cannot start the Postgres worker thread");
            tx
        })
    }

    async fn ask<T>(&self, make: impl FnOnce(oneshot::Sender<T>) -> Request, gone: T) -> T {
        let (tx, rx) = oneshot::channel();
        if self.worker().send(make(tx)).is_err() {
            return gone;
        }
        rx.await.unwrap_or(gone)
    }

    fn stopped() -> StorageError {
        StorageError::Backend(format!("{KIND}: worker thread stopped").into())
    }

    pub async fn migrate(&self) -> Result<()> {
        self.ask(Request::Migrate, Err(Self::stopped())).await
    }

    pub async fn write(&self, batch: Vec<StoredEvent>) -> Result<()> {
        self.ask(|tx| Request::Write(batch, tx), Err(Self::stopped()))
            .await
    }

    pub async fn query(&self, q: EventQuery) -> Result<Page<StoredEvent>> {
        self.ask(|tx| Request::Query(q, tx), Err(Self::stopped()))
            .await
    }

    pub async fn delete_before(&self, cutoff: SystemTime) -> Result<u64> {
        self.ask(|tx| Request::DeleteBefore(cutoff, tx), Err(Self::stopped()))
            .await
    }

    pub async fn health(&self) -> Health {
        self.ask(
            Request::Health,
            Health::Down(format!("{KIND}: worker thread stopped")),
        )
        .await
    }
}
