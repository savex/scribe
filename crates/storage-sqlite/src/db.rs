//! The SQLite connection: opened on first use, WAL mode, migrations tracked in `schema_migrations`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};
use scribe_core::{Clock, SystemClock};
use scribe_storage_api::codec::to_millis;
use scribe_storage_api::{Health, Result, StorageError};

use crate::MIGRATIONS;

/// How long a writer waits for a lock held by another connection.
const BUSY_TIMEOUT_MS: u32 = 5_000;

pub(crate) struct Db {
    path: PathBuf,
    conn: Mutex<Option<Connection>>,
    pub(crate) clock: Arc<dyn Clock>,
}

pub(crate) fn backend(e: rusqlite::Error) -> StorageError {
    StorageError::backend(e)
}

impl Db {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            conn: Mutex::new(None),
            clock: Arc::new(SystemClock),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn now_ms(&self) -> i64 {
        to_millis(self.clock.now())
    }

    /// Run `f` on the connection, opening it first if needed. Calls are short and serialized;
    /// the storage manager gives each backend its own task (plan phase 2).
    pub(crate) fn with<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>,
    ) -> Result<T> {
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            *guard = Some(open(&self.path).map_err(|e| {
                StorageError::Config(format!("sqlite: cannot open {}: {e}", self.path.display()))
            })?);
        }
        f(guard.as_mut().expect("opened above")).map_err(backend)
    }

    /// The highest applied migration, 0 for an empty database.
    pub(crate) fn version(&self) -> Result<u32> {
        self.with(|c| current_version(c))
    }

    /// Apply the migrations this database lacks, each in its own transaction.
    pub(crate) fn migrate(&self) -> Result<u32> {
        let now = self.now_ms();
        let latest = MIGRATIONS.len() as u32;
        let current = self.version()?;
        if current > latest {
            return Err(StorageError::Data(format!(
                "{} has schema version {current}, newer than this scribed reads ({latest})",
                self.path.display()
            )));
        }
        for version in current + 1..=latest {
            self.with(|c| {
                let tx = c.transaction()?;
                tx.execute_batch(MIGRATIONS[version as usize - 1])?;
                tx.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![version, now],
                )?;
                tx.pragma_update(None, "user_version", version)?;
                tx.commit()
            })?;
        }
        Ok(latest)
    }

    pub(crate) fn health(&self) -> Health {
        match self.version() {
            Ok(v) if v == MIGRATIONS.len() as u32 => Health::Ok,
            Ok(v) => Health::Degraded(format!(
                "{}: schema version {v}, expected {}; migration pending",
                self.path.display(),
                MIGRATIONS.len()
            )),
            Err(e) => Health::Down(e.to_string()),
        }
    }
}

fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS.into()))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(conn)
}

fn current_version(c: &Connection) -> rusqlite::Result<u32> {
    let exists: Option<i64> = c
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Ok(0);
    }
    c.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )
}
