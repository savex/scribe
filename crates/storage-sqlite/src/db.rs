//! The SQLite connection lives on its own worker thread, opened on first use (WAL mode);
//! migrations are tracked in `schema_migrations`.
//!
//! Every call is a job sent to that thread; the caller gets a [`Reply`] future, so async callers
//! never block their runtime on SQLite, and the futures work with any executor (the conformance
//! suite uses a minimal one). Jobs run one at a time, in the order they were sent.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread;

use rusqlite::{params, Connection, OptionalExtension};
use scribe_core::{Clock, SystemClock};
use scribe_storage_api::codec::to_millis;
use scribe_storage_api::{Health, Result, StorageError};

use crate::MIGRATIONS;

/// How long a writer waits for a lock held by another connection.
const BUSY_TIMEOUT_MS: u32 = 5_000;

type Job = Box<dyn FnOnce(&mut Option<Connection>, &Path) + Send>;

pub(crate) struct Db {
    path: PathBuf,
    worker: OnceLock<mpsc::Sender<Job>>,
    pub(crate) clock: Arc<dyn Clock>,
}

pub(crate) fn backend(e: rusqlite::Error) -> StorageError {
    StorageError::backend(e)
}

struct Slot<T> {
    value: Option<T>,
    waker: Option<Waker>,
}

/// The result of a job, as a future or by blocking.
pub(crate) struct Reply<T> {
    shared: Arc<(Mutex<Slot<T>>, Condvar)>,
}

impl<T> Reply<T> {
    fn pair() -> (Self, impl FnOnce(T) + Send)
    where
        T: Send + 'static,
    {
        let shared = Arc::new((
            Mutex::new(Slot {
                value: None,
                waker: None,
            }),
            Condvar::new(),
        ));
        let done = {
            let shared = shared.clone();
            move |value: T| {
                let (lock, cvar) = &*shared;
                let mut slot = lock.lock().unwrap_or_else(|p| p.into_inner());
                slot.value = Some(value);
                if let Some(waker) = slot.waker.take() {
                    waker.wake();
                }
                cvar.notify_all();
            }
        };
        (Self { shared }, done)
    }

    /// Block the current thread until the job has run (for synchronous callers).
    pub(crate) fn wait(self) -> T {
        let (lock, cvar) = &*self.shared;
        let mut slot = lock.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(value) = slot.value.take() {
                return value;
            }
            slot = cvar.wait(slot).unwrap_or_else(|p| p.into_inner());
        }
    }
}

impl<T> Future for Reply<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let mut slot = self.shared.0.lock().unwrap_or_else(|p| p.into_inner());
        match slot.value.take() {
            Some(value) => Poll::Ready(value),
            None => {
                slot.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl Db {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            worker: OnceLock::new(),
            clock: Arc::new(SystemClock),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn now_ms(&self) -> i64 {
        to_millis(self.clock.now())
    }

    /// The worker thread, started on first use; it ends when the `Db` is dropped.
    fn worker(&self) -> &mpsc::Sender<Job> {
        self.worker.get_or_init(|| {
            let (tx, rx) = mpsc::channel::<Job>();
            let path = self.path.clone();
            let name = format!(
                "sqlite:{}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            thread::Builder::new()
                .name(name)
                .spawn(move || {
                    let mut conn = None;
                    for job in rx {
                        job(&mut conn, &path);
                    }
                })
                .expect("cannot start the SQLite worker thread");
            tx
        })
    }

    /// Run `f` on the worker thread with an open connection.
    pub(crate) fn run<T, F>(&self, f: F) -> Reply<Result<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply, done) = Reply::pair();
        let job: Job = Box::new(move |conn, path| {
            if conn.is_none() {
                match open(path) {
                    Ok(c) => *conn = Some(c),
                    Err(e) => {
                        return done(Err(StorageError::Config(format!(
                            "sqlite: cannot open {}: {e}",
                            path.display()
                        ))))
                    }
                }
            }
            done(f(conn.as_mut().expect("opened above")));
        });
        if self.worker().send(job).is_err() {
            let (reply, done) = Reply::pair();
            done(Err(StorageError::Data(
                "sqlite worker thread stopped".into(),
            )));
            return reply;
        }
        reply
    }

    /// [`Db::run`] for closures that return `rusqlite` errors.
    pub(crate) fn with<T, F>(&self, f: F) -> Reply<Result<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        self.run(move |c| f(c).map_err(backend))
    }

    /// The highest applied migration, 0 for an empty database.
    pub(crate) fn version(&self) -> Reply<Result<u32>> {
        self.with(current_version)
    }

    /// Apply the migrations this database lacks, each in its own transaction.
    pub(crate) fn migrate(&self) -> Reply<Result<u32>> {
        let now = self.now_ms();
        let path = self.path.clone();
        self.run(move |c| {
            let latest = MIGRATIONS.len() as u32;
            let current = current_version(c).map_err(backend)?;
            if current > latest {
                return Err(StorageError::Data(format!(
                    "{} has schema version {current}, newer than this scribed reads ({latest})",
                    path.display()
                )));
            }
            for version in current + 1..=latest {
                let tx = c.transaction().map_err(backend)?;
                tx.execute_batch(MIGRATIONS[version as usize - 1])
                    .map_err(backend)?;
                tx.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![version, now],
                )
                .map_err(backend)?;
                tx.pragma_update(None, "user_version", version)
                    .map_err(backend)?;
                tx.commit().map_err(backend)?;
            }
            Ok(latest)
        })
    }

    pub(crate) async fn health(&self) -> Health {
        match self.version().await {
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

fn current_version(c: &mut Connection) -> rusqlite::Result<u32> {
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
