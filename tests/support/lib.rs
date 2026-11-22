//! Helpers shared by the smoke, integration and scenario test binaries of `scribe-tests`.
//! Every helper keeps tests isolated: files go to the caller's temporary folder and snapshots
//! are copied before use (workfiles/test-list.md, section 3).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Output;

use scribe_storage_sqlite::{SqliteSink, SqliteStore};

/// The repository root.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `config/scribe.toml`.
pub fn shipped_config() -> PathBuf {
    repo_root().join("config/scribe.toml")
}

/// `testdata/<relative>`.
pub fn testdata(relative: &str) -> PathBuf {
    repo_root().join("testdata").join(relative)
}

/// Copy the SQLite schema snapshot `v<version>.db` into `dir` and return the copy.
pub fn sqlite_snapshot(version: u32, dir: &Path) -> PathBuf {
    let dst = dir.join(format!("v{version}.db"));
    std::fs::copy(testdata(&format!("db/sqlite/v{version}.db")), &dst).unwrap();
    dst
}

fn path_option(path: &Path) -> HashMap<String, String> {
    HashMap::from([("path".to_owned(), path.to_string_lossy().into_owned())])
}

pub fn sqlite_store(path: &Path) -> SqliteStore {
    SqliteStore::from_options(&path_option(path)).unwrap()
}

pub fn sqlite_sink(name: &str, path: &Path) -> SqliteSink {
    SqliteSink::from_options(name, &path_option(path)).unwrap()
}

/// A config that keeps everything inside `dir` and logs to `dir/scribed.log`.
pub fn write_config(dir: &Path, extra: &str) -> PathBuf {
    let path = dir.join("scribe.toml");
    let config = format!(
        "data_dir = '{data}'\n{extra}\n[log]\nfile = '{log}'\nrotate = 'size'\n",
        data = dir.join("data").display(),
        log = dir.join("scribed.log").display(),
    );
    std::fs::write(&path, config).unwrap();
    path
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Assert an exit code, showing both streams on failure.
pub fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        text(&output.stdout),
        text(&output.stderr)
    );
}
