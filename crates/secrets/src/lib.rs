//! Secret references (NFR-10): credentials and keys are named in config by reference, never stored
//! in it. Forms:
//!
//! | Reference | Store | Status |
//! |---|---|---|
//! | `file:<absolute path>` | a file only its owner can read (Unix mode `0600` or stricter, owned by the service account or root) | implemented |
//! | `keychain:<service>/<account>` | macOS keychain, generic password item (root: System keychain) | implemented (macOS) |
//! | `dpapi:<absolute path>` | Windows DPAPI blob in a file, machine scope | implemented (Windows) |
//! | `secret-service:<label>` | Linux Secret Service on the session bus (attributes `application = scribe`, `scribe-secret = <label>`) | implemented (Linux) |
//!
//! A reference for another system's store is [`SecretError::Unsupported`]. A `file:` secret is its
//! bytes, less one trailing newline. [`read_or_create`] generates a random key on first use and
//! stores it as lowercase hex, so it can be copied by hand; [`store`] writes a given value
//! (`scribed --set-secret`).

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ring::rand::{SecureRandom, SystemRandom};

mod os;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    File(PathBuf),
    Keychain { service: String, account: String },
    Dpapi(PathBuf),
    SecretService(String),
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error(
        "malformed secret reference `{0}`: expected file:, keychain:, dpapi: or secret-service:"
    )]
    Malformed(String),
    #[error("{0} secrets are not available on this system; use a `file:` reference")]
    Unsupported(&'static str),
    #[error("{reference}: {why}")]
    Store { reference: String, why: String },
    #[error("secret `{0}` not found")]
    NotFound(String),
    #[error("{path}: {why}")]
    Insecure { path: PathBuf, why: String },
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("no random bytes available")]
    Random,
}

/// Secret bytes; `Debug` hides them and drop overwrites them.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Secret {
    /// Key material already in memory (tests, or a value another store returned).
    fn from(bytes: Vec<u8>) -> Self {
        Secret(bytes)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<{} bytes>)", self.0.len())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: `b` is a valid, aligned, exclusive reference.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl FromStr for SecretRef {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, SecretError> {
        let bad = || SecretError::Malformed(s.to_owned());
        let (scheme, rest) = s.split_once(':').ok_or_else(bad)?;
        if rest.is_empty() {
            return Err(bad());
        }
        let absolute = |p: &str| {
            let p = PathBuf::from(p);
            if p.is_absolute() {
                Ok(p)
            } else {
                Err(bad())
            }
        };
        match scheme {
            "file" => absolute(rest).map(SecretRef::File),
            "dpapi" => absolute(rest).map(SecretRef::Dpapi),
            "secret-service" => Ok(SecretRef::SecretService(rest.to_owned())),
            "keychain" => match rest.split_once('/') {
                Some((service, account)) if !service.is_empty() && !account.is_empty() => {
                    Ok(SecretRef::Keychain {
                        service: service.to_owned(),
                        account: account.to_owned(),
                    })
                }
                _ => Err(bad()),
            },
            _ => Err(bad()),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRef::File(p) => write!(f, "file:{}", p.display()),
            SecretRef::Keychain { service, account } => write!(f, "keychain:{service}/{account}"),
            SecretRef::Dpapi(p) => write!(f, "dpapi:{}", p.display()),
            SecretRef::SecretService(label) => write!(f, "secret-service:{label}"),
        }
    }
}

impl SecretRef {
    /// The store's name as written in the reference (`file`, `keychain`, …).
    pub fn backend(&self) -> &'static str {
        match self {
            SecretRef::File(_) => "file",
            SecretRef::Keychain { .. } => "keychain",
            SecretRef::Dpapi(_) => "dpapi",
            SecretRef::SecretService(_) => "secret-service",
        }
    }
}

/// Read a secret.
pub fn read(r: &SecretRef) -> Result<Secret, SecretError> {
    match r {
        SecretRef::File(path) => read_file(path),
        SecretRef::Keychain { service, account } => os::keychain::read(service, account),
        SecretRef::Dpapi(path) => os::dpapi::read(path),
        SecretRef::SecretService(label) => os::secret_service::read(label),
    }
}

/// Write `value` to the store, replacing what was there (`scribed --set-secret`). A `file:` is
/// written to a temporary file with mode `0600` and renamed over the old one.
pub fn store(r: &SecretRef, value: &[u8]) -> Result<(), SecretError> {
    if value.is_empty() {
        return Err(SecretError::Store {
            reference: r.to_string(),
            why: "an empty secret is not stored".into(),
        });
    }
    match r {
        SecretRef::File(path) => {
            check_dir(path.parent().unwrap_or(Path::new("/")))?;
            replace_file(path, value)
        }
        SecretRef::Keychain { service, account } => os::keychain::store(service, account, value),
        SecretRef::Dpapi(path) => os::dpapi::store(path, value),
        SecretRef::SecretService(label) => os::secret_service::store(label, value),
    }
}

/// Remove a keychain item (tests and uninstall); other stores are removed with their file or by
/// the keyring's own tools.
pub fn delete_keychain_item(service: &str, account: &str) -> Result<(), SecretError> {
    os::keychain::delete(service, account)
}

/// Read a secret, or generate `len` random bytes, store them and return them (as hex text, the
/// form they are stored in).
pub fn read_or_create(r: &SecretRef, len: usize) -> Result<Secret, SecretError> {
    match read(r) {
        Err(SecretError::NotFound(_)) => {}
        other => return other,
    }
    let mut raw = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| SecretError::Random)?;
    let mut text: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    raw.fill(0);
    let SecretRef::File(path) = r else {
        let stored = store(r, text.as_bytes());
        drop(Secret(text.into_bytes()));
        stored?;
        return read(r);
    };
    text.push('\n');
    let created = create_file(path, text.as_bytes());
    drop(Secret(text.into_bytes()));
    match created {
        Ok(()) => read_file(path),
        // Another process won the race: use its key.
        Err(SecretError::Io { .. }) if path.exists() => read_file(path),
        Err(e) => Err(e),
    }
}

pub(crate) fn io_err(path: &Path) -> impl FnOnce(io::Error) -> SecretError + '_ {
    move |source| {
        if source.kind() == io::ErrorKind::NotFound {
            SecretError::NotFound(format!("file:{}", path.display()))
        } else {
            SecretError::Io {
                path: path.to_owned(),
                source,
            }
        }
    }
}

fn read_file(path: &Path) -> Result<Secret, SecretError> {
    let meta = fs::metadata(path).map_err(io_err(path))?;
    if !meta.is_file() {
        return Err(SecretError::Insecure {
            path: path.to_owned(),
            why: "not a regular file".into(),
        });
    }
    check_private(path, &meta)?;
    let mut bytes = fs::read(path).map_err(io_err(path))?;
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        return Err(SecretError::Insecure {
            path: path.to_owned(),
            why: "empty secret".into(),
        });
    }
    Ok(Secret(bytes))
}

/// Write `contents` to `path` through a temporary file readable only by its owner, replacing an
/// existing file.
pub(crate) fn replace_file(path: &Path, contents: &[u8]) -> Result<(), SecretError> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    let tmp = dir.join(format!(
        ".{}.{}.new",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("secret"),
        std::process::id()
    ));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let write = || -> io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    };
    let result = write();
    let _ = fs::remove_file(&tmp);
    result.map_err(|source| SecretError::Io {
        path: path.to_owned(),
        source,
    })
}

/// Write a new file readable only by its owner, never replacing one that exists.
fn create_file(path: &Path, contents: &[u8]) -> Result<(), SecretError> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    check_dir(dir)?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("secret"),
        std::process::id()
    ));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let write = || -> io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        // Fails if `path` exists: a concurrent start keeps the first key.
        fs::hard_link(&tmp, path)
    };
    let result = write();
    let _ = fs::remove_file(&tmp);
    result.map_err(|source| SecretError::Io {
        path: path.to_owned(),
        source,
    })
}

#[cfg(unix)]
fn check_private(path: &Path, meta: &fs::Metadata) -> Result<(), SecretError> {
    use std::os::unix::fs::MetadataExt;
    let insecure = |why: String| SecretError::Insecure {
        path: path.to_owned(),
        why,
    };
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(insecure(format!(
            "mode {mode:03o} lets other users read or change it; use 600"
        )));
    }
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me && meta.uid() != 0 {
        return Err(insecure(format!(
            "owned by uid {}, not by this account or root",
            meta.uid()
        )));
    }
    Ok(())
}

/// Windows: ACL checks arrive with the installer (phase 13), which sets them on `data_dir`.
#[cfg(not(unix))]
fn check_private(_path: &Path, _meta: &fs::Metadata) -> Result<(), SecretError> {
    Ok(())
}

#[cfg(unix)]
fn check_dir(dir: &Path) -> Result<(), SecretError> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(dir).map_err(|source| SecretError::Io {
        path: dir.to_owned(),
        source,
    })?;
    let mode = meta.mode();
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(SecretError::Insecure {
            path: dir.to_owned(),
            why: format!(
                "directory mode {:03o} lets other users replace the key",
                mode & 0o777
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_dir(_dir: &Path) -> Result<(), SecretError> {
    Ok(())
}
