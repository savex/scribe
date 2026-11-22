//! Start-up checks like sshd's StrictModes (specs 12.1.1): scribed refuses to start when its
//! config file or `data_dir` can be changed by other users. `file:` secrets are checked when read
//! (`scribe-secrets`). Windows ACLs are checked by the installer (phase 13).

use std::path::Path;

use crate::config::{Settings, Source};

/// Every path that is writable by group or others, with the fix.
pub fn strict_modes(settings: &Settings) -> Result<(), String> {
    let mut problems = Vec::new();
    if let Source::File(path) = &settings.source {
        check(path, "config file", &mut problems);
    }
    check(&settings.data_dir, "data_dir", &mut problems);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[cfg(unix)]
fn check(path: &Path, what: &str, problems: &mut Vec<String>) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return; // missing paths are reported by whoever opens them
    };
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 {
        problems.push(format!(
            "{what} {} is writable by group or others (mode {:03o}); run `chmod go-w {}`",
            path.display(),
            mode & 0o777,
            path.display()
        ));
    }
}

#[cfg(not(unix))]
fn check(_path: &Path, _what: &str, _problems: &mut Vec<String>) {}
