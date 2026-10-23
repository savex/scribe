//! Sets `SCRIBE_VERSION` for `scribe_core::VERSION`.
//!
//! 1. `SCRIBE_VERSION` from the environment (release builds set it from the tag).
//! 2. `git describe` against `v*` tags: `v1.2.0` -> `1.2.0`, `v1.2.0-3-gabc1234` -> `1.2.0+3.gabc1234`.
//!    No dirty marker: edits to files don't re-run this script, so it would go stale.
//!    `scripts/version.sh current` shows it.
//! 3. No tag reachable: `<Cargo version>+g<sha>`; no git at all: the Cargo version.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SCRIBE_VERSION");
    let pkg_version = std::env::var("CARGO_PKG_VERSION").unwrap();

    let version = match std::env::var("SCRIBE_VERSION") {
        Ok(v) if !v.trim().is_empty() => v.trim().trim_start_matches('v').to_owned(),
        _ => {
            watch_git_state();
            git(&[
                "describe",
                "--tags",
                "--match",
                "v[0-9]*",
                "--always",
                "--abbrev=7",
            ])
            .map(|d| from_describe(&d, &pkg_version))
            .unwrap_or(pkg_version)
        }
    };
    println!("cargo:rustc-env=SCRIBE_VERSION={version}");
}

fn from_describe(describe: &str, pkg_version: &str) -> String {
    let mut meta = Vec::new();
    let base = match describe.strip_prefix('v') {
        // v1.2.0-3-gabc1234: split from the right, the tag itself may contain '-' (v1.0.0-rc.1)
        Some(tagged) => match tagged.rsplitn(3, '-').collect::<Vec<_>>().as_slice() {
            [sha, count, tag] if sha.starts_with('g') && count.parse::<u32>().is_ok() => {
                meta.push(count.to_string());
                meta.push(sha.to_string());
                tag.to_string()
            }
            _ => tagged.to_owned(),
        },
        // only a sha: no release tag reachable
        None => {
            meta.push(format!("g{describe}"));
            pkg_version.to_owned()
        }
    };
    if meta.is_empty() {
        base
    } else {
        format!("{base}+{}", meta.join("."))
    }
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(env_path("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_owned())
}

/// Re-run when HEAD or tags change. Only existing paths, or cargo re-runs every build.
fn watch_git_state() {
    let manifest = env_path("CARGO_MANIFEST_DIR");
    let resolve = |p: String| {
        let p = PathBuf::from(p);
        if p.is_absolute() {
            p
        } else {
            manifest.join(p)
        }
    };
    let (Some(git_dir), Some(common_dir)) = (
        git(&["rev-parse", "--git-dir"]).map(resolve),
        git(&["rev-parse", "--git-common-dir"]).map(resolve),
    ) else {
        return;
    };
    for path in [
        git_dir.join("HEAD"),
        common_dir.join("refs/tags"),
        common_dir.join("packed-refs"),
    ] {
        watch(&path);
    }
    // HEAD itself only changes on checkout; new commits move the branch ref it points to.
    if let Some(branch) = git(&["rev-parse", "--symbolic-full-name", "HEAD"]) {
        if branch.starts_with("refs/") {
            watch(&common_dir.join(branch));
        }
    }
}

fn watch(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn env_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var(key).unwrap())
}
