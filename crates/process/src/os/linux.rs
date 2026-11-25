//! Linux: sockets from `/proc/net/*` (with their inode), owners from the `socket:[inode]` links
//! in `/proc/<pid>/fd`, paths from `/proc/<pid>/exe`. Only this network namespace is seen.

use std::collections::HashMap;
use std::fs;
use std::io;

use super::parse_proc_net;
use crate::{SocketEntry, SocketTable, Transport};

pub struct ProcTable;

/// Every socket inode open in any process, with its pid. Processes that vanish or can't be read
/// (no permission) are skipped.
fn socket_owners() -> io::Result<HashMap<u64, u32>> {
    let mut owners = HashMap::new();
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            {
                owners.entry(inode).or_insert(pid);
            }
        }
    }
    Ok(owners)
}

impl SocketTable for ProcTable {
    fn snapshot(&mut self) -> io::Result<Vec<SocketEntry>> {
        let mut sockets = Vec::new();
        for (file, transport) in [
            ("/proc/net/tcp", Transport::Tcp),
            ("/proc/net/tcp6", Transport::Tcp),
            ("/proc/net/udp", Transport::Udp),
            ("/proc/net/udp6", Transport::Udp),
        ] {
            // tcp6 / udp6 are missing without IPv6.
            let Ok(text) = fs::read_to_string(file) else {
                continue;
            };
            sockets.extend(
                parse_proc_net(&text)
                    .into_iter()
                    .filter(|e| !e.listening && e.inode != 0)
                    .map(|e| (transport, e)),
            );
        }
        let owners = socket_owners()?;
        Ok(sockets
            .into_iter()
            .filter_map(|(transport, e)| {
                Some(SocketEntry {
                    transport,
                    local: e.local,
                    remote: e.remote,
                    pid: *owners.get(&e.inode)?,
                })
            })
            .collect())
    }

    fn process_path(&self, pid: u32) -> Option<String> {
        fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
}
