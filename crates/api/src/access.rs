//! Who is calling, and what they may do (specs 6.3, 12.1.1).
//!
//! The identity comes from the OS once per connection (`SO_PEERCRED` / `getpeereid` on Unix, the
//! pipe client token on Windows) and is attached to every request on it; identity fields inside
//! messages are never trusted.

use tonic::{Request, Status};

/// The OS identity of the process on the other end of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// User name, or the numeric id when it has none.
    pub user: String,
    pub uid: Option<u32>,
    pub pid: Option<i32>,
    /// root on Unix, an Administrator or SYSTEM on Windows.
    pub privileged: bool,
    /// Names of the user's groups, the primary one included.
    pub groups: Vec<String>,
}

impl Caller {
    /// How the caller appears in logs and `audit` events, e.g. `alice (uid 1000, pid 4242)`.
    pub fn describe(&self) -> String {
        let mut ids = Vec::new();
        if let Some(uid) = self.uid {
            ids.push(format!("uid {uid}"));
        }
        if let Some(pid) = self.pid {
            ids.push(format!("pid {pid}"));
        }
        if ids.is_empty() {
            self.user.clone()
        } else {
            format!("{} ({})", self.user, ids.join(", "))
        }
    }
}

/// What a call needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Status, health, hosts, alerts, baseline, export, modules.
    Read,
    /// Reset, hibernate, wakeup, mode, acknowledge, baseline edits.
    Control,
}

/// Which callers may make control calls. Read calls are open to everyone who can open the socket:
/// the socket's directory (`root:scribe`, `0750`) decides that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPolicy {
    /// Group whose members may make control calls besides root / Administrators.
    pub admin_group: String,
}

/// Default admin group (specs 6.3; name Proposed).
pub const ADMIN_GROUP: &str = "scribe-admin";

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            admin_group: ADMIN_GROUP.to_owned(),
        }
    }
}

impl AccessPolicy {
    pub fn allows(&self, caller: &Caller, access: Access) -> bool {
        match access {
            Access::Read => true,
            Access::Control => caller.privileged || caller.groups.contains(&self.admin_group),
        }
    }

    /// The caller of `request` if it may make a call that needs `access`; `permission denied`
    /// otherwise, and `unauthenticated` when the transport attached no identity.
    pub fn check<'r, T>(
        &self,
        request: &'r Request<T>,
        access: Access,
    ) -> Result<&'r Caller, Status> {
        let caller = caller(request)?;
        if self.allows(caller, access) {
            Ok(caller)
        } else {
            Err(Status::permission_denied(format!(
                "permission denied: {} is not root and not in the {} group",
                caller.user, self.admin_group
            )))
        }
    }
}

/// The identity the transport attached to `request`.
pub fn caller<T>(request: &Request<T>) -> Result<&Caller, Status> {
    request
        .extensions()
        .get::<Caller>()
        .ok_or_else(|| Status::unauthenticated("the connection carries no caller identity"))
}
