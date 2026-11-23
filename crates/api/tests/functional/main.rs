//! Functional tests of the API transport: calls over a real Unix socket in a temp dir, the caller
//! identity attached by the server, access checks, socket ownership checks and limits.

#[cfg(unix)]
mod access;
#[cfg(unix)]
mod mock;
#[cfg(unix)]
mod socket;
