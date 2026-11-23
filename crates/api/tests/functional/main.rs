//! Functional tests of the API transport: calls over a real Unix socket in a temp dir (a named
//! pipe on Windows), the caller identity attached by the server, access checks, ownership checks
//! and limits.

#[cfg(unix)]
mod access;
mod mock;
mod pipe;
#[cfg(unix)]
mod socket;
