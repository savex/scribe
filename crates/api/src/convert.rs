//! Conversions between protocol strings and core types.

use scribe_core::Mode;

/// The protocol's name of a mode.
pub fn mode_to_api(mode: Mode) -> String {
    mode.to_string()
}

/// Parses a protocol mode name, with the message a client shows when it's wrong.
pub fn mode_from_api(name: &str) -> Result<Mode, String> {
    name.parse()
}
