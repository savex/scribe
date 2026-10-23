use std::fmt;
use std::str::FromStr;

/// Policy mode of the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Record everything and add new hosts to the list; never alert.
    #[default]
    Learn,
    /// Alert on unlisted hosts that look non-ordinary, and on any plaintext flow.
    Caution,
    /// Alert on every host or flow that is not on the list.
    Alert,
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "learn" => Ok(Mode::Learn),
            "caution" => Ok(Mode::Caution),
            "alert" => Ok(Mode::Alert),
            other => Err(format!("unknown mode '{other}', expected learn|caution|alert")),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Learn => "learn",
            Mode::Caution => "caution",
            Mode::Alert => "alert",
        })
    }
}
