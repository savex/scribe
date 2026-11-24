use std::time::{Duration, SystemTime};

/// Length of one rate-limit window.
pub const WINDOW: Duration = Duration::from_secs(60);

/// What [`Throttle::admit`] decided for one alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Send,
    Suppress,
}

/// Per-output rate limit: at most `max_per_minute` alerts in a fixed one-minute window that starts
/// with the first alert after a quiet spell. Alerts over the limit are counted, and the count is
/// reported once when the window ends ([`Throttle::roll`]). `0` = unlimited.
#[derive(Debug, Clone)]
pub struct Throttle {
    max_per_minute: u32,
    window_start: Option<SystemTime>,
    sent: u32,
    suppressed: u64,
}

impl Throttle {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            window_start: None,
            sent: 0,
            suppressed: 0,
        }
    }

    pub fn max_per_minute(&self) -> u32 {
        self.max_per_minute
    }

    /// Decide for one alert at `now`. Call [`Throttle::roll`] first to collect the count of a
    /// window that has ended.
    pub fn admit(&mut self, now: SystemTime) -> Admit {
        if self.max_per_minute == 0 {
            return Admit::Send;
        }
        let start = *self.window_start.get_or_insert(now);
        if now.duration_since(start).unwrap_or_default() >= WINDOW {
            // A window ended without a roll (the caller never ticked); start a new one.
            self.window_start = Some(now);
            self.sent = 0;
        }
        if self.sent < self.max_per_minute {
            self.sent += 1;
            Admit::Send
        } else {
            self.suppressed += 1;
            Admit::Suppress
        }
    }

    /// End the current window once it is a minute old: returns the alerts it held back, if any.
    pub fn roll(&mut self, now: SystemTime) -> Option<u64> {
        let start = self.window_start?;
        if now.duration_since(start).unwrap_or_default() < WINDOW {
            return None;
        }
        self.window_start = None;
        self.sent = 0;
        let held = std::mem::take(&mut self.suppressed);
        (held > 0).then_some(held)
    }
}
