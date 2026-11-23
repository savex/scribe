//! Time formatting shared by the daemon and the clients.

use std::time::{Duration, SystemTime};

/// `2026-11-22T10:00:00Z` (UTC, whole seconds).
pub fn rfc3339(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// [`rfc3339`] of a Unix epoch millisecond value (the API's `*_ms` fields).
pub fn rfc3339_ms(ms: i64) -> String {
    let t = if ms >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        SystemTime::UNIX_EPOCH
    };
    rfc3339(t)
}

/// A length of time for people: `45s`, `12m 5s`, `3h 20m`, `2d 4h`.
pub fn human_duration(d: Duration) -> String {
    let s = d.as_secs();
    let (days, hours, mins, secs) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60, s % 60);
    match (days, hours, mins) {
        (0, 0, 0) => format!("{secs}s"),
        (0, 0, _) => format!("{mins}m {secs}s"),
        (0, _, _) => format!("{hours}h {mins}m"),
        _ => format!("{days}d {hours}h"),
    }
}
