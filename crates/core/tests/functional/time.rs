//! Time formatting for status output.

use std::time::{Duration, SystemTime};

use scribe_core::time::{human_duration, rfc3339, rfc3339_ms};

#[test]
fn rfc3339_is_utc_with_whole_seconds() {
    assert_eq!(rfc3339(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
    let t = SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_999);
    assert_eq!(rfc3339(t), "2023-11-14T22:13:20Z");
    assert_eq!(rfc3339_ms(1_700_000_000_999), "2023-11-14T22:13:20Z");
    assert_eq!(
        rfc3339_ms(951_782_400_000),
        "2000-02-29T00:00:00Z",
        "leap day"
    );
    assert_eq!(rfc3339_ms(-5), "1970-01-01T00:00:00Z");
}

#[test]
fn durations_read_as_the_two_largest_units() {
    let cases = [
        (0, "0s"),
        (45, "45s"),
        (725, "12m 5s"),
        (12_000, "3h 20m"),
        (187_200, "2d 4h"),
    ];
    for (secs, text) in cases {
        assert_eq!(human_duration(Duration::from_secs(secs)), text);
    }
}
