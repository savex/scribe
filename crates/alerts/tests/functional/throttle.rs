use std::time::{Duration, UNIX_EPOCH};

use scribe_alerts::{Admit, Throttle};

#[test]
fn throttle_lets_the_limit_through_then_counts() {
    let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut t = Throttle::new(3);
    let got: Vec<Admit> = (0..5)
        .map(|i| t.admit(t0 + Duration::from_secs(i)))
        .collect();
    assert_eq!(
        got,
        [
            Admit::Send,
            Admit::Send,
            Admit::Send,
            Admit::Suppress,
            Admit::Suppress
        ]
    );
    assert_eq!(
        t.roll(t0 + Duration::from_secs(59)),
        None,
        "window still open"
    );
    assert_eq!(t.roll(t0 + Duration::from_secs(60)), Some(2));
    assert_eq!(t.roll(t0 + Duration::from_secs(200)), None, "reported once");
    assert_eq!(t.admit(t0 + Duration::from_secs(200)), Admit::Send);
}

#[test]
fn throttle_window_without_roll_restarts_on_its_own() {
    let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut t = Throttle::new(1);
    assert_eq!(t.admit(t0), Admit::Send);
    assert_eq!(t.admit(t0 + Duration::from_secs(1)), Admit::Suppress);
    assert_eq!(t.admit(t0 + Duration::from_secs(61)), Admit::Send);
}

#[test]
fn throttle_zero_is_unlimited() {
    let t0 = UNIX_EPOCH;
    let mut t = Throttle::new(0);
    assert!((0..1000).all(|_| t.admit(t0) == Admit::Send));
    assert_eq!(t.roll(t0 + Duration::from_secs(3600)), None);
}
