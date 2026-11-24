use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scribe_alerts::{AlertOutput, Dispatcher, QUEUE};
use scribe_core::{Alert, Clock};
use scribe_test_support::{FakeClock, RecordingAlertSink};

use super::{alert, GRACE};

fn clock() -> Arc<FakeClock> {
    Arc::new(FakeClock::at_unix(1_800_000_000))
}

#[test]
fn dispatcher_delivers_to_every_output_in_order() {
    let clock = clock();
    let a = Arc::new(RecordingAlertSink::default());
    let b = Arc::new(RecordingAlertSink::default());
    let mut d = Dispatcher::new(vec![a.clone(), b.clone()], 0, clock.clone());
    for host in ["a.example.com", "b.example.com", "c.example.com"] {
        d.send(&alert(host, clock.now()));
    }
    assert!(d.close(GRACE).is_empty());
    for sink in [&a, &b] {
        let hosts: Vec<_> = sink.alerts().into_iter().map(|a| a.host.unwrap()).collect();
        assert_eq!(hosts, ["a.example.com", "b.example.com", "c.example.com"]);
    }
}

#[test]
fn dispatcher_rate_limit_reports_held_alerts_once_per_window() {
    let clock = clock();
    let sink = Arc::new(RecordingAlertSink::default());
    let mut d = Dispatcher::new(vec![sink.clone()], 2, clock.clone());
    for i in 0..5 {
        d.send(&alert(&format!("h{i}.example.com"), clock.now()));
    }
    d.tick();
    clock.advance(Duration::from_secs(60));
    d.tick();
    d.tick();
    let stats = d.stats();
    assert_eq!(stats[0].suppressed, 3);
    assert!(d.close(GRACE).is_empty());
    assert_eq!(sink.count(), 2);
    assert_eq!(sink.suppressed_counts(), vec![3]);
}

/// Blocks in `notify` until the test lets it go, so the queue fills up.
struct Stuck {
    gate: Mutex<mpsc::Receiver<()>>,
    seen: Mutex<usize>,
}

impl AlertOutput for Stuck {
    fn name(&self) -> &str {
        "stuck"
    }
    fn notify(&self, _: &Alert) -> Result<(), String> {
        let _ = self.gate.lock().unwrap().recv();
        *self.seen.lock().unwrap() += 1;
        Ok(())
    }
}

#[test]
fn dispatcher_drops_when_an_output_is_behind_and_others_keep_going() {
    let clock = clock();
    let (open, gate) = mpsc::channel();
    let stuck = Arc::new(Stuck {
        gate: Mutex::new(gate),
        seen: Mutex::new(0),
    });
    let fast = Arc::new(RecordingAlertSink::default());
    let mut d = Dispatcher::new(vec![stuck.clone(), fast.clone()], 0, clock.clone());
    let total = QUEUE + 50;
    for i in 0..total {
        d.send(&alert(&format!("h{i}.example.com"), clock.now()));
    }
    let dropped = d.stats()[0].dropped;
    // One alert may already sit in `notify`, the queue holds QUEUE more.
    assert!(
        (49..=50).contains(&dropped),
        "dropped {dropped} of {total} with a queue of {QUEUE}"
    );
    drop(open);
    let fast_dropped = d.stats()[1].dropped;
    assert!(d.close(GRACE).is_empty());
    // The fast output works on while the stuck one is blocked: it delivers everything its queue
    // took, which is at least a full queue (it may drop too if 306 alerts outrun its thread).
    assert_eq!(fast.count() as u64 + fast_dropped, total as u64);
    assert!(fast.count() >= QUEUE, "the fast output kept going");
    assert_eq!(*stuck.seen.lock().unwrap() as u64 + dropped, total as u64);
}

struct Failing;

impl AlertOutput for Failing {
    fn name(&self) -> &str {
        "failing"
    }
    fn notify(&self, _: &Alert) -> Result<(), String> {
        Err("connection refused".into())
    }
}

#[test]
fn dispatcher_counts_failures_and_keeps_the_last_error() {
    let clock = clock();
    let failing = Arc::new(Failing);
    let mut d = Dispatcher::new(vec![failing], 0, clock.clone());
    d.send(&alert("a.example.com", clock.now()));
    d.send(&alert("b.example.com", clock.now()));
    // Let the thread finish before reading the counters.
    let stats_after = {
        let deadline = std::time::Instant::now() + GRACE;
        loop {
            let s = d.stats();
            if s[0].failed == 2 || std::time::Instant::now() > deadline {
                break s;
            }
            std::thread::yield_now();
        }
    };
    assert_eq!(stats_after[0].failed, 2);
    assert_eq!(stats_after[0].sent, 0);
    assert_eq!(
        stats_after[0].last_error.as_deref(),
        Some("connection refused")
    );
    assert!(d.close(GRACE).is_empty());
}

#[test]
fn dispatcher_close_leaves_a_hung_output_behind() {
    let clock = clock();
    let (_open, gate) = mpsc::channel();
    let stuck = Arc::new(Stuck {
        gate: Mutex::new(gate),
        seen: Mutex::new(0),
    });
    let mut d = Dispatcher::new(vec![stuck], 0, clock.clone());
    d.send(&alert("a.example.com", clock.now()));
    assert_eq!(d.close(Duration::from_millis(50)), ["stuck"]);
}

#[test]
fn dispatcher_without_outputs_takes_alerts() {
    let clock = clock();
    let mut d = Dispatcher::empty(clock.clone());
    d.send(&alert("a.example.com", clock.now()));
    d.tick();
    assert!(d.names().is_empty());
    assert!(d.stats().is_empty());
}
