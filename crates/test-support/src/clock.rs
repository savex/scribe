use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scribe_core::Clock;

/// Clock that only moves when the test moves it. Clones share the same time.
#[derive(Debug, Clone)]
pub struct FakeClock(Arc<Mutex<SystemTime>>);

impl FakeClock {
    pub fn at(time: SystemTime) -> Self {
        Self(Arc::new(Mutex::new(time)))
    }

    pub fn at_unix(secs: u64) -> Self {
        Self::at(UNIX_EPOCH + Duration::from_secs(secs))
    }

    pub fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }

    pub fn set(&self, time: SystemTime) {
        *self.0.lock().unwrap() = time;
    }
}

impl Default for FakeClock {
    /// 2023-11-14T22:13:20Z, the same base time as the pcap fixtures.
    fn default() -> Self {
        Self::at_unix(1_700_000_000)
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}
