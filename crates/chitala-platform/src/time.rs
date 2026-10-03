//! Time (v20 §4 TimeSource, §12 secure/monotonic time; threat model R3).
//!
//! A [`TimeSource`] reports a wall clock (untrusted input that may jump either
//! way) and a monotonic clock. [`TrustedClock`] turns them into the time the
//! Trusted Core uses for every expiry decision:
//!
//! ```text
//! now = max(wall, last + monotonic time elapsed since last)
//! ```
//!
//! - **never goes backwards** — a wall clock set back (reviving expired tokens,
//!   a dead RTC battery, a bad NTP step) is ignored and recorded;
//! - **follows forward corrections** — the fail-safe direction: things can only
//!   expire early;
//! - **floor** — a node starts no earlier than the last event in its audit log.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub trait TimeSource: Send + Sync {
    /// Wall-clock time in Unix milliseconds. Untrusted: it may jump either way.
    fn wall_ms(&self) -> u64;
    /// Milliseconds since an arbitrary origin. Never decreases while the
    /// platform runs.
    fn monotonic_ms(&self) -> u64;
}

/// A plain time function, as consumed by the node and the monitor.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Wall-clock regressions smaller than this are ordinary jitter and not reported.
pub const REGRESSION_NOTICE_MS: u64 = 1_000;

pub struct TrustedClock {
    source: Arc<dyn TimeSource>,
    /// (time returned last, monotonic reading at that moment)
    last: Mutex<(u64, u64)>,
    regression_ms: AtomicU64,
}

impl TrustedClock {
    /// `floor_ms`: the clock never reports a time before this.
    pub fn new(source: Arc<dyn TimeSource>, floor_ms: u64) -> Self {
        // the very first reading also passes through `now_ms`, so a wall clock
        // behind the floor is recorded as a regression
        let start = (floor_ms, source.monotonic_ms());
        let clock = Self { source, last: Mutex::new(start), regression_ms: AtomicU64::new(0) };
        clock.now_ms();
        clock
    }

    pub fn now_ms(&self) -> u64 {
        let wall = self.source.wall_ms();
        let mono = self.source.monotonic_ms();
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let advanced = last.0.saturating_add(mono.saturating_sub(last.1));
        let now = if wall >= advanced {
            wall
        } else {
            let behind = advanced - wall;
            if behind >= REGRESSION_NOTICE_MS {
                self.regression_ms.fetch_max(behind, Ordering::Relaxed);
            }
            advanced
        };
        *last = (now, mono);
        now
    }

    /// The largest wall-clock regression observed since the previous call, if any.
    pub fn take_regression(&self) -> Option<u64> {
        match self.regression_ms.swap(0, Ordering::Relaxed) {
            0 => None,
            ms => Some(ms),
        }
    }

    /// As a plain [`Clock`].
    pub fn as_clock(self: &Arc<Self>) -> Clock {
        let me = Arc::clone(self);
        Arc::new(move || me.now_ms())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryTime;

    #[test]
    fn never_goes_backwards_and_reports_regressions() {
        let t = Arc::new(MemoryTime::new(10_000_000));
        let clock = TrustedClock::new(t.clone(), 0);
        assert_eq!(clock.now_ms(), 10_000_000);
        t.advance(5_000);
        assert_eq!(clock.now_ms(), 10_005_000);
        // the wall clock is set back an hour; the monotonic clock keeps going
        t.set_wall(10_005_000 - 3_600_000);
        t.advance_monotonic(10);
        let n = clock.now_ms();
        assert_eq!(n, 10_005_010, "time continued on the monotonic clock");
        assert!(clock.take_regression().unwrap() >= 3_599_000);
        assert_eq!(clock.take_regression(), None);
        // forward corrections are followed
        t.set_wall(20_000_000);
        assert_eq!(clock.now_ms(), 20_000_000);
    }

    #[test]
    fn floor_and_jitter() {
        let t = Arc::new(MemoryTime::new(500));
        let clock = TrustedClock::new(t.clone(), 10_000);
        assert!(clock.now_ms() >= 10_000);
        assert!(clock.take_regression().unwrap() >= 9_000, "a wall clock behind the floor is recorded");
        t.set_wall(10_000);
        let a = clock.now_ms();
        t.set_wall(a - 10); // jitter
        assert!(clock.now_ms() >= a);
        assert_eq!(clock.take_regression(), None);
    }
}
