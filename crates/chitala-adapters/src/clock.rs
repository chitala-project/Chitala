//! Trusted time (spec `specs/11-node-ipc.md` §"Time", Blueprint v16 §4,
//! threat model R3). Shared by the node and the adapter host so both agree on
//! order freshness.
//!
//! The system wall clock is an input, not the authority:
//!
//! ```text
//! now = max(wall, last + monotonic time elapsed since last)
//! ```
//!
//! - **Never goes backwards.** A wall clock set back (an attacker reviving expired
//!   tokens, a dead RTC battery, a bad NTP step) is ignored; time keeps advancing
//!   on the monotonic clock and the regression is recorded for the audit log.
//! - **Follows forward corrections** (e.g. NTP synchronising after boot). Moving
//!   forward is the fail-safe direction: tokens and requests can only expire early.
//! - **Floor**: a node starts no earlier than the last event in its audit log.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub type WallSource = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Wall-clock regressions smaller than this are ordinary jitter and not reported.
pub const REGRESSION_NOTICE_MS: u64 = 1_000;

/// The system wall clock in Unix milliseconds.
pub fn system_wall() -> WallSource {
    Arc::new(|| SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0))
}

pub struct TrustedClock {
    wall: WallSource,
    last: Mutex<(u64, Instant)>,
    /// Largest regression seen since the last [`TrustedClock::take_regression`].
    regression_ms: AtomicU64,
}

impl TrustedClock {
    /// `floor_ms`: the clock never reports a time before this.
    pub fn new(wall: WallSource, floor_ms: u64) -> Self {
        let start = wall().max(floor_ms);
        Self { wall, last: Mutex::new((start, Instant::now())), regression_ms: AtomicU64::new(0) }
    }

    pub fn system(floor_ms: u64) -> Self {
        Self::new(system_wall(), floor_ms)
    }

    pub fn now_ms(&self) -> u64 {
        let wall = (self.wall)();
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let monotonic = last.0.saturating_add(last.1.elapsed().as_millis() as u64);
        let now = if wall >= monotonic {
            wall
        } else {
            let behind = monotonic - wall;
            if behind >= REGRESSION_NOTICE_MS {
                self.regression_ms.fetch_max(behind, Ordering::Relaxed);
            }
            monotonic
        };
        *last = (now, Instant::now());
        now
    }

    /// The largest wall-clock regression observed since the previous call, if any.
    pub fn take_regression(&self) -> Option<u64> {
        match self.regression_ms.swap(0, Ordering::Relaxed) {
            0 => None,
            ms => Some(ms),
        }
    }

    /// As a plain `Fn() -> u64` clock.
    pub fn as_clock(self: &Arc<Self>) -> crate::Clock {
        let me = Arc::clone(self);
        Arc::new(move || me.now_ms())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controllable(start: u64) -> (WallSource, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(start));
        let c = Arc::clone(&t);
        (Arc::new(move || c.load(Ordering::SeqCst)), t)
    }

    #[test]
    fn never_goes_backwards_and_reports_regressions() {
        let (wall, t) = controllable(10_000_000);
        let clock = TrustedClock::new(wall, 0);
        // the monotonic clock may already have advanced a little on a busy machine
        let first = clock.now_ms();
        assert!((10_000_000..10_001_000).contains(&first), "{first}");
        t.store(10_005_000, Ordering::SeqCst);
        assert_eq!(clock.now_ms(), 10_005_000);
        // the wall clock is set back an hour
        t.store(10_005_000 - 3_600_000, Ordering::SeqCst);
        let n = clock.now_ms();
        assert!(n >= 10_005_000, "time went backwards: {n}");
        assert!(clock.take_regression().unwrap() >= 3_599_000);
        assert_eq!(clock.take_regression(), None);
        // forward corrections are followed
        t.store(20_000_000, Ordering::SeqCst);
        assert_eq!(clock.now_ms(), 20_000_000);
    }

    #[test]
    fn floor_and_jitter() {
        let (wall, t) = controllable(500);
        let clock = TrustedClock::new(wall, 10_000);
        assert!(clock.now_ms() >= 10_000, "starts no earlier than the floor");
        // a wall clock behind the floor is itself a regression worth recording
        assert!(clock.take_regression().unwrap() >= 9_000);
        t.store(10_000, Ordering::SeqCst);
        let a = clock.now_ms();
        t.store(a - 10, Ordering::SeqCst); // tiny jitter
        assert!(clock.now_ms() >= a);
        assert_eq!(clock.take_regression(), None);
    }
}
