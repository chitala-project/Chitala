//! The history recorder (spec 29): a subscriber of the node's event bus that
//! writes what the node observed into the history log. It decides nothing.
//!
//! The bus drops events for a subscriber that falls behind. The recorder
//! notices: it writes a gap, then reads every device's state again from the
//! node and writes it. A missed event becomes unknown time, never a wrong
//! value.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use chitala_bus::{Filter, Subscription};
use chitala_model::{EntityId, EventKind, Payload};

use crate::log::HistoryLog;
use crate::Record;

/// The recorder's queue on the bus.
pub const QUEUE: usize = 4_096;

/// What the node can say about a device now.
#[derive(Debug, Clone, PartialEq)]
pub enum Now {
    /// Observed: its state, and when its source produced it.
    Observed { state: Payload, at: u64 },
    /// It cannot be observed, since then.
    Unobservable { since: u64 },
    /// Never observed.
    Unknown,
}

/// Every device's state now, from the node.
pub type Snapshot = Box<dyn Fn() -> Vec<(EntityId, Now)> + Send>;
/// The node's clock.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The running recorder; it stops when dropped.
pub struct Recorder {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// How long the recorder keeps records, and how often it drops older ones.
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub keep_ms: u64,
    pub every_ms: u64,
}

impl Retention {
    pub fn days(days: u64) -> Self {
        Self { keep_ms: days * 86_400_000, every_ms: 86_400_000 }
    }
}

/// The subscription a recorder reads: observations and losses of observability.
pub fn filter() -> Filter {
    Filter::Kinds(vec![EventKind::Observed, EventKind::Unobservable])
}

/// Start recording `events` (a subscription made with [`filter`] and
/// [`QUEUE`]) into `log`, with `snapshot` to resynchronise.
pub fn start(
    events: Subscription,
    mut log: HistoryLog,
    snapshot: Snapshot,
    clock: Clock,
    retention: Retention,
) -> Recorder {
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let mut compacted = None;
        let mut dropped = events.dropped();
        let now = clock();
        let _ = log.append(&Record::Start { at: now });
        resync(&mut log, &snapshot, now);
        while !s.load(Ordering::SeqCst) {
            let now = clock();
            if compacted.is_none_or(|at| now.saturating_sub(at) >= retention.every_ms) {
                let _ = log.compact(now.saturating_sub(retention.keep_ms));
                compacted = Some(now);
            }
            if let Some(event) = events.recv_timeout(Duration::from_millis(200)) {
                let record = match event.kind {
                    EventKind::Observed => {
                        Record::Observed { device: event.source, at: event.ts_ms, observed_at: now, state: event.data }
                    }
                    EventKind::Unobservable => Record::Unobservable { device: event.source, at: event.ts_ms },
                    _ => continue,
                };
                let _ = log.append(&record);
            }
            let missed = events.dropped();
            if missed != dropped {
                dropped = missed;
                let now = clock();
                let _ = log.append(&Record::Gap { at: now });
                resync(&mut log, &snapshot, now);
            }
        }
    });
    Recorder { stop, thread: Some(thread) }
}

/// Write every device's state now, as the node holds it.
fn resync(log: &mut HistoryLog, snapshot: &Snapshot, now: u64) {
    for (device, state) in snapshot() {
        let record = match state {
            Now::Observed { state, at } => Record::Observed { device, at: at.min(now), observed_at: now, state },
            Now::Unobservable { since } => Record::Unobservable { device, at: since.min(now) },
            Now::Unknown => continue,
        };
        let _ = log.append(&record);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;

    use chitala_bus::EventBus;
    use chitala_model::{payload, Event};
    use chitala_platform::{memory, StoragePath};

    use super::*;

    fn id(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }

    fn event(kind: EventKind, device: &str, ts_ms: u64, data: Payload) -> Event {
        Event { id: "00".into(), kind, source: id(device), ts_ms, data, caused_by: None }
    }

    fn until(what: &str, f: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !f() {
            assert!(Instant::now() < deadline, "timed out waiting until {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Observations and losses are written as the node published them: the
    /// source's time beside the observed time; other events are not history.
    #[test]
    fn the_node_s_observations_are_recorded() {
        let (platform, _) = memory::platform("history", 0);
        let path = StoragePath::new("history.jsonl").unwrap();
        let bus = EventBus::new();
        let clock_ms = Arc::new(AtomicU64::new(1_000));
        let c = Arc::clone(&clock_ms);
        let clock: Clock = Arc::new(move || c.load(Ordering::SeqCst));
        let snapshot: Snapshot =
            Box::new(|| vec![(id("device:light"), Now::Observed { state: payload([("on", false)]), at: 900 })]);
        let rec = start(
            bus.subscribe_with_capacity(filter(), QUEUE),
            HistoryLog::new(Arc::clone(&platform.storage), path.clone()),
            snapshot,
            clock,
            Retention::days(30),
        );
        bus.publish(event(EventKind::Observed, "device:pump", 950, payload([("on", true)])));
        bus.publish(event(EventKind::StateChanged, "device:pump", 960, payload([("on", true)])));
        bus.publish(event(EventKind::Unobservable, "device:pump", 990, Payload::new()));
        let log = HistoryLog::new(Arc::clone(&platform.storage), path);
        until("recorded", || log.read().unwrap().len() >= 4);
        drop(rec);
        assert_eq!(
            log.read().unwrap(),
            [
                Record::Start { at: 1_000 },
                Record::Observed {
                    device: id("device:light"),
                    at: 900,
                    observed_at: 1_000,
                    state: payload([("on", false)])
                },
                Record::Observed {
                    device: id("device:pump"),
                    at: 950,
                    observed_at: 1_000,
                    state: payload([("on", true)])
                },
                Record::Unobservable { device: id("device:pump"), at: 990 },
            ]
        );
    }

    /// Events the bus dropped for the recorder become a gap, then every
    /// device's state again: unknown time, never a wrong value.
    #[test]
    fn missed_events_are_a_gap_then_a_resync() {
        let (platform, _) = memory::platform("history", 0);
        let path = StoragePath::new("history.jsonl").unwrap();
        let bus = EventBus::new();
        let clock: Clock = Arc::new(|| 5_000);
        let snapshot: Snapshot = Box::new(|| {
            vec![
                (id("device:pump"), Now::Observed { state: payload([("on", true)]), at: 4_000 }),
                (id("device:lock"), Now::Unobservable { since: 4_500 }),
                (id("device:new"), Now::Unknown),
            ]
        });
        // a queue of one, so that a burst drops events
        let rec = start(
            bus.subscribe_with_capacity(filter(), 1),
            HistoryLog::new(Arc::clone(&platform.storage), path.clone()),
            snapshot,
            clock,
            Retention::days(30),
        );
        for i in 0..50 {
            bus.publish(event(EventKind::Observed, "device:pump", 4_000 + i, payload([("on", i % 2 == 0)])));
        }
        let log = HistoryLog::new(Arc::clone(&platform.storage), path);
        until("a gap", || log.read().unwrap().iter().any(|r| matches!(r, Record::Gap { .. })));
        std::thread::sleep(Duration::from_millis(300));
        drop(rec);
        let records = log.read().unwrap();
        let gap = records.iter().rposition(|r| matches!(r, Record::Gap { .. })).unwrap();
        // right after the gap, every device's state as the node holds it
        assert_eq!(
            records[gap + 1..gap + 3],
            [
                Record::Observed {
                    device: id("device:pump"),
                    at: 4_000,
                    observed_at: 5_000,
                    state: payload([("on", true)])
                },
                Record::Unobservable { device: id("device:lock"), at: 4_500 },
            ],
            "{records:?}"
        );
        assert!(!records.iter().any(|r| r.device() == Some(&id("device:new"))), "never observed: nothing written");
    }
}
