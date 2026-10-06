//! History through the node (spec 29): the node publishes what it observed
//! (`Observed`, `Unobservable`) on the right transitions only, and the
//! recorder turns a lock driven through the whole chain into a history whose
//! durations, cycles and unknown time are right.

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chitala_adapters::conformance::{Fault, MockRig};
use chitala_history::log::HistoryLog;
use chitala_history::query;
use chitala_history::recorder::{self, Retention};
use chitala_model::{EventKind, ParamValue};
use chitala_platform::{memory, StoragePath};
use common::*;

/// One pass of the node's periodic observations, a minute later.
fn pass(h: &mut Home) {
    h.clock.fetch_add(60_000, Ordering::SeqCst);
    h.node.tick();
    std::thread::sleep(Duration::from_millis(5));
}

/// `Observed` when the state changed (by an order or by hand) or the device
/// is back; `Unobservable` once when it is lost; nothing for an observation
/// that changes nothing.
#[test]
fn the_node_publishes_observations_on_their_transitions_only() {
    let mut h = home(Box::new(MockRig::new()));
    let events = h.node.subscribe_with_capacity(recorder::filter(), 100);
    let lock = h.lock();
    let kinds = |events: &chitala_bus::Subscription| -> Vec<(EventKind, Option<ParamValue>)> {
        events.drain().into_iter().map(|e| (e.kind, e.data.get("locked").cloned())).collect()
    };
    h.unlocked();
    assert_eq!(kinds(&events), [(EventKind::Observed, Some(ParamValue::Bool(false)))]);
    pass(&mut h);
    pass(&mut h);
    assert_eq!(kinds(&events), [], "nothing changed");
    h.rig.by_hand(true);
    pass(&mut h);
    assert_eq!(kinds(&events), [(EventKind::Observed, Some(ParamValue::Bool(true)))], "a change outside Chitala");
    h.rig.fault(Fault::Offline);
    for _ in 0..4 {
        pass(&mut h);
    }
    assert_eq!(kinds(&events), [(EventKind::Unobservable, None)], "lost once");
    h.rig.heal();
    for _ in 0..4 {
        pass(&mut h);
    }
    assert_eq!(kinds(&events), [(EventKind::Observed, Some(ParamValue::Bool(true)))], "back, unchanged");
    let _ = lock;
}

/// The whole chain: a lock driven through the node, a time lost, and the
/// recorder's history answers how long it was locked, how often it was
/// locked, and how long nobody could tell.
#[test]
fn a_lock_driven_through_the_node_has_a_true_history() {
    let h = home(Box::new(MockRig::new()));
    let start = h.node.now();
    let Home { rig, others, node, clock, alice, max_age_ms } = h;
    let node = Arc::new(Mutex::new(node));
    let (platform, _) = memory::platform("history", 0);
    let path = StoragePath::new("history.jsonl").unwrap();
    let rec = chitala_node::history::record(
        &node,
        HistoryLog::new(Arc::clone(&platform.storage), path.clone()),
        Retention::days(30),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let node = Arc::try_unwrap(node).ok();
    // the recorder holds the node only weakly: the test takes it back to drive it
    let Some(node) = node else { panic!("the recorder holds the node strongly") };
    let mut h = Home { rig, others, node: node.into_inner().unwrap(), clock, alice, max_age_ms };
    let advance = |h: &mut Home, ms: u64| {
        h.clock.fetch_add(ms, Ordering::SeqCst);
        h.node.tick();
        std::thread::sleep(Duration::from_millis(5));
    };
    h.unlocked();
    advance(&mut h, 600_000);
    assert!(h.req("lock.lock").is_ok());
    advance(&mut h, 300_000);
    assert!(h.req("lock.unlock").is_ok());
    advance(&mut h, 120_000);
    h.rig.by_hand(true); // locked by hand
    advance(&mut h, 60_000);
    advance(&mut h, 60_000);
    h.rig.fault(Fault::Offline);
    for _ in 0..3 {
        advance(&mut h, 60_000);
    }
    h.rig.heal();
    advance(&mut h, 60_000);
    std::thread::sleep(Duration::from_millis(400));
    let end = h.node.now();
    drop(rec);
    let records = HistoryLog::new(platform.storage, path).read().unwrap();
    let lock = h.lock();
    let s = query::summary(&records, &lock, "locked", &ParamValue::Bool(true), start, end);
    let minute = 60_000;
    let near = |ms: u64, want: u64| ms.abs_diff(want) < 5_000;
    // locked by the order for 5 minutes; by hand, seen at the next pass, for
    // 2 minutes until the lock was lost; lost for 3 minutes, unknown; locked
    // again once it was back, an entry nobody saw happen
    assert_eq!(s.cycles, 2, "{s:?}");
    assert!(near(s.in_value_ms, 7 * minute), "{s:?}");
    assert!(near(s.unknown_ms, 3 * minute), "the time it was lost is unknown: {s:?}");
    assert!(near(s.longest_run_ms, 5 * minute), "{s:?}");
}
