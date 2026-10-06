//! The adversarial Home suite (v0.3 step ⑥, spec 28), on the direct Matter
//! path: the whole chain, with the matter.js backend speaking the real
//! sidecar protocol to a fake sidecar that crashes, hangs, lies about its
//! lines, and devices that jam, go quiet, or drop off and come back. Whatever
//! happens, a command reaches the device at most once, nothing is made up,
//! and what Chitala cannot establish ends `unconfirmed`, with recovery.

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chitala_adapters::conformance::{Fault, HaRig, MatterRig, MockRig};
use chitala_adapters::direct_matter::fake::{FakeBackend, NextCommand};
use chitala_adapters::direct_matter::fake_sidecar::{Crash, SidecarControl};
use chitala_adapters::direct_matter::Target;
use chitala_adapters::fake_ha::World;
use chitala_adapters::fake_matter::MatterWorld;
use chitala_model::{ExecCode, Payload};
use chitala_node::Step;
use common::*;
use serde_json::json;

/// A home whose front door's lock is on Chitala's fabric, through the
/// matter.js backend and a fake sidecar; its door's state is relied on for
/// `max_age_ms` at most.
fn matter_home(max_age_ms: u64) -> (Home, FakeBackend, SidecarControl) {
    let rig = MatterRig::over_sidecar();
    let (world, sidecar) = (rig.backend.clone(), rig.sidecar.clone().expect("through the sidecar"));
    (home_with(Box::new(rig), max_age_ms), world, sidecar)
}

const MATTER_AT: Target = Target { node: 1, endpoint: 1 };

/// Invokes the sidecars received: what Chitala sent, retries included.
fn sent(sidecar: &SidecarControl) -> usize {
    sidecar.received().iter().filter(|op| *op == "InvokeProfileCommand").count()
}

/// Ticks until the door can be observed (or cannot).
fn until_observable(h: &mut Home, observable: bool) {
    let lock = h.lock();
    for _ in 0..300 {
        if h.node.twins().evidence(&lock, h.node.now()).is_some() == observable {
            return;
        }
        // a pass a minute apart, while real time lets a replaced sidecar start
        h.clock.fetch_add(60_000, Ordering::SeqCst);
        h.node.tick();
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the door never became {}", if observable { "observable" } else { "unobservable" });
}

// ───────────────────────────── a sidecar crashes or hangs ─────────────────────────────

/// The sidecar dies having read the command, before the device got it. The
/// order's fate is unknown to Chitala; a new sidecar is started, the lock is
/// read, and the order is `not_applied`. Nothing is sent again.
#[test]
fn a_sidecar_that_dies_before_the_device_leaves_the_order_unknown_and_never_resent() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    sidecar.crash_on_next_invoke(Crash::BeforeTheDevice);
    let r = h.req("lock.lock");
    assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    let o = h.settled(&r);
    assert_eq!((o["status"].clone(), o["observed"].clone()), (json!("not_applied"), json!({"locked": false})), "{o}");
    h.idle(20);
    assert_eq!(world.invokes().len(), 1, "the lock never got it");
    assert_eq!(sent(&sidecar), 2, "the unlock, and the lock once: never resent by the new sidecar");
    assert!(sidecar.spawns() >= 2, "a new sidecar was started");
}

/// The sidecar dies after the lock took the command. Unknown, then the read
/// after the order shows it locked: `applied`. Nothing is sent again.
#[test]
fn a_sidecar_that_dies_after_the_device_acted_leaves_the_order_unknown_and_never_resent() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    sidecar.crash_on_next_invoke(Crash::AfterTheDevice);
    let r = h.req("lock.lock");
    assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    let o = h.settled(&r);
    assert_eq!((o["status"].clone(), o["observed"].clone()), (json!("applied"), json!({"locked": true})), "{o}");
    assert!(!h.in_recovery());
    h.idle(20);
    assert_eq!((world.invokes().len(), sent(&sidecar)), (2, 2), "the lock got it once");
}

/// A sidecar that hangs: the command's fate is unknown, it is never sent
/// again, and the hung sidecar is stopped and replaced, so the door can be
/// observed again once a sidecar answers.
#[test]
fn a_hung_sidecar_is_replaced_and_its_command_is_never_resent() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    sidecar.stall(true);
    let r = h.req("lock.lock");
    assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    sidecar.stall(false);
    let o = h.settled(&r);
    // the lock never got it: not applied if a new sidecar read it in time,
    // unconfirmed (and recovery) if not; never applied, never resent
    match o["status"].as_str() {
        Some("not_applied") => assert_eq!(o["observed"], json!({"locked": false})),
        Some("unconfirmed") => assert!(h.in_recovery()),
        other => panic!("{other:?}: {o}"),
    }
    h.idle(20);
    assert_eq!(world.invokes().len(), 1, "the lock never got it");
    assert_eq!(sent(&sidecar), 2, "sent once");
    until_observable(&mut h, true);
    assert!(sidecar.spawns() >= 2, "the hung sidecar was replaced");
}

/// A lock that reports what no lock state is: text, or a `LockState` out
/// of the enumeration. Nothing is made up: it is no state, so the door's
/// state is unknown and nothing is sent, until the lock reports a real one.
#[test]
fn a_malformed_state_makes_nothing_up() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    for junk in [json!("open sesame"), json!(7)] {
        world.set(MATTER_AT, (0x0101, 0x0000), junk);
        until_observable(&mut h, false);
        let r = h.req("lock.lock");
        assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-3-STATE"), "{}", r.summary());
        world.set(MATTER_AT, (0x0101, 0x0000), json!(2));
        until_observable(&mut h, true);
    }
    assert_eq!(sent(&sidecar), 1, "only the first unlock was ever sent");
}

/// Lines a sidecar should never send: not JSON is ignored; a line too long
/// ends that sidecar, and another one serves.
#[test]
fn malformed_lines_from_the_sidecar_are_ignored_or_end_it() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    sidecar.inject("this is not JSON");
    sidecar.inject("{\"event\": 42}");
    std::thread::sleep(Duration::from_millis(100));
    let r = h.req("lock.lock");
    assert!(r.is_ok(), "the same sidecar serves: {}", r.summary());
    let spawns = sidecar.spawns();
    sidecar.inject("x".repeat(300 * 1024));
    std::thread::sleep(Duration::from_millis(100));
    let r = h.req("lock.unlock");
    assert!(r.is_ok(), "another sidecar serves: {}", r.summary());
    assert!(sidecar.spawns() > spawns, "the sidecar that sent a line too long was replaced");
    assert_eq!(world.invokes().len(), 3, "the unlock, the lock, the unlock: each once");
}

// ───────────────────────────── the device ─────────────────────────────

/// A lock that jams answers `FAILURE` with its bolt part way: the fate is
/// unknown, no state settles it, and the door is put in recovery. Its safe
/// state is not run blindly: nothing is sent again.
#[test]
fn a_lock_that_jams_puts_the_door_in_recovery_without_a_second_command() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    world.next(NextCommand::Jam);
    let r = h.req("lock.lock");
    assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "FAILURE may have moved it: {}", r.summary());
    let o = h.settled(&r);
    assert_eq!(o["status"], "unconfirmed", "a jammed bolt states no `locked`: {o}");
    assert!(h.in_recovery());
    h.idle(20);
    assert_eq!((world.invokes().len(), sent(&sidecar)), (2, 2), "never a second command");
}

/// A subscription that goes quiet while the lock still answers reads, before
/// the controller notices (finding F12). Past the interval the lock agreed
/// to keep it alive at, and a margin, its last values are history: the door's
/// state is unknown, and nothing is sent. Once it reports again, it is a
/// state again.
#[test]
fn a_quiet_subscription_is_no_state_once_past_its_interval() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    world.quiet(1, true);
    // the fake lock agreed to 200 ms; the margin is 2 s
    std::thread::sleep(Duration::from_millis(2_400));
    until_observable(&mut h, false);
    let r = h.req("lock.lock");
    assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-3-STATE"), "{}", r.summary());
    assert_eq!(world.invokes().len(), 1, "nothing was sent");
    world.quiet(1, false);
    until_observable(&mut h, true);
    let r = h.req("lock.lock");
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(sent(&sidecar), 2);
}

/// A lock that drops off right after a command whose answer was lost: the
/// door is in recovery. When it rejoins, it is observed again, but the door
/// stays in recovery until a person ends it; then it is driven as before.
#[test]
fn a_lock_that_drops_off_and_rejoins_stays_in_recovery_until_a_person_ends_it() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    world.next(NextCommand::LoseAnswerAndGoSilent);
    let r = h.req("lock.lock");
    assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(h.settled(&r)["status"], "unconfirmed");
    assert!(h.in_recovery());
    h.rig.heal();
    until_observable(&mut h, true);
    let r = h.req("lock.unlock");
    assert!(!r.is_ok(), "still in recovery: {}", r.summary());
    assert_eq!(sent(&sidecar), 2, "nothing sent meanwhile");
    assert!(h.release().is_ok());
    let r = h.req("lock.unlock");
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(world.invokes().len(), 3);
}

// ───────────────────────────── Chitala restarts around a send ─────────────────────────────

/// Chitala crashes with the lock order on record, before it is sent. After
/// the restart the order may have run, as far as Chitala knows; the lock's
/// own read, after the order, shows it did not: `not_applied`. Nothing is
/// sent. (Through Home Assistant the same ends `unconfirmed`, with no state
/// after the order to judge by: `home_assistant::crash_after_the_order_is_on_record_but_before_it_is_sent`.)
#[test]
fn a_crash_before_the_lock_is_sent_ends_on_the_lock_s_own_read() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    let lock = h.lock();
    let bytes = h.signed(&lock, "lock.lock", Payload::new());
    let Step::Device(pending) = h.node.begin(&bytes) else { panic!("a device action") };
    drop(pending); // the node dies here
    let mut h = restart(h);
    assert_eq!(h.node.pending_outcomes().len(), 1, "watched as a command that may have run");
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let o = h.last_outcome();
    assert_eq!((o["status"].clone(), o["execution"].clone()), (json!("not_applied"), json!("unknown")), "{o}");
    assert_eq!((world.invokes().len(), sent(&sidecar)), (1, 1), "the lock was never sent");
}

/// Chitala crashes after the lock got the order, before its outcome is on
/// record. After the restart the lock's read shows it locked: `applied`.
/// Nothing is sent again.
#[test]
fn a_crash_after_the_lock_was_sent_ends_applied_and_never_resent() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    let lock = h.lock();
    let bytes = h.signed(&lock, "lock.lock", Payload::new());
    let Step::Device(mut pending) = h.node.begin(&bytes) else { panic!("a device action") };
    let _ = pending.run(); // the lock locks; the node dies before finishing
    drop(pending);
    let mut h = restart(h);
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let o = h.last_outcome();
    assert_eq!((o["status"].clone(), o["execution"].clone()), (json!("applied"), json!("unknown")), "{o}");
    assert!(!h.in_recovery());
    h.idle(20);
    assert_eq!((world.invokes().len(), sent(&sidecar)), (2, 2), "never resent");
}

// ───────────────────────────── reports twice, late, or for another device ─────────────────────────────

/// An old report arriving late, and twice: the subscription's values are no
/// evidence, so an order is still judged by the lock's own read. The lock
/// did nothing: `not_applied`, whatever the late report says.
#[test]
fn a_late_or_repeated_report_changes_no_outcome() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    let late = r#"{"event":"values","node":"1","endpoint":1,"values":[[257,0,1]]}"#;
    sidecar.inject(late);
    sidecar.inject(late);
    std::thread::sleep(Duration::from_millis(100));
    world.next(NextCommand::LoseAnswerWithoutEffect);
    let r = h.req("lock.lock");
    let o = h.settled(&r);
    assert_eq!((o["status"].clone(), o["observed"].clone()), (json!("not_applied"), json!({"locked": false})), "{o}");
}

/// Reports for another node, or another endpoint of the lock's node, never
/// reach this door.
#[test]
fn reports_for_another_device_never_reach_this_door() {
    let (mut h, world, sidecar) = matter_home(120_000);
    h.unlocked();
    sidecar.inject(r#"{"event":"values","node":"2","endpoint":1,"values":[[257,0,1]]}"#);
    sidecar.inject(r#"{"event":"values","node":"1","endpoint":2,"values":[[257,0,1]]}"#);
    std::thread::sleep(Duration::from_millis(100));
    world.next(NextCommand::LoseAnswerWithoutEffect);
    let r = h.req("lock.lock");
    let o = h.settled(&r);
    assert_eq!((o["status"].clone(), o["observed"].clone()), (json!("not_applied"), json!({"locked": false})), "{o}");
}

// ───────────────────────────── Home Assistant cut off ─────────────────────────────

/// A home on Home Assistant, its lock a Matter device read for evidence
/// through the Matter server (F10); the fakes' worlds kept by the test.
fn ha_home() -> (Home, Arc<Mutex<World>>, Arc<Mutex<MatterWorld>>) {
    let rig = HaRig::new();
    let (ha, matter) = (rig.ha.shared(), rig.matter.shared());
    (home(Box::new(rig)), ha, matter)
}

fn lock_calls(ha: &Arc<Mutex<World>>) -> Vec<(String, &'static str)> {
    ha.lock()
        .unwrap()
        .calls
        .iter()
        .filter(|(_, e, _)| e == "lock.front_door")
        .map(|(s, _, t)| (s.clone(), *t))
        .collect()
}

/// Cut off from Home Assistant's WebSocket API, not its REST API: a command
/// goes once, by REST, and the lock's own read verifies it.
#[test]
fn cut_off_from_home_assistant_s_websocket_a_command_goes_once_by_rest() {
    let (mut h, ha, _) = ha_home();
    h.unlocked();
    {
        let mut w = ha.lock().unwrap();
        w.ws_up = false;
        w.restarts += 1;
    }
    std::thread::sleep(Duration::from_millis(500));
    let r = h.req("lock.lock");
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(status(&r), "verified", "{}", r.summary());
    let calls = lock_calls(&ha);
    assert_eq!(calls.last().map(|(s, t)| (s.as_str(), *t)), Some(("lock.lock", "rest")), "{calls:?}");
    assert_eq!(calls.iter().filter(|(s, _)| s == "lock.lock").count(), 1, "once");
}

/// Cut off from the Matter server its lock is read through: Home Assistant
/// still runs the command, but nothing ties what it reports to the lock
/// (F10): `unconfirmed`, recovery, never a second command.
#[test]
fn cut_off_from_the_matter_server_a_matter_lock_s_outcome_is_unconfirmed() {
    let (mut h, ha, matter) = ha_home();
    h.unlocked();
    matter.lock().unwrap().cut_off = true;
    let r = h.req("lock.lock");
    let o = h.settled(&r);
    assert_eq!(o["status"], "unconfirmed", "{o}");
    assert!(h.in_recovery());
    h.idle(20);
    assert_eq!(lock_calls(&ha).len(), 2, "the unlock and the lock, each once");
}

// ───────────────────────────── both paths at once ─────────────────────────────

/// Two doors: the front door's lock through Home Assistant, the back door's
/// on Chitala's own fabric. Their orders run at the same time, round after
/// round: each order reaches its own lock once, each outcome is verified by
/// its own lock, and neither path touches the other's door.
#[test]
fn the_home_assistant_and_matter_paths_at_once_each_order_once_no_cross_talk() {
    let ha_rig = HaRig::new();
    let (ha, ha_matter) = (ha_rig.ha.shared(), ha_rig.matter.shared());
    let m = MatterRig::over_sidecar().named("device:back-lock");
    let (back_world, sidecar) = (m.backend.clone(), m.sidecar.clone().expect("through the sidecar"));
    let mut h = home_of(Box::new(ha_rig), vec![Box::new(m)]);
    let (front, back) = (h.lock(), id("device:back-lock"));
    let bolt = |locked: bool| json!(if locked { 1 } else { 2 });
    for round in 0..10 {
        // Safety lets a door move three times a minute (SAFE-6)
        h.clock.fetch_add(21_000, Ordering::SeqCst);
        let (c, locked) = if round % 2 == 0 { ("lock.unlock", false) } else { ("lock.lock", true) };
        let a = h.signed(&front, c, Payload::new());
        let b = h.signed(&back, c, Payload::new());
        let step = h.node.begin(&a);
        let Step::Device(mut pa) = step else {
            let Step::Done(r) = step else { panic!("neither") };
            panic!("round {round}: the front door: {}", r.summary())
        };
        let step = h.node.begin(&b);
        let Step::Device(mut pb) = step else {
            let Step::Done(r) = step else { panic!("neither") };
            panic!("round {round}: the back door: {}", r.summary())
        };
        let ta = std::thread::spawn(move || {
            let r = pa.run();
            (pa, r)
        });
        let tb = std::thread::spawn(move || {
            let r = pb.run();
            (pb, r)
        });
        let (pa, ra) = ta.join().unwrap();
        let (pb, rb) = tb.join().unwrap();
        for r in [h.node.finish(pa, ra), h.node.finish(pb, rb)] {
            assert_eq!(status(&r), "verified", "round {round}: {}", r.summary());
        }
        assert_eq!(ha_matter.lock().unwrap().nodes[&4].attributes["1/257/0"], bolt(locked), "round {round}");
        assert_eq!(back_world.get(MATTER_AT, (0x0101, 0x0000)), Some(bolt(locked)), "round {round}");
    }
    assert_eq!(lock_calls(&ha).len(), 10, "each front door order once");
    assert_eq!((back_world.invokes().len(), sent(&sidecar)), (10, 10), "each back door order once");
    assert!(h.node.domain_state().recovery.is_empty());
}

/// SAFE-8 (spec 22), on every rig: new evidence, a new safe-state order. A
/// lock order whose answer is lost, the lock gone silent: `unconfirmed`,
/// recovery, and nothing sent blind. Back, and found unlocked (by hand,
/// meanwhile): one new lock order, decided on that evidence. Back, and found
/// locked: nothing.
#[test]
fn a_door_back_from_silence_is_locked_on_evidence_only() {
    let rigs: [fn() -> Box<dyn chitala_adapters::conformance::Rig>; 2] =
        [|| Box::new(MockRig::new()), || Box::new(MatterRig::new())];
    for (make, unlocked_meanwhile) in rigs.iter().flat_map(|m| [(m, true), (m, false)]) {
        let mut h = home(make());
        let name = h.name();
        h.unlocked();
        h.rig.fault(Fault::LoseAnswerAndGoSilent);
        let r = h.req("lock.lock");
        assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "{name}: {}", r.summary());
        assert_eq!(h.settled(&r)["status"], "unconfirmed", "{name}");
        assert!(h.in_recovery(), "{name}");
        let sent = h.rig.commands();
        h.idle(10);
        assert_eq!(h.rig.commands(), sent, "{name}: nothing blind while it is silent");
        if unlocked_meanwhile {
            h.rig.by_hand(false);
        }
        h.rig.heal();
        // until its state is evidence again: confirmed current. The direct
        // Matter adapter reads a device that did not answer again only after a
        // few seconds, in real time (`device_read::READ_RETRY`)
        let lock = h.lock();
        let evidence = |h: &Home| {
            h.node.twins().get(&lock).is_some_and(|t| {
                t.unobservable_since_ms.is_none()
                    && t.confirmed_at_ms.is_some_and(|c| t.source_at_ms.is_some_and(|s| c >= s))
            })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !evidence(&h) && std::time::Instant::now() < deadline {
            h.idle(1);
            std::thread::sleep(Duration::from_millis(100));
        }
        h.idle(5);
        let expected = sent + usize::from(unlocked_meanwhile);
        assert_eq!(h.rig.commands(), expected, "{name}, unlocked meanwhile {unlocked_meanwhile}");
        assert_eq!(h.rig.bolt(), Some(true), "{name}");
        h.idle(30);
        assert_eq!(h.rig.commands(), expected, "{name}: one attempt for that evidence");
        assert!(h.in_recovery(), "{name}: a person still ends it");
        // still in recovery, reachable, and unlocked by hand: watched closely,
        // it is seen within seconds, and locked on that evidence
        if !unlocked_meanwhile {
            h.rig.by_hand(false);
            h.idle(8);
            assert_eq!(h.rig.commands(), expected + 1, "{name}: seen within seconds, locked");
            assert_eq!(h.rig.bolt(), Some(true), "{name}");
        }
    }
}
