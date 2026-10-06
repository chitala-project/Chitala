//! The adversarial Home suite (v0.3 step ⑥, spec 28), on the direct Matter
//! path: the whole chain, with the matter.js backend speaking the real
//! sidecar protocol to a fake sidecar that crashes, hangs, lies about its
//! lines, and devices that jam, go quiet, or drop off and come back. Whatever
//! happens, a command reaches the device at most once, nothing is made up,
//! and what Chitala cannot establish ends `unconfirmed`, with recovery.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use chitala_adapters::conformance::MatterRig;
use chitala_adapters::direct_matter::fake::{FakeBackend, NextCommand};
use chitala_adapters::direct_matter::fake_sidecar::{Crash, SidecarControl};
use chitala_adapters::direct_matter::Target;
use chitala_model::ExecCode;
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
