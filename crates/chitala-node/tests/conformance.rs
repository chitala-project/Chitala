//! The adapter conformance suite (spec 26), the node's half: every adapter,
//! on its rig, through the whole chain (Authority → Safety → the trusted
//! boundary → the adapter → outcome verification and recovery). Whatever the
//! adapter, Chitala ends with the same judgement of what an order did, and
//! never sends a command twice.

use std::sync::atomic::Ordering;
use std::time::Duration;

use chitala_adapters::conformance::{Fault, HaRig, MatterRig, MockRig, Rig};
use chitala_model::ExecCode;
use serde_json::json;

mod common;

use common::*;

// ───────────────────────────── the contract ─────────────────────────────

/// An order reaches the device once and is verified by what the device says.
fn an_order_is_verified_once(rig: Box<dyn Rig>) {
    let mut h = home(rig);
    let name = h.name();
    h.unlocked();
    let r = h.req("lock.lock");
    assert!(r.is_ok(), "{name}: {}", r.summary());
    assert_eq!(status(&r), "verified", "{name}: {}", r.summary());
    assert_eq!(h.rig.bolt(), Some(true), "{name}");
    h.idle(20);
    assert_eq!(h.rig.commands(), 2, "{name}: each order once");
    assert!(!h.in_recovery(), "{name}");
}

/// A lost answer: the order's fate is unknown until the device shows what it
/// did, after the order. It did lock: `applied`, no recovery, never resent.
fn a_lost_answer_is_settled_by_what_the_device_did(rig: Box<dyn Rig>) {
    let mut h = home(rig);
    let name = h.name();
    h.unlocked();
    h.rig.fault(Fault::LoseAnswer);
    let r = h.req("lock.lock");
    assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "{name}: {}", r.summary());
    let o = h.settled(&r);
    assert_eq!(o["status"], "applied", "{name}: {o}");
    assert_eq!(o["observed"], json!({"locked": true}), "{name}: {o}");
    assert!(!h.in_recovery(), "{name}");
    h.idle(20);
    assert_eq!(h.rig.commands(), 2, "{name}: never sent twice");
}

/// A lost answer, and the device did nothing: `not_applied`, never resent.
fn a_lost_answer_without_effect_is_not_applied(rig: Box<dyn Rig>) {
    let mut h = home(rig);
    let name = h.name();
    h.unlocked();
    h.rig.fault(Fault::LoseAnswerWithoutEffect);
    let r = h.req("lock.lock");
    assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "{name}: {}", r.summary());
    let o = h.settled(&r);
    assert_eq!(o["status"], "not_applied", "{name}: {o}");
    assert_eq!(o["observed"], json!({"locked": false}), "{name}: {o}");
    h.idle(20);
    assert_eq!(h.rig.commands(), 2, "{name}: never sent twice");
}

/// A lost answer from a device that then went silent: nothing can tell what
/// the order did. `unconfirmed`, and the door is put in recovery; its safe
/// state is not run blindly, and nothing is sent again (spec 22).
fn a_lost_answer_from_a_silent_device_is_unconfirmed_and_recovered(rig: Box<dyn Rig>) {
    let mut h = home(rig);
    let name = h.name();
    h.unlocked();
    h.rig.fault(Fault::LoseAnswerAndGoSilent);
    let r = h.req("lock.lock");
    assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "{name}: {}", r.summary());
    let o = h.settled(&r);
    assert_eq!(o["status"], "unconfirmed", "{name}: {o}");
    assert!(h.in_recovery(), "{name}: the door is in recovery");
    h.idle(20);
    assert_eq!(h.rig.commands(), 2, "{name}: never sent twice, the safe state not run blindly");
}

/// A device that cannot be reached: once the node has looked, the door's
/// state is not known, and Safety refuses to act on it; nothing is sent
/// (F6). Once it is reached again, it can be acted on.
fn an_unreachable_device_is_not_acted_on(rig: Box<dyn Rig>) {
    let mut h = home(rig);
    let name = h.name();
    h.unlocked();
    h.rig.fault(Fault::Offline);
    let lock = h.lock();
    for _ in 0..200 {
        if h.node.twins().evidence(&lock, h.node.now()).is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        h.clock.fetch_add(60_000, Ordering::SeqCst);
        h.node.tick();
    }
    assert!(h.node.twins().evidence(&lock, h.node.now()).is_none(), "{name}: the door cannot be observed");
    let r = h.req("lock.lock");
    assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-3-STATE"), "{name}: {}", r.summary());
    assert_eq!(h.rig.commands(), 1, "{name}: nothing was sent");
    h.rig.heal();
    h.ticks_until("the door is observed again", |n| n.twins().evidence(&lock, n.now()).is_some());
    let r = h.req("lock.lock");
    assert!(r.is_ok(), "{name}: {}", r.summary());
    assert_eq!(h.rig.commands(), 2, "{name}");
}

macro_rules! conforms {
    ($adapter:ident, $rig:expr) => {
        mod $adapter {
            use super::*;

            fn rig() -> Box<dyn Rig> {
                Box::new($rig)
            }

            #[test]
            fn an_order_is_verified_once() {
                super::an_order_is_verified_once(rig());
            }
            #[test]
            fn a_lost_answer_is_settled_by_what_the_device_did() {
                super::a_lost_answer_is_settled_by_what_the_device_did(rig());
            }
            #[test]
            fn a_lost_answer_without_effect_is_not_applied() {
                super::a_lost_answer_without_effect_is_not_applied(rig());
            }
            #[test]
            fn a_lost_answer_from_a_silent_device_is_unconfirmed_and_recovered() {
                super::a_lost_answer_from_a_silent_device_is_unconfirmed_and_recovered(rig());
            }
            #[test]
            fn an_unreachable_device_is_not_acted_on() {
                super::an_unreachable_device_is_not_acted_on(rig());
            }
        }
    };
}

conforms!(mock, MockRig::new());
conforms!(home_assistant, HaRig::new());
conforms!(direct_matter, MatterRig::new());
conforms!(direct_matter_sidecar, MatterRig::over_sidecar());
