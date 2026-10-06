//! The adapter conformance suite (spec 26), the adapter's half: every
//! adapter, on its rig, against the same contract. The rigs are in
//! `chitala_adapters::conformance`; the orders and the checks are here, test
//! code, so that nothing outside the boundary's allowlist builds, admits or
//! sends an order.

#![cfg(feature = "conformance")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use chitala_adapters::conformance::{Fault, HaRig, MatterRig, MockRig, Rig};
use chitala_adapters::profile::HomeProfile;
use chitala_adapters::{AdapterError, DeviceAdapter, Observed, OrderGate, Provenance, VerifiedOrder};
use chitala_csme::order::{payload_digest, ExecOrder};
use chitala_identity::{test_seed, Keypair};
use chitala_model::{CapabilityId, EntityId, ParamValue, Payload};

// ───────────────────────────── orders ─────────────────────────────

const SESSION: [u8; 16] = [0x5c; 16];

fn order_key() -> &'static Keypair {
    static KEY: OnceLock<Keypair> = OnceLock::new();
    KEY.get_or_init(|| Keypair::from_seed(&test_seed("conformance/boundary")))
}

/// An order for `capability` on `device`, signed and admitted as the node's
/// trusted boundary and an adapter host's gate would.
fn admitted(device: &EntityId, capability: &str) -> VerifiedOrder {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let now = 1_790_000_000_000 + n;
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let params = Payload::new();
    let order = ExecOrder {
        id,
        executor: SESSION,
        subject: [1; 16],
        subject_digest: [2; 32],
        actor: EntityId::parse("person:alice").expect("valid"),
        resource: EntityId::parse(&format!("resource:{}", device.local())).expect("valid"),
        device: device.clone(),
        capability: CapabilityId::parse(capability).expect("a capability"),
        capability_version: 1,
        params_digest: payload_digest(&params),
        params,
        context_digest: [3; 32],
        epoch: 1,
        evidence_seq: 1,
        cleared_at_ms: now,
        issued_at_ms: now,
        expires_at_ms: now + 10_000,
    };
    OrderGate::new(order_key().public_key(), SESSION, Arc::new(move || now))
        .admit(&order.sign(order_key()))
        .expect("a conformance order is admitted")
}

// ───────────────────────────── the contract ─────────────────────────────

/// An admitted order reaches the device once; observing sends nothing.
fn executes_an_order_once(rig: &mut dyn Rig) {
    let name = rig.adapter_name();
    let mut a = rig.adapter();
    let lock = rig.lock();
    rig.by_hand(false);
    sees(name, a.as_mut(), &lock, false);
    let before = rig.commands();
    let r = a.execute(admitted(&lock, "lock.lock"));
    assert!(r.is_ok(), "{name}: {r:?}");
    assert_eq!(rig.bolt(), Some(true), "{name}: the bolt is thrown");
    assert_eq!(rig.commands(), before + 1, "{name}: one command");
    sees(name, a.as_mut(), &lock, true);
    quiet(a.as_mut(), &lock, Duration::from_millis(300));
    assert_eq!(rig.commands(), before + 1, "{name}: observing sends no command");
}

/// A command whose answer was lost after it reached the device has an
/// unknown fate, and is never sent again.
fn never_resends_a_command_whose_answer_was_lost(rig: &mut dyn Rig) {
    let name = rig.adapter_name();
    let mut a = rig.adapter();
    let lock = rig.lock();
    rig.by_hand(false);
    sees(name, a.as_mut(), &lock, false);
    let before = rig.commands();
    rig.fault(Fault::LoseAnswer);
    let r = a.execute(admitted(&lock, "lock.lock"));
    assert!(matches!(r, Err(AdapterError::Indeterminate(_))), "{name}: unknown, not {r:?}");
    assert_eq!(rig.bolt(), Some(true), "{name}: it took effect");
    quiet(a.as_mut(), &lock, Duration::from_millis(1_000));
    assert_eq!(rig.commands(), before + 1, "{name}: never sent again");
    // and what it did can be established afterwards
    confirms(name, a.as_mut(), &lock, true);
    assert_eq!(rig.commands(), before + 1, "{name}: never sent again");
}

/// A lost answer is unknown even when the device did nothing: the
/// adapter cannot tell the two apart.
fn a_lost_answer_without_effect_is_unknown_too(rig: &mut dyn Rig) {
    let name = rig.adapter_name();
    let mut a = rig.adapter();
    let lock = rig.lock();
    rig.by_hand(false);
    sees(name, a.as_mut(), &lock, false);
    let before = rig.commands();
    rig.fault(Fault::LoseAnswerWithoutEffect);
    let r = a.execute(admitted(&lock, "lock.lock"));
    assert!(matches!(r, Err(AdapterError::Indeterminate(_))), "{name}: unknown, not {r:?}");
    assert_eq!(rig.bolt(), Some(false), "{name}: nothing moved");
    quiet(a.as_mut(), &lock, Duration::from_millis(500));
    assert_eq!(rig.commands(), before + 1, "{name}: never sent again");
    confirms(name, a.as_mut(), &lock, false);
}

/// A device that went silent right after a command whose answer was
/// lost: the fate is unknown, and nothing confirms what it did.
fn a_lost_answer_from_a_device_gone_silent_confirms_nothing(rig: &mut dyn Rig) {
    let name = rig.adapter_name();
    let mut a = rig.adapter();
    let lock = rig.lock();
    rig.by_hand(false);
    confirms(name, a.as_mut(), &lock, false);
    let before = rig.commands();
    rig.fault(Fault::LoseAnswerAndGoSilent);
    let r = a.execute(admitted(&lock, "lock.lock"));
    assert!(matches!(r, Err(AdapterError::Indeterminate(_))), "{name}: unknown, not {r:?}");
    assert_eq!(rig.bolt(), Some(true), "{name}: it took effect");
    let sent = Instant::now();
    let end = sent + Duration::from_millis(1_000);
    while Instant::now() < end {
        let since = sent.elapsed();
        if let Ok(o) = a.observe_evidence(&lock) {
            if let Some(age) = confirmed(&o) {
                assert!(u128::from(age) >= since.as_millis(), "{name}: nothing confirms it after the order: {o:?}");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(rig.commands(), before + 1, "{name}: never sent again");
}

/// A refusal the backend states is a certain failure, not an unknown.
fn a_refusal_is_a_certain_failure(rig: &mut dyn Rig) {
    let name = rig.adapter_name();
    let mut a = rig.adapter();
    let lock = rig.lock();
    rig.by_hand(false);
    sees(name, a.as_mut(), &lock, false);
    let before = rig.commands();
    rig.fault(Fault::Refuse);
    let r = a.execute(admitted(&lock, "lock.lock"));
    assert!(
        matches!(r, Err(AdapterError::Refused(_) | AdapterError::Failed(_))),
        "{name}: a certain failure, not {r:?}"
    );
    assert_eq!(rig.bolt(), Some(false), "{name}: nothing moved");
    assert!(rig.commands() <= before + 1, "{name}: at most the one command");
}

/// The adapter observes the device as it is, in the profile's terms, and
/// follows changes made outside Chitala.
fn observes_the_device_as_it_is(rig: &mut dyn Rig) {
    let name = rig.adapter_name();
    let mut a = rig.adapter();
    let lock = rig.lock();
    let class = HomeProfile::v0_1().class("lock").expect("the profile has locks");
    // each a change, so each is heard live (a state from a bootstrap has no age, F9)
    for want in [false, true, false] {
        rig.by_hand(want);
        let o = eventually(name, &format!("heard live, locked: {want}"), || {
            a.observe(&lock).ok().filter(|o| locked(o) == Some(want) && o.age_ms.is_some())
        });
        assert!(class.conforms(&o.state).is_ok(), "{name}: {:?} is a lock state", o.state);
    }
    assert_eq!(rig.commands(), 0, "{name}: observing sends no command");
}

/// A state tied to the device now is confirmed, recently.
fn confirms_what_the_device_says_now(rig: &mut dyn Rig) {
    let name = rig.adapter_name();
    let mut a = rig.adapter();
    let lock = rig.lock();
    rig.by_hand(false);
    let o = confirms(name, a.as_mut(), &lock, false);
    assert!(confirmed(&o).is_some_and(|age| age < 2_000), "{name}: {o:?}");
}

/// A device that went silent confirms nothing new: no state younger than
/// its silence is confirmed, a command does not succeed, and nothing is
/// made up. Once it can be reached again, it is confirmed again.
fn a_silent_device_confirms_nothing_new(rig: &mut dyn Rig) {
    let name = rig.adapter_name();
    let mut a = rig.adapter();
    let lock = rig.lock();
    rig.by_hand(false);
    confirms(name, a.as_mut(), &lock, false);
    rig.fault(Fault::Offline);
    let silent = Instant::now();
    std::thread::sleep(Duration::from_millis(300));
    let end = Instant::now() + Duration::from_millis(1_000);
    while Instant::now() < end {
        for evidence in [false, true] {
            let since = silent.elapsed();
            let o = if evidence { a.observe_evidence(&lock) } else { a.observe(&lock) };
            if let Ok(o) = &o {
                if let Some(age) = confirmed(o) {
                    assert!(
                        u128::from(age) >= since.as_millis(),
                        "{name}: confirmed {age} ms ago, but silent for {since:?}"
                    );
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let before = rig.commands();
    let r = a.execute(admitted(&lock, "lock.lock"));
    assert!(r.is_err(), "{name}: a silent device does not lock: {r:?}");
    assert_eq!(rig.bolt(), Some(false), "{name}: nothing moved");
    assert!(rig.commands() <= before + 1, "{name}: at most the one command");
    rig.heal();
    confirms(name, a.as_mut(), &lock, false);
}
// ───────────────────────────── helpers ─────────────────────────────

/// The age at which `o` is confirmed current, if it is.
fn confirmed(o: &Observed) -> Option<u64> {
    match o.provenance {
        Provenance::ConfirmedCurrent { age_ms } => Some(age_ms),
        Provenance::Uncertain => None,
    }
}

fn locked(o: &Observed) -> Option<bool> {
    o.state.get("locked").and_then(ParamValue::as_bool)
}

/// Wait (at most 5 s) until a plain observation shows the bolt `locked`.
fn sees(name: &str, a: &mut dyn DeviceAdapter, lock: &EntityId, locked_: bool) -> Observed {
    eventually(name, &format!("observed locked: {locked_}"), || {
        a.observe(lock).ok().filter(|o| locked(o) == Some(locked_))
    })
}

/// Wait (at most 5 s) until an observation for evidence confirms the bolt `locked`.
fn confirms(name: &str, a: &mut dyn DeviceAdapter, lock: &EntityId, locked_: bool) -> Observed {
    eventually(name, &format!("confirmed locked: {locked_}"), || {
        a.observe_evidence(lock).ok().filter(|o| locked(o) == Some(locked_) && confirmed(o).is_some())
    })
}

fn eventually<T>(name: &str, what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "{name}: timed out waiting until {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Observe, plainly and for evidence, for a while.
fn quiet(a: &mut dyn DeviceAdapter, lock: &EntityId, d: Duration) {
    let end = Instant::now() + d;
    while Instant::now() < end {
        let _ = a.observe(lock);
        let _ = a.observe_evidence(lock);
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ───────────────────────────── the rigs ─────────────────────────────

/// One test per check of the contract, each on a fresh rig.
macro_rules! conforms {
    ($adapter:ident, $rig:expr) => {
        mod $adapter {
            use super::*;

            fn rig() -> Box<dyn Rig> {
                Box::new($rig)
            }

            #[test]
            fn executes_an_order_once() {
                super::executes_an_order_once(rig().as_mut());
            }
            #[test]
            fn never_resends_a_command_whose_answer_was_lost() {
                super::never_resends_a_command_whose_answer_was_lost(rig().as_mut());
            }
            #[test]
            fn a_lost_answer_without_effect_is_unknown_too() {
                super::a_lost_answer_without_effect_is_unknown_too(rig().as_mut());
            }
            #[test]
            fn a_lost_answer_from_a_device_gone_silent_confirms_nothing() {
                super::a_lost_answer_from_a_device_gone_silent_confirms_nothing(rig().as_mut());
            }
            #[test]
            fn a_refusal_is_a_certain_failure() {
                super::a_refusal_is_a_certain_failure(rig().as_mut());
            }
            #[test]
            fn observes_the_device_as_it_is() {
                super::observes_the_device_as_it_is(rig().as_mut());
            }
            #[test]
            fn confirms_what_the_device_says_now() {
                super::confirms_what_the_device_says_now(rig().as_mut());
            }
            #[test]
            fn a_silent_device_confirms_nothing_new() {
                super::a_silent_device_confirms_nothing_new(rig().as_mut());
            }
        }
    };
}

conforms!(mock, MockRig::new());
conforms!(home_assistant, HaRig::new());
conforms!(direct_matter, MatterRig::new());
