use std::time::Duration;

use chitala_model::{payload, ExecCode, ParamValue, SecurityClass};

use super::*;
use crate::device_read::READ_WAIT;
use crate::direct_matter::fake::{FakeBackend, NextCommand};
use crate::testkit::authorize;

const AT: Target = Target { node: 1, endpoint: 1 };

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}

fn device(local: &str, caps: &[&str]) -> DeviceDescriptor {
    DeviceDescriptor {
        id: id(local),
        name: local.into(),
        adapter: ADAPTER.into(),
        room: None,
        security_class: SecurityClass::Sc1,
        capabilities: caps.iter().map(|c| CapabilityId::parse(c).unwrap()).collect(),
    }
}

fn lock() -> DeviceDescriptor {
    device("device:lock", &["device.read_state", "lock.lock", "lock.unlock"])
}

fn adapter(fake: &FakeBackend) -> DirectMatterAdapter {
    DirectMatterAdapter::new(Arc::new(fake.clone()), &[(lock(), AT)]).unwrap()
}

fn confirmed(o: &Observed) -> Option<u64> {
    match o.provenance {
        Provenance::ConfirmedCurrent { age_ms } => Some(age_ms),
        Provenance::Uncertain => None,
    }
}

/// The profile's commands, as Timed Invokes where it says so, once each; the
/// state returned is the one read right after.
#[test]
fn a_lock_is_driven_by_the_profile_s_timed_commands() {
    let fake = FakeBackend::new();
    fake.lock(AT, false);
    let mut a = adapter(&fake);
    let lock = id("device:lock");
    let s = a.execute(authorize(&lock, "lock.lock", Payload::new())).unwrap();
    assert_eq!(s, payload([("locked", true)]));
    let s = a.execute(authorize(&lock, "lock.unlock", Payload::new())).unwrap();
    assert_eq!(s, payload([("locked", false)]));
    assert_eq!(fake.invokes(), ["1/1 0x0101/0x00 timed", "1/1 0x0101/0x01 timed"]);
    assert_eq!(fake.world().subscriptions.iter().copied().collect::<Vec<_>>(), [AT], "subscribed at start");
}

/// What each answer says about the order, and nothing is ever sent twice.
#[test]
fn every_answer_says_what_it_says_about_the_order() {
    let lock = id("device:lock");
    let case = |setup: &dyn Fn(&FakeBackend)| {
        let fake = FakeBackend::new();
        fake.lock(AT, false);
        let mut a = adapter(&fake);
        setup(&fake);
        let r = a.execute(authorize(&lock, "lock.lock", Payload::new()));
        (r.map_err(|e| e.code()), fake.invokes().len(), fake.get(AT, (0x0101, 0)))
    };
    let unlocked = Some(serde_json::json!(2));
    let locked = Some(serde_json::json!(1));
    // the device did not answer the read before: nothing was sent
    assert_eq!(case(&|f| f.alive(1, false)), (Err(ExecCode::DeviceUnavailable), 0, unlocked.clone()));
    // statuses the device gives before acting: certainly not executed
    for status in [0x7E, 0x9C, 0x9D, 0xCB] {
        let r = case(&|f| f.next(NextCommand::Status(status)));
        assert_eq!(r, (Err(ExecCode::DeviceRefused), 1, unlocked.clone()), "status 0x{status:02X}");
    }
    for status in [0x7F, 0x81, 0x85, 0x87, 0xC3, 0xC6, 0xC9] {
        let r = case(&|f| f.next(NextCommand::Status(status)));
        assert_eq!(r, (Err(ExecCode::Adapter), 1, unlocked.clone()), "status 0x{status:02X}");
    }
    // FAILURE, TIMEOUT: a lock that jams moved part way; unknown
    for status in [0x01, 0x94] {
        let r = case(&|f| f.next(NextCommand::Status(status)));
        assert_eq!(r.0, Err(ExecCode::ExecutionUnknown), "status 0x{status:02X}");
    }
    // no answer, with or without effect
    assert_eq!(case(&|f| f.next(NextCommand::LoseAnswer)), (Err(ExecCode::ExecutionUnknown), 1, locked.clone()));
    assert_eq!(
        case(&|f| f.next(NextCommand::LoseAnswerWithoutEffect)),
        (Err(ExecCode::ExecutionUnknown), 1, unlocked.clone())
    );
    // success, and the device cannot be read right after: no state to vouch for
    assert_eq!(case(&|f| f.next(NextCommand::SucceedThenGoSilent)), (Err(ExecCode::ExecutionUnknown), 1, locked));
}

/// A plain observation is the subscription's: as old as the last time the
/// device was heard, and never evidence. A device gone silent keeps its
/// last state, getting older, until the controller notices; then it cannot
/// be observed.
#[test]
fn a_plain_observation_is_the_subscription_s_and_confirms_nothing() {
    let fake = FakeBackend::new();
    fake.lock(AT, true);
    let mut a = adapter(&fake);
    let lock = id("device:lock");
    let o = a.observe(&lock).unwrap();
    assert_eq!((o.state.clone(), confirmed(&o)), (payload([("locked", true)]), None));
    assert!(o.age_ms.is_some_and(|age| age < 50), "{o:?}");
    fake.set(AT, (0x0101, 0), serde_json::json!(2)); // turned by hand
    assert_eq!(a.observe(&lock).unwrap().state.get("locked"), Some(&ParamValue::Bool(false)));
    fake.alive(1, false);
    std::thread::sleep(Duration::from_millis(120));
    let o = a.observe(&lock).unwrap();
    assert!(o.age_ms.is_some_and(|age| age >= 120), "older since it was last heard: {o:?}");
    assert_eq!(confirmed(&o), None);
    std::thread::sleep(Duration::from_millis(250));
    assert!(matches!(a.observe(&lock), Err(AdapterError::Unavailable(_))), "noticed");
    assert_eq!(fake.world().reads, 0, "a plain observation reads nothing");
}

/// For evidence, the device is read itself, each read's values given once;
/// a device that does not answer is not read again at once, and its state is
/// then the subscription's, unconfirmed.
#[test]
fn evidence_is_a_read_of_the_device_given_once() {
    let fake = FakeBackend::new();
    fake.lock(AT, true);
    let mut a = adapter(&fake);
    let lock = id("device:lock");
    let o = a.observe_evidence(&lock).unwrap();
    assert_eq!(o.state, payload([("locked", true)]));
    assert!(confirmed(&o).is_some_and(|age| age < 1_000), "{o:?}");
    assert_eq!(fake.world().reads, 1);
    let o = a.observe_evidence(&lock).unwrap();
    assert!(confirmed(&o).is_some(), "a new read");
    assert_eq!(fake.world().reads, 2, "each read is evidence once");
    fake.alive(1, false);
    let o = a.observe_evidence(&lock).unwrap();
    assert_eq!(confirmed(&o), None, "no answer: the subscription's state, unconfirmed");
    let o = a.observe_evidence(&lock).unwrap();
    assert_eq!(confirmed(&o), None);
    assert_eq!(fake.world().reads, 3, "not read again at once");
}

/// A slow read is waited for a moment and goes on in the background; it
/// counts when it comes, as of when it began.
#[test]
fn a_slow_read_counts_as_of_when_it_began() {
    let fake = FakeBackend::new();
    fake.lock(AT, true);
    fake.world().read_takes = READ_WAIT + Duration::from_millis(300);
    let mut a = adapter(&fake);
    let lock = id("device:lock");
    let began = std::time::Instant::now();
    assert_eq!(confirmed(&a.observe_evidence(&lock).unwrap()), None, "not back yet");
    assert!(began.elapsed() < READ_WAIT + Duration::from_millis(200), "waited {:?}", began.elapsed());
    std::thread::sleep(Duration::from_millis(500));
    let o = a.observe_evidence(&lock).unwrap();
    assert!(confirmed(&o).is_some_and(|age| age >= 1_300), "as of when the read began: {o:?}");
    assert_eq!(fake.world().reads, 1, "one read at a time");
}

/// Only what the Home profile maps: a device's class comes from its
/// capabilities, each of which must map to a Matter command; parameters are
/// refused before anything is sent.
#[test]
fn only_what_the_profile_maps() {
    assert_eq!(class_of(&lock()).unwrap().class, "lock");
    assert_eq!(class_of(&device("device:plug", &["switch.turn_on", "switch.turn_off"])).unwrap().class, "plug");
    let dimmer = device("device:light", &["light.turn_on", "light.set_brightness"]);
    assert!(class_of(&dimmer).unwrap_err().to_string().contains("no Matter command for light.set_brightness"));
    assert!(class_of(&device("device:x", &["device.read_state"])).is_err(), "nothing to drive");
    assert!(class_of(&device("device:x", &["lock.lock", "light.turn_on"])).is_err(), "no such class");
    let class = class_of(&lock()).unwrap();
    assert!(ProfileCommand::of(class, &CapabilityId::parse("light.turn_on").unwrap()).is_none());

    let fake = FakeBackend::new();
    fake.lock(AT, false);
    let mut a = adapter(&fake);
    let r = a.execute(authorize(&id("device:lock"), "lock.lock", payload([("code", 1234i64)])));
    assert_eq!(r.map_err(|e| e.code()), Err(ExecCode::Adapter));
    assert!(fake.invokes().is_empty(), "nothing was sent");
    // a node not on the fabric cannot be bound
    let r = DirectMatterAdapter::new(Arc::new(FakeBackend::new()), &[(lock(), AT)]);
    assert!(r.is_err());
}

/// A subscription that goes quiet before the controller notices (F12): past
/// the interval the device agreed to, and a margin, its last values are not
/// a state any more; when it reports again, they are.
#[test]
fn a_subscription_quiet_past_its_interval_is_no_state() {
    let fake = FakeBackend::new();
    fake.lock(AT, true);
    let mut a = adapter(&fake);
    let lock = id("device:lock");
    fake.quiet(1, true);
    std::thread::sleep(Duration::from_millis(1_000));
    assert!(a.observe(&lock).is_ok(), "within its interval and the margin");
    std::thread::sleep(super::SILENCE_MARGIN);
    assert!(matches!(a.observe(&lock), Err(AdapterError::Unavailable(_))), "past them");
    assert!(fake.subscribed(AT).unwrap().live, "though the controller has not noticed");
    fake.quiet(1, false);
    assert!(a.observe(&lock).is_ok());
}
