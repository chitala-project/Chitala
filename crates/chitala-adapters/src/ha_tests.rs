//! The Home Assistant adapter against a deterministic fake Home Assistant
//! (spec 25): its WebSocket and REST APIs, with fault injection — lost
//! connections, restarts, silence, refused and unanswered calls, transitional,
//! jammed and unavailable states, duplicate and out-of-order events.
//!
//! The invariants under test: the adapter only executes and observes; it never
//! sends a command twice; a command whose fate is unknown is indeterminate; and
//! nothing that was not observed ever becomes a state.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use chitala_model::{payload, DeviceDescriptor, EntityId, ParamValue, Payload, SecurityClass};
use serde_json::{json, Value};

use super::link::{CallError, Link, Timing};
use super::*;
use crate::fake_ha::{Behaviour, FakeHa, TOKEN};
use crate::testkit::authorize;
use crate::DeviceAdapter;

const TOKEN_ENV: &str = "CHITALA_TEST_FAKE_HA_TOKEN";

fn token_env() -> &'static str {
    static SET: OnceLock<()> = OnceLock::new();
    SET.get_or_init(|| std::env::set_var(TOKEN_ENV, TOKEN));
    TOKEN_ENV
}

fn fast() -> Timing {
    Timing {
        connect: Duration::from_secs(2),
        call: Duration::from_millis(400),
        poll: Duration::from_millis(5),
        ping_every: Duration::from_millis(150),
        min_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(80),
    }
}

/// Wait until `f` holds (at most 5 s).
fn until(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Adapters on the fake.
trait Adapters {
    fn adapter(&self, timing: Option<Timing>) -> HomeAssistantAdapter;
    fn live_adapter(&self) -> HomeAssistantAdapter;
}

impl Adapters for FakeHa {
    fn adapter(&self, timing: Option<Timing>) -> HomeAssistantAdapter {
        let entities: BTreeMap<EntityId, String> = [
            ("device:light", "light.living_room"),
            ("device:plug", "switch.kettle"),
            ("device:lock", "lock.front_door"),
        ]
        .into_iter()
        .map(|(d, e)| (EntityId::parse(d).unwrap(), e.to_string()))
        .collect();
        HomeAssistantAdapter::with_link(&self.url(), token_env(), entities, false, timing).unwrap()
    }

    fn live_adapter(&self) -> HomeAssistantAdapter {
        let a = self.adapter(Some(fast()));
        until("the link is live", || a.link().unwrap().live());
        a
    }
}

// ───────────────────────────── the tests ─────────────────────────────

fn dev(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}

#[test]
fn the_link_bootstraps_and_serves_pushed_states_without_polling() {
    let ha = FakeHa::start();
    let mut a = ha.live_adapter();
    assert_eq!(a.observe(&dev("device:lock")).unwrap(), payload([("locked", true)]));
    // someone switches the light on at the wall: pushed, no REST read
    ha.world().set("light.living_room", "on", json!({"brightness": 255}));
    until("the light is seen on", || a.link().unwrap().state("light.living_room").is_some_and(|s| s["state"] == "on"));
    let state = a.observe(&dev("device:light")).unwrap();
    assert_eq!(state, payload([("on", ParamValue::Bool(true)), ("brightness_pct", ParamValue::Int(100))]));
    assert_eq!(ha.world().rest_reads, 0, "observations come from the link");
}

#[test]
fn a_command_goes_over_the_link_exactly_once() {
    let ha = FakeHa::start();
    let mut a = ha.live_adapter();
    let state = a.execute(authorize(&dev("device:plug"), "switch.turn_on", Payload::new())).unwrap();
    assert_eq!(state, payload([("on", true)]));
    assert_eq!(ha.calls(), [("switch.turn_on".to_string(), "switch.kettle".to_string(), "ws")]);
}

#[test]
fn a_lock_still_moving_never_passes_for_its_target() {
    let ha = FakeHa::start();
    ha.behave("lock.front_door", Behaviour::Moving);
    let mut a = ha.live_adapter();
    let state = a.execute(authorize(&dev("device:lock"), "lock.unlock", Payload::new())).unwrap();
    assert!(!state.contains_key("locked"), "unlocking is not unlocked: {state:?}");
    until("the lock is seen moving", || {
        a.link().unwrap().state("lock.front_door").is_some_and(|s| s["state"] == "unlocking")
    });
    assert_eq!(a.observe(&dev("device:lock")).unwrap(), payload([("moving", true)]));
    // the bolt arrives
    ha.world().set("lock.front_door", "unlocked", json!({}));
    until("the lock is seen unlocked", || {
        a.link().unwrap().state("lock.front_door").is_some_and(|s| s["state"] == "unlocked")
    });
    assert_eq!(a.observe(&dev("device:lock")).unwrap(), payload([("locked", false)]));
}

#[test]
fn jammed_unavailable_and_removed_are_never_states() {
    let ha = FakeHa::start();
    let mut a = ha.live_adapter();
    let seen =
        |a: &HomeAssistantAdapter, s: &str| a.link().unwrap().state("lock.front_door").is_some_and(|v| v["state"] == s);
    ha.world().set("lock.front_door", "jammed", json!({}));
    until("jammed", || seen(&a, "jammed"));
    assert_eq!(a.observe(&dev("device:lock")).unwrap(), payload([("fault", "jammed")]));
    ha.world().set("lock.front_door", "unavailable", json!({}));
    until("unavailable", || seen(&a, "unavailable"));
    assert!(matches!(a.observe(&dev("device:lock")), Err(AdapterError::Unavailable(_))));
    ha.world().set("lock.front_door", "unknown", json!({}));
    until("unknown", || seen(&a, "unknown"));
    assert!(matches!(a.observe(&dev("device:lock")), Err(AdapterError::Unavailable(_))));
    // the entity is removed from Home Assistant: unknown, never its old state
    ha.world().set("lock.front_door", "locked", json!({}));
    until("locked", || seen(&a, "locked"));
    ha.world().broadcast(json!({"type": "event", "event": {"event_type": "state_changed",
        "data": {"entity_id": "lock.front_door", "new_state": null}}}));
    until("removed", || seen(&a, "unavailable"));
    assert!(matches!(a.observe(&dev("device:lock")), Err(AdapterError::Unavailable(_))));
}

#[test]
fn duplicate_and_out_of_order_events_never_move_a_state_back() {
    let ha = FakeHa::start();
    let mut a = ha.live_adapter();
    let old = ha.world().states["switch.kettle"].clone(); // "off", older
    ha.world().set("switch.kettle", "on", json!({}));
    until("on", || a.link().unwrap().state("switch.kettle").is_some_and(|s| s["state"] == "on"));
    let current = ha.world().states["switch.kettle"].clone();
    let event = |s: &Value| {
        json!({"type": "event", "event": {"event_type": "state_changed",
            "data": {"entity_id": "switch.kettle", "new_state": s}}})
    };
    // a marker after an event, on another entity, proves the event was processed
    let marker = |ha: &FakeHa, a: &HomeAssistantAdapter, s: &str| {
        ha.world().set("light.living_room", s, json!({}));
        until("the marker", || a.link().unwrap().state("light.living_room").is_some_and(|v| v["state"] == s));
    };
    // a late event from before: ignored
    ha.world().broadcast(event(&old));
    marker(&ha, &a, "on");
    assert_eq!(a.observe(&dev("device:plug")).unwrap(), payload([("on", true)]));
    // a duplicate of the current one: nothing changes
    ha.world().broadcast(event(&current));
    marker(&ha, &a, "off");
    assert_eq!(a.observe(&dev("device:plug")).unwrap(), payload([("on", true)]));
    // a newer one is taken
    ha.world().set("switch.kettle", "off", json!({}));
    until("off", || a.link().unwrap().state("switch.kettle").is_some_and(|s| s["state"] == "off"));
    assert_eq!(a.observe(&dev("device:plug")).unwrap(), payload([("on", false)]));
}

#[test]
fn a_command_lost_after_sending_is_indeterminate_and_never_sent_again() {
    let ha = FakeHa::start();
    ha.behave("lock.front_door", Behaviour::LoseAfterSend);
    ha.world().set("lock.front_door", "unlocked", json!({}));
    let mut a = ha.live_adapter();
    let err = a.execute(authorize(&dev("device:lock"), "lock.lock", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Unavailable(m) if m.contains("may have executed")), "{err}");
    // the door did lock; the adapter neither resent it nor guessed
    assert_eq!(ha.calls().len(), 1, "never sent twice: {:?}", ha.calls());
    assert_eq!(ha.world().states["lock.front_door"]["state"], "locked");
    // once the link is back, observing tells the truth: Chitala's outcome
    // verification finds the command applied (spec 22)
    until("reconnected", || a.link().unwrap().connections() >= 2 && a.link().unwrap().live());
    assert_eq!(a.observe(&dev("device:lock")).unwrap(), payload([("locked", true)]));
    assert_eq!(ha.calls().len(), 1);
}

#[test]
fn no_result_in_time_is_indeterminate_and_never_sent_again() {
    let ha = FakeHa::start();
    ha.behave("switch.kettle", Behaviour::Silent);
    let mut a = ha.live_adapter();
    let err = a.execute(authorize(&dev("device:plug"), "switch.turn_on", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Unavailable(m) if m.contains("may have executed")), "{err}");
    assert_eq!(ha.calls().len(), 1);
    std::thread::sleep(fast().call * 2);
    assert_eq!(ha.calls().len(), 1, "no retry later either");
}

#[test]
fn errors_are_reported_and_never_retried() {
    let ha = FakeHa::start();
    let mut a = ha.live_adapter();
    // Home Assistant did not run it: a definite failure
    ha.behave("switch.kettle", Behaviour::Error("service_validation_error"));
    let err = a.execute(authorize(&dev("device:plug"), "switch.turn_on", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Failed(m) if m.contains("did not run")), "{err}");
    // an integration error may come after the device was reached: indeterminate
    ha.behave("switch.kettle", Behaviour::Error("home_assistant_error"));
    let err = a.execute(authorize(&dev("device:plug"), "switch.turn_on", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Unavailable(m) if m.contains("may have executed")), "{err}");
    assert_eq!(ha.calls().len(), 2, "one call per order: {:?}", ha.calls());
    // and a stuck device is reported as it is: Chitala's outcome verification
    // will find the promise broken (spec 22)
    ha.behave("switch.kettle", Behaviour::Stuck);
    let state = a.execute(authorize(&dev("device:plug"), "switch.turn_on", Payload::new())).unwrap();
    assert_eq!(state, payload([("on", false)]));
}

#[test]
fn after_a_restart_the_link_reconnects_and_bootstraps_again() {
    let ha = FakeHa::start();
    let mut a = ha.live_adapter();
    {
        let mut w = ha.world();
        w.ws_up = false;
        w.restarts += 1;
    }
    until("the link noticed", || !a.link().unwrap().live());
    // while it is down, the door is unlocked: the event is missed, so the
    // adapter reads the state over REST rather than serve an old one
    ha.world().set("lock.front_door", "unlocked", json!({}));
    assert_eq!(a.observe(&dev("device:lock")).unwrap(), payload([("locked", false)]));
    assert_eq!(ha.world().rest_reads, 1);
    // Home Assistant comes back: the link bootstraps and serves the state again
    ha.world().ws_up = true;
    until("live again", || a.link().unwrap().live());
    assert!(a.link().unwrap().connections() >= 2);
    assert_eq!(a.observe(&dev("device:lock")).unwrap(), payload([("locked", false)]));
    assert_eq!(ha.world().rest_reads, 1, "back on the link");
}

#[test]
fn while_the_link_is_down_a_command_goes_by_rest_once() {
    let ha = FakeHa::start();
    ha.world().ws_up = false;
    let mut a = ha.adapter(Some(fast()));
    assert!(!a.link().unwrap().live());
    let state = a.execute(authorize(&dev("device:light"), "light.turn_on", Payload::new())).unwrap();
    assert_eq!(state, payload([("on", true)]));
    assert_eq!(ha.calls(), [("light.turn_on".to_string(), "light.living_room".to_string(), "rest")]);
    // the link itself answers a call it cannot make at once: never sent
    let link = Link::start(format!("ws://{}/api/websocket", ha.addr), TOKEN.into(), Default::default(), fast());
    assert!(matches!(link.call("light", "turn_on", json!({}), "light.living_room"), Err(CallError::NotSent(_))));
    assert_eq!(ha.calls().len(), 1);
}

#[test]
fn nothing_is_made_up_when_home_assistant_is_unreachable() {
    let ha = FakeHa::start();
    {
        let mut w = ha.world();
        w.ws_up = false;
        w.rest_up = false;
    }
    let mut a = ha.adapter(Some(fast()));
    assert!(matches!(a.observe(&dev("device:lock")), Err(AdapterError::Unavailable(_))));
    let err = a.execute(authorize(&dev("device:lock"), "lock.unlock", Payload::new())).unwrap_err();
    assert!(matches!(err, AdapterError::Unavailable(_)), "{err}");
    assert!(ha.calls().is_empty());
}

#[test]
fn a_wrong_token_is_never_accepted() {
    let ha = FakeHa::start();
    std::env::set_var("CHITALA_TEST_FAKE_HA_BAD_TOKEN", "not-the-token");
    let entities: BTreeMap<EntityId, String> = [(dev("device:lock"), "lock.front_door".to_string())].into();
    let mut a =
        HomeAssistantAdapter::with_link(&ha.url(), "CHITALA_TEST_FAKE_HA_BAD_TOKEN", entities, false, Some(fast()))
            .unwrap();
    until("the link gave up a connection", || a.link().unwrap().last_error().is_some());
    assert!(a.link().unwrap().last_error().unwrap().contains("rejected the access token"));
    assert!(!a.link().unwrap().live());
    let err = a.observe(&dev("device:lock")).unwrap_err();
    assert!(matches!(&err, AdapterError::Failed(m) if m.contains("access token")), "{err}");
}

#[test]
fn a_silent_connection_is_noticed_and_replaced() {
    let ha = FakeHa::start();
    let a = ha.live_adapter();
    ha.world().answer_pings = false;
    // no pong within the call timeout after a ping: the link drops it and reconnects
    until("a reconnect", || a.link().unwrap().connections() >= 2);
    ha.world().answer_pings = true;
    until("live", || a.link().unwrap().live());
}

#[test]
fn entities_must_be_of_their_kind() {
    let device = |caps: &[&str]| DeviceDescriptor {
        id: dev("device:x"),
        name: "x".into(),
        adapter: "home-assistant".into(),
        room: None,
        security_class: SecurityClass::Sc1,
        capabilities: caps.iter().map(|c| chitala_model::CapabilityId::parse(c).unwrap()).collect(),
    };
    let lock = device(&["device.read_state", "lock.lock", "lock.unlock"]);
    assert!(check_entity(&lock, "lock.front_door").is_ok());
    assert!(check_entity(&lock, "light.living_room").is_err(), "a lock is driven through a lock entity");
    assert!(check_entity(&lock, "lock.").is_err());
    assert!(check_entity(&device(&["switch.turn_on", "switch.turn_off"]), "switch.kettle").is_ok());
    assert!(check_entity(&device(&["switch.turn_on", "switch.turn_off"]), "light.x").is_err());
    assert!(check_entity(&device(&["climate.set_target_temperature"]), "climate.x").is_ok());
    assert!(check_entity(&device(&["device.read_state"]), "sensor.outside").is_err());
}

#[test]
fn discovery_proposes_the_entities_the_profile_drives() {
    let ha = FakeHa::start();
    ha.world().set("lock.back_door", "jammed", json!({"friendly_name": "Back door"}));
    ha.world().set("light.hall", "unavailable", json!({}));
    let a = ha.adapter(None);
    let found = a.discover().unwrap();
    let by: BTreeMap<&str, &Discovered> = found.iter().map(|d| (d.entity_id.as_str(), d)).collect();
    assert!(!by.contains_key("sensor.outside"), "only what the profile can drive");
    assert_eq!(by["lock.front_door"].class, "lock");
    assert_eq!(by["lock.front_door"].name.as_deref(), Some("Front door"));
    assert_eq!(by["lock.front_door"].state, Ok(payload([("locked", true)])));
    assert_eq!(by["switch.kettle"].class, "plug");
    assert_eq!(by["lock.back_door"].state, Ok(payload([("fault", "jammed")])));
    assert!(by["light.hall"].state.is_err(), "unavailable is not a state");
    assert!(ha.calls().is_empty(), "discovery never acts");
}
