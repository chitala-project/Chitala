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
        auth_min: Duration::from_millis(20),
        auth_max: Duration::from_millis(80),
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
    assert_eq!(a.observe(&dev("device:lock")).unwrap().state, payload([("locked", true)]));
    // someone switches the light on at the wall: pushed, no REST read
    ha.world().set("light.living_room", "on", json!({"brightness": 255}));
    until("the light is seen on", || a.link().unwrap().state("light.living_room").is_some_and(|s| s["state"] == "on"));
    let state = a.observe(&dev("device:light")).unwrap().state;
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
    assert_eq!(a.observe(&dev("device:lock")).unwrap().state, payload([("moving", true)]));
    // the bolt arrives
    ha.world().set("lock.front_door", "unlocked", json!({}));
    until("the lock is seen unlocked", || {
        a.link().unwrap().state("lock.front_door").is_some_and(|s| s["state"] == "unlocked")
    });
    assert_eq!(a.observe(&dev("device:lock")).unwrap().state, payload([("locked", false)]));
}

#[test]
fn jammed_unavailable_and_removed_are_never_states() {
    let ha = FakeHa::start();
    let mut a = ha.live_adapter();
    let seen =
        |a: &HomeAssistantAdapter, s: &str| a.link().unwrap().state("lock.front_door").is_some_and(|v| v["state"] == s);
    ha.world().set("lock.front_door", "jammed", json!({}));
    until("jammed", || seen(&a, "jammed"));
    assert_eq!(a.observe(&dev("device:lock")).unwrap().state, payload([("fault", "jammed")]));
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
    assert_eq!(a.observe(&dev("device:plug")).unwrap().state, payload([("on", true)]));
    // a duplicate of the current one: nothing changes
    ha.world().broadcast(event(&current));
    marker(&ha, &a, "off");
    assert_eq!(a.observe(&dev("device:plug")).unwrap().state, payload([("on", true)]));
    // a newer one is taken
    ha.world().set("switch.kettle", "off", json!({}));
    until("off", || a.link().unwrap().state("switch.kettle").is_some_and(|s| s["state"] == "off"));
    assert_eq!(a.observe(&dev("device:plug")).unwrap().state, payload([("on", false)]));
}

#[test]
fn a_command_lost_after_sending_is_indeterminate_and_never_sent_again() {
    let ha = FakeHa::start();
    ha.behave("lock.front_door", Behaviour::LoseAfterSend);
    ha.world().set("lock.front_door", "unlocked", json!({}));
    let mut a = ha.live_adapter();
    let err = a.execute(authorize(&dev("device:lock"), "lock.lock", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Indeterminate(m) if m.contains("may have executed")), "{err}");
    // the door did lock; the adapter neither resent it nor guessed
    assert_eq!(ha.calls().len(), 1, "never sent twice: {:?}", ha.calls());
    assert_eq!(ha.world().states["lock.front_door"]["state"], "locked");
    // once the link is back, observing tells the truth: Chitala's outcome
    // verification finds the command applied (spec 22)
    until("reconnected", || a.link().unwrap().connections() >= 2 && a.link().unwrap().live());
    assert_eq!(a.observe(&dev("device:lock")).unwrap().state, payload([("locked", true)]));
    assert_eq!(ha.calls().len(), 1);
}

#[test]
fn no_result_in_time_is_indeterminate_and_never_sent_again() {
    let ha = FakeHa::start();
    ha.behave("switch.kettle", Behaviour::Silent);
    let mut a = ha.live_adapter();
    let err = a.execute(authorize(&dev("device:plug"), "switch.turn_on", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Indeterminate(m) if m.contains("may have executed")), "{err}");
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
    assert!(matches!(&err, AdapterError::Indeterminate(m) if m.contains("may have executed")), "{err}");
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
    assert_eq!(a.observe(&dev("device:lock")).unwrap().state, payload([("locked", false)]));
    assert_eq!(ha.world().rest_reads, 1);
    // Home Assistant comes back: the link bootstraps and serves the state again
    ha.world().ws_up = true;
    until("live again", || a.link().unwrap().live());
    assert!(a.link().unwrap().connections() >= 2);
    assert_eq!(a.observe(&dev("device:lock")).unwrap().state, payload([("locked", false)]));
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
fn a_dead_home_assistant_is_not_reached_and_nothing_is_made_up() {
    let ha = FakeHa::start();
    let mut a = ha.live_adapter();
    ha.kill();
    until("the link noticed", || !a.link().unwrap().live());
    // nothing could be delivered: the command certainly did not execute
    let err = a.execute(authorize(&dev("device:lock"), "lock.unlock", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Unavailable(m) if m.contains("unreachable")), "{err}");
    assert!(matches!(a.observe(&dev("device:lock")), Err(AdapterError::Unavailable(_))));
    assert!(ha.calls().is_empty());
}

#[test]
fn a_broken_home_assistant_leaves_a_command_s_fate_unknown_and_nothing_is_made_up() {
    let ha = FakeHa::start();
    {
        // it takes connections and drops them: a request may or may not have been read
        let mut w = ha.world();
        w.ws_up = false;
        w.rest_up = false;
    }
    let mut a = ha.adapter(Some(fast()));
    assert!(matches!(a.observe(&dev("device:lock")), Err(AdapterError::Unavailable(_))));
    let err = a.execute(authorize(&dev("device:lock"), "lock.unlock", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Indeterminate(m) if m.contains("may have executed")), "{err}");
    assert!(ha.calls().is_empty());
}

#[test]
fn a_call_that_ran_but_cannot_be_observed_is_indeterminate() {
    let ha = FakeHa::start();
    ha.behave("light.living_room", Behaviour::DropsOff);
    let mut a = ha.live_adapter();
    let err = a.execute(authorize(&dev("device:light"), "light.turn_on", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Indeterminate(m) if m.contains("cannot be observed")), "{err}");
    assert_eq!(ha.calls().len(), 1);
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

/// An adapter on the fake with a device mapped to an entity Home Assistant
/// does not have (a typo in the config), and the living room light.
fn ghost_adapter(ha: &FakeHa, timing: Option<Timing>) -> HomeAssistantAdapter {
    let entities: BTreeMap<EntityId, String> =
        [(dev("device:ghost"), "light.ghost".to_string()), (dev("device:light"), "light.living_room".to_string())]
            .into();
    HomeAssistantAdapter::with_link(&ha.url(), token_env(), entities, false, timing).unwrap()
}

/// v0.3 step ③A, finding F2: Home Assistant answers success to a call on an
/// entity it does not have, and nothing runs. While the link is live and its
/// inventory (`get_states` on this very connection) is good, a command to an
/// entity that is not in it is refused before anything is sent: certainly
/// not executed. Reading it costs no REST request either. An entity that
/// appears is there at once; one Home Assistant removes is absent again.
#[test]
fn a_command_to_an_entity_home_assistant_does_not_have_is_not_sent() {
    let ha = FakeHa::start();
    let mut a = ghost_adapter(&ha, Some(fast()));
    until("live", || a.link().unwrap().live());
    let err = a.execute(authorize(&dev("device:ghost"), "light.turn_on", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Failed(m) if m.contains("has no entity light.ghost")), "{err}");
    assert!(ha.calls().is_empty(), "nothing was sent");
    let reads = ha.world().rest_reads;
    assert!(matches!(a.observe(&dev("device:ghost")), Err(AdapterError::Unavailable(_))));
    assert_eq!(ha.world().rest_reads, reads, "no REST read for an entity the live inventory does not have");

    // it appears: there at once
    ha.world().set("light.ghost", "off", json!({"supported_color_modes": ["onoff"]}));
    until("the link heard of it", || a.link().unwrap().state("light.ghost").is_some());
    assert!(a.execute(authorize(&dev("device:ghost"), "light.turn_on", Payload::new())).is_ok());
    assert_eq!(ha.calls().len(), 1);

    // Home Assistant removes it: absent again
    ha.world().remove("light.ghost");
    until("the link heard of the removal", || {
        a.link().unwrap().state("light.ghost").is_some_and(|s| s["state"] == "unavailable")
    });
    let err = a.execute(authorize(&dev("device:ghost"), "light.turn_on", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Failed(m) if m.contains("has no entity")), "{err}");
    assert_eq!(ha.calls().len(), 1, "nothing more was sent");

    // and back again
    ha.world().set("light.ghost", "off", json!({"supported_color_modes": ["onoff"]}));
    until("back", || a.link().unwrap().state("light.ghost").is_some_and(|s| s["state"] == "off"));
    assert!(a.execute(authorize(&dev("device:ghost"), "light.turn_on", Payload::new())).is_ok());
}

/// F2 across a reconnect: an entity that disappeared while the link was down
/// (no event told of it) is absent by the new connection's inventory; what
/// the old connection knew does not count.
#[test]
fn absence_follows_the_inventory_of_the_current_connection() {
    let ha = FakeHa::start();
    ha.world().set("light.ghost", "off", json!({"supported_color_modes": ["onoff"]}));
    let mut a = ghost_adapter(&ha, Some(fast()));
    until("live", || a.link().unwrap().live() && a.link().unwrap().state("light.ghost").is_some());
    let connections = a.link().unwrap().connections();
    {
        let mut w = ha.world();
        w.states.remove("light.ghost"); // gone without a word
        w.restarts += 1; // and the connection drops
    }
    until("reconnected", || a.link().unwrap().live() && a.link().unwrap().connections() > connections);
    let err = a.execute(authorize(&dev("device:ghost"), "light.turn_on", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Failed(m) if m.contains("has no entity")), "{err}");
    assert!(ha.calls().is_empty());
}

/// F2's limit: absence is never inferred without a live inventory Home
/// Assistant gave on this connection. Without a link (REST only), or when
/// `get_states` failed, the command goes, and outcome verification decides.
#[test]
fn absence_is_never_inferred_without_a_live_inventory() {
    let ha = FakeHa::start();
    let mut a = ghost_adapter(&ha, None);
    let r = a.execute(authorize(&dev("device:ghost"), "light.turn_on", Payload::new()));
    assert!(matches!(&r, Err(AdapterError::Indeterminate(_))), "sent; the entity cannot be observed: {r:?}");
    assert_eq!(ha.calls(), [("light.turn_on".to_string(), "light.ghost".to_string(), "rest")]);
    drop(a);

    ha.world().fail_get_states = true;
    let mut a = ghost_adapter(&ha, Some(fast()));
    until("live, without an inventory", || a.link().unwrap().live());
    let r = a.execute(authorize(&dev("device:ghost"), "light.turn_on", Payload::new()));
    assert!(matches!(&r, Err(AdapterError::Indeterminate(_))), "sent over the link: {r:?}");
    assert_eq!(ha.calls().len(), 2);
    assert_eq!(ha.calls()[1].2, "ws");
    drop(a);

    // a link that had a good inventory and is down now knows nothing
    ha.world().fail_get_states = false;
    let mut a = ghost_adapter(&ha, Some(fast()));
    until("live", || a.link().unwrap().live());
    {
        let mut w = ha.world();
        w.ws_up = false;
        w.restarts += 1;
    }
    until("down", || !a.link().unwrap().live());
    let r = a.execute(authorize(&dev("device:ghost"), "light.turn_on", Payload::new()));
    assert!(matches!(&r, Err(AdapterError::Indeterminate(_))), "sent by REST: {r:?}");
    assert_eq!(ha.calls().len(), 3);
    assert_eq!(ha.calls()[2].2, "rest");
}

/// v0.3 step ③A, finding F4 (against a real Home Assistant): after its token
/// was revoked, Chitala presented it about six times a second, once per
/// observation. Home Assistant counts each as a failed login and, with
/// `login_attempts_threshold` set, bans the address for good. After a
/// rejection the token is not presented again for a while, by REST or by the
/// link, and nothing is sent in between.
#[test]
fn a_rejected_token_is_not_presented_again_and_again() {
    let ha = FakeHa::start();
    ha.world().token = "a-token-issued-later".into();
    let timing = Timing { auth_min: Duration::from_secs(2), auth_max: Duration::from_secs(4), ..fast() };
    let mut a = ha.adapter(Some(timing));
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(300) {
        let err = a.observe(&dev("device:lock")).unwrap_err();
        assert!(matches!(&err, AdapterError::Failed(m) if m.contains("access token")), "{err}");
        std::thread::sleep(Duration::from_millis(5));
    }
    let rejected = ha.world().rejected_logins;
    assert!((1..=2).contains(&rejected), "the token was presented {rejected} times in 300 ms");
    // a command meanwhile is not sent: certainly not executed
    let err = a.execute(authorize(&dev("device:lock"), "lock.unlock", Payload::new())).unwrap_err();
    assert!(matches!(&err, AdapterError::Failed(m) if m.contains("nothing was sent")), "{err}");
    assert!(ha.calls().is_empty());
    assert_eq!(ha.world().rejected_logins, rejected);
    drop(a);

    // REST only: the same
    let before = ha.world().rejected_logins;
    let mut a = ha.adapter(None);
    for _ in 0..50 {
        assert!(a.observe(&dev("device:lock")).is_err());
    }
    assert_eq!(ha.world().rejected_logins - before, 1, "REST presented a rejected token again");
}

/// F4 for the link alone: with no request coming in, the link does not log
/// in again and again with a rejected token.
#[test]
fn the_link_alone_does_not_present_a_rejected_token_again() {
    let ha = FakeHa::start();
    ha.world().token = "a-token-issued-later".into();
    let timing = Timing { auth_min: Duration::from_secs(2), auth_max: Duration::from_secs(4), ..fast() };
    let a = ha.adapter(Some(timing));
    until("a rejection", || ha.world().rejected_logins >= 1);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(ha.world().rejected_logins, 1, "the link logged in again with a rejected token");
    assert!(!a.link().unwrap().live());
}

/// The gate's schedule: closed from `auth_min`, doubling up to `auth_max`; a
/// rejection racing one that already closed it does not double it again; an
/// accepted login opens it and starts over.
#[test]
fn the_auth_gate_waits_longer_after_each_rejection() {
    let ms = Duration::from_millis;
    let gate = link::AuthGate::new(&Timing { auth_min: ms(200), auth_max: ms(500), ..fast() });
    let closed_for = |g: &link::AuthGate| g.check().err().unwrap_or_default();
    assert!(gate.check().is_ok());
    gate.rejected();
    let first = closed_for(&gate);
    assert!(first > ms(100) && first <= ms(200), "{first:?}");
    gate.rejected(); // raced: still closed, not doubled
    assert!(closed_for(&gate) <= ms(200));
    std::thread::sleep(ms(210));
    assert!(gate.check().is_ok(), "the wait ends");
    gate.rejected();
    assert!(closed_for(&gate) > ms(200), "doubled");
    std::thread::sleep(ms(410));
    gate.rejected();
    let capped = closed_for(&gate);
    assert!(capped <= ms(500) && capped > ms(400), "capped at auth_max: {capped:?}");
    gate.accepted();
    assert!(gate.check().is_ok());
    gate.rejected();
    assert!(closed_for(&gate) <= ms(200), "an accepted login starts over");
}

/// F4, the other side: the wait ends. A token rejected for a moment (say,
/// while Home Assistant starts) is presented again later and works.
#[test]
fn a_token_rejected_for_a_while_is_tried_again_and_works() {
    let ha = FakeHa::start();
    ha.world().token = "not-yet".into();
    let timing = Timing { auth_min: Duration::from_millis(100), auth_max: Duration::from_millis(200), ..fast() };
    let mut a = ha.adapter(Some(timing));
    until("a rejection", || ha.world().rejected_logins >= 1);
    ha.world().token = TOKEN.into();
    until("live again", || a.link().unwrap().live());
    assert_eq!(a.observe(&dev("device:lock")).unwrap().state, payload([("locked", true)]));
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

/// v0.3 step ③A, finding F1: discovery proposed `light.set_brightness` for
/// every light. A light whose color modes are only `onoff`, or that declares
/// none, is not proposed it: nothing is guessed (Home Assistant's own rule,
/// `brightness_supported`).
#[test]
fn discovery_proposes_brightness_only_for_lights_that_have_it() {
    let ha = FakeHa::start();
    ha.world().set("light.lamp", "on", json!({"supported_color_modes": ["onoff"], "color_mode": "onoff"}));
    ha.world().set("light.dimmer", "on", json!({"supported_color_modes": ["brightness"], "brightness": 128}));
    ha.world().set("light.bulb", "on", json!({"supported_color_modes": ["color_temp", "hs"], "brightness": 255}));
    ha.world().set("light.old", "on", json!({}));
    let a = ha.adapter(None);
    let found = a.discover().unwrap();
    let dims = |e: &str| {
        found
            .iter()
            .find(|d| d.entity_id == e)
            .unwrap()
            .capabilities
            .iter()
            .any(|c| c.as_str() == "light.set_brightness")
    };
    assert!(!dims("light.lamp"), "an on/off lamp cannot dim");
    assert!(dims("light.dimmer"));
    assert!(dims("light.bulb"));
    assert!(!dims("light.old"), "no color modes declared: not guessed");
    let lamp = found.iter().find(|d| d.entity_id == "light.lamp").unwrap();
    assert!(lamp.capabilities.iter().any(|c| c.as_str() == "light.turn_on"), "it still turns on");
}

/// v0.3 step ③A, finding F9: the adapter says how old a state is. Pushed on
/// the link: since it was heard. From the link's bootstrap: nobody can tell.
/// Over REST: by Home Assistant's own clock.
#[test]
fn every_observation_says_how_old_its_state_is() {
    let ha = FakeHa::start();
    let mut a = ha.live_adapter();
    // from the bootstrap: unknown
    assert_eq!(a.observe(&dev("device:lock")).unwrap().age_ms, None, "bootstrapped: age unknown");
    // pushed: since it was heard
    ha.world().set("lock.front_door", "unlocked", json!({}));
    until("pushed", || a.link().unwrap().state("lock.front_door").is_some_and(|s| s["state"] == "unlocked"));
    let o = a.observe(&dev("device:lock")).unwrap();
    assert!(o.age_ms.is_some_and(|age| age < 1_000), "{o:?}");
    std::thread::sleep(Duration::from_millis(120));
    assert!(a.observe(&dev("device:lock")).unwrap().age_ms.is_some_and(|age| age >= 120), "it ages");
    drop(a);

    // REST: Home Assistant's clock at the answer minus the last write, rounded up
    let mut a = ha.adapter(None);
    let o = a.observe(&dev("device:lock")).unwrap();
    assert!(o.age_ms.is_some_and(|age| (999..3_000).contains(&age)), "{o:?}");
    // a state written long ago is old
    ha.world().states.get_mut("lock.front_door").unwrap()["last_reported"] = json!("2026-01-01T00:00:00.000000+00:00");
    ha.world().states.get_mut("lock.front_door").unwrap()["last_updated"] = json!("2026-01-01T00:00:00.000000+00:00");
    assert!(a.observe(&dev("device:lock")).unwrap().age_ms.is_some_and(|age| age > 86_400_000));
}

#[test]
fn home_assistant_and_http_times_are_read_exactly() {
    assert_eq!(ha_time_ms("2026-10-05T12:00:00.000000+00:00"), Some(1_791_201_600_000));
    assert_eq!(ha_time_ms("2026-10-05T12:00:00.123456+00:00"), Some(1_791_201_600_123));
    assert_eq!(ha_time_ms("2026-10-05T12:00:00+00:00"), Some(1_791_201_600_000));
    assert_eq!(ha_time_ms("2024-02-29T23:59:59.5Z"), Some(1_709_251_199_500));
    assert_eq!(http_date_ms("Mon, 05 Oct 2026 12:00:00 GMT"), Some(1_791_201_600_000));
    assert_eq!(http_date_ms("Thu, 29 Feb 2024 23:59:59 GMT"), Some(1_709_251_199_000));
    for bad in ["2026-10-05T12:00:00+02:00", "2026-13-05T12:00:00+00:00", "2026-10-05T25:00:00Z", "yesterday", ""] {
        assert_eq!(ha_time_ms(bad), None, "{bad}");
    }
    for bad in ["Mon, 05 Oct 2026 12:00:00 CET", "Mon, 05 Foo 2026 12:00:00 GMT", "05 Oct 2026"] {
        assert_eq!(http_date_ms(bad), None, "{bad}");
    }
    // a REST state: the latest write, by Home Assistant's clock, plus the Date header's rounding
    let state = json!({"last_updated": "2026-10-05T12:00:00.000000+00:00", "last_reported": "2026-10-05T12:00:05.000000+00:00"});
    assert_eq!(rest_age_ms(&state, Some(1_791_201_610_000)), Some(5_999));
    assert_eq!(rest_age_ms(&state, None), None);
    assert_eq!(rest_age_ms(&json!({}), Some(1_791_201_610_000)), None);
}

/// Wait until the link has read the entity registry's entry of `entity`.
fn registry_read(a: &HomeAssistantAdapter, entity: &str) {
    until("the registry is read", || a.link().unwrap().registered(entity).is_some());
}

/// Wait until the link holds `state` for `entity`, pushed.
fn pushed(a: &HomeAssistantAdapter, entity: &str, state: &str) {
    until("pushed", || a.link().unwrap().state(entity).is_some_and(|s| s["state"] == state));
}

fn confirmed(o: &crate::Observed) -> Option<u64> {
    match o.provenance {
        crate::Provenance::ConfirmedCurrent { age_ms } => Some(age_ms),
        crate::Provenance::Uncertain => None,
    }
}

/// v0.3 step ③A, finding F9b: Home Assistant writes a Matter lock's cached
/// value again with a new timestamp when the lock does not answer. So a Matter
/// device's state is confirmed current only when the device answered an
/// exchange (`matter/interview_node`) begun after Home Assistant reported the
/// state — and only an observation for evidence asks it.
#[test]
fn a_matter_device_s_state_is_confirmed_only_by_an_answer_after_it() {
    let ha = FakeHa::start();
    ha.world().matter("lock.front_door", "node-lock", true);
    let mut a = ha.live_adapter();
    registry_read(&a, "lock.front_door");
    let lock = dev("device:lock");
    ha.world().set("lock.front_door", "unlocked", json!({}));
    pushed(&a, "lock.front_door", "unlocked");

    // a plain observation asks no device: not confirmed
    let o = a.observe(&lock).unwrap();
    assert_eq!(confirmed(&o), None, "{o:?}");
    assert!(ha.world().interviews.is_empty(), "a plain observation asks nobody");

    // for evidence: the device answers, after the state: confirmed, and no
    // older than the state itself
    let o = a.observe_evidence(&lock).unwrap();
    assert_eq!(ha.world().interviews, ["node-lock"]);
    let (age, since) = (o.age_ms.unwrap(), confirmed(&o).expect("confirmed"));
    assert!(since <= age, "confirmed after the state was reported: {o:?}");
    // the answer stands for that state: nobody is asked again
    assert!(confirmed(&a.observe_evidence(&lock).unwrap()).is_some());
    assert!(confirmed(&a.observe(&lock).unwrap()).is_some(), "a plain observation reports what is known");
    assert_eq!(ha.world().interviews.len(), 1);

    // a newer state needs a newer answer
    ha.world().set("lock.front_door", "locked", json!({}));
    pushed(&a, "lock.front_door", "locked");
    assert_eq!(confirmed(&a.observe(&lock).unwrap()), None, "the answer came before this state");
    assert!(confirmed(&a.observe_evidence(&lock).unwrap()).is_some());
    assert_eq!(ha.world().interviews.len(), 2);

    // the lock dies, and Home Assistant writes its cached value again, with a
    // new timestamp: the lock does not answer, so nothing confirms it
    ha.world().matter_nodes.insert("node-lock".into(), false);
    ha.world().set("lock.front_door", "unlocked", json!({}));
    pushed(&a, "lock.front_door", "unlocked");
    let o = a.observe_evidence(&lock).unwrap();
    assert_eq!(o.state, payload([("locked", false)]));
    assert!(o.age_ms.is_some(), "the timestamp is fresh");
    assert_eq!(confirmed(&o), None, "but nothing ties it to the lock: {o:?}");
    assert_eq!(ha.world().interviews.len(), 3);
    // a device that did not answer is not asked again at once
    assert_eq!(confirmed(&a.observe_evidence(&lock).unwrap()), None);
    assert_eq!(ha.world().interviews.len(), 3, "not asked again within {REACH_RETRY:?}");
}

/// F9b: an entity of another integration (here: one outside the entity
/// registry, as Home Assistant's demo locks are) keeps Home Assistant's word,
/// as old as its state. An entity whose integration is not known has nothing
/// to vouch for it: a Matter device's state read over REST, or any state when
/// the registry could not be read.
#[test]
fn only_what_can_be_tied_to_its_device_is_confirmed() {
    let ha = FakeHa::start();
    ha.world().matter("light.living_room", "node-light", true);
    let mut a = ha.live_adapter();
    registry_read(&a, "lock.front_door");
    ha.world().set("lock.front_door", "unlocked", json!({}));
    pushed(&a, "lock.front_door", "unlocked");
    let o = a.observe(&dev("device:lock")).unwrap();
    assert_eq!(confirmed(&o), o.age_ms, "Home Assistant's word, as old as the state: {o:?}");
    assert!(o.age_ms.is_some());
    drop(a);

    // REST only: nobody knows which integration provides an entity
    let mut rest = ha.adapter(None);
    let o = rest.observe_evidence(&dev("device:lock")).unwrap();
    assert!(o.age_ms.is_some());
    assert_eq!(confirmed(&o), None, "{o:?}");
    assert_eq!(confirmed(&rest.observe_evidence(&dev("device:light")).unwrap()), None);
    assert!(ha.world().interviews.is_empty(), "REST cannot ask a Matter device");

    // the registry cannot be read: nothing is confirmed
    let ha = FakeHa::start();
    ha.world().fail_registry = true;
    let mut a = ha.live_adapter();
    ha.world().set("lock.front_door", "unlocked", json!({}));
    pushed(&a, "lock.front_door", "unlocked");
    let o = a.observe_evidence(&dev("device:lock")).unwrap();
    assert!(o.age_ms.is_some());
    assert_eq!(confirmed(&o), None, "{o:?}");
    assert_eq!(a.link().unwrap().registered("lock.front_door"), None);
}

/// F9b: a Matter device is not waited for longer than REACH_WAIT, whether it
/// answers slowly or never; a slow answer (within the link's call timeout)
/// counts when it comes, for the states reported before the exchange began.
#[test]
fn a_device_is_not_waited_for_and_a_slow_answer_counts_when_it_comes() {
    let ha = FakeHa::start();
    ha.world().matter("lock.front_door", "node-lock", true);
    ha.world().answer_after = REACH_WAIT + Duration::from_millis(300);
    let mut a = ha.adapter(Some(Timing { call: Duration::from_secs(3), ..fast() }));
    until("the link is live", || a.link().unwrap().live());
    registry_read(&a, "lock.front_door");
    ha.world().set("lock.front_door", "unlocked", json!({}));
    pushed(&a, "lock.front_door", "unlocked");
    let lock = dev("device:lock");
    let began = Instant::now();
    assert_eq!(confirmed(&a.observe_evidence(&lock).unwrap()), None, "not answered yet");
    assert!(began.elapsed() < REACH_WAIT + Duration::from_millis(250), "waited {:?}", began.elapsed());
    std::thread::sleep(Duration::from_millis(500));
    assert!(confirmed(&a.observe_evidence(&lock).unwrap()).is_some(), "the answer came");
    assert_eq!(ha.world().interviews.len(), 1, "asked once");

    // one that never answers: the same bound
    ha.world().matter_nodes.insert("node-lock".into(), false);
    ha.world().set("lock.front_door", "locked", json!({}));
    pushed(&a, "lock.front_door", "locked");
    let began = Instant::now();
    assert_eq!(confirmed(&a.observe_evidence(&lock).unwrap()), None);
    assert!(began.elapsed() < REACH_WAIT + Duration::from_millis(250), "waited {:?}", began.elapsed());
    // an entity outside the registry is no Matter device's: nobody to ask
    assert_eq!(a.link().unwrap().registered("light.living_room"), Some(None));
}
