//! Outcome verification and recovery end to end (v0.2 step 9, spec 22): did the
//! world end up as the action promised, according to the resource's witness;
//! and when it did not, the resource takes nothing but its safe state, which
//! the node runs once by itself, until a person releases it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::{AdapterError, Simulation};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_bus::Filter;
use chitala_identity::{test_seed, Keypair};
use chitala_model::{payload, CapabilityId, DenyCode, EntityId, EventKind, ExecCode, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::executor::{in_process, Routed};
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response};
use chitala_resource::{Resource, ResourceId};
use serde_json::{json, Value};

const T0: u64 = 1_790_000_000_000;
const LIGHT: &str = "device:living-room-light";
const FAN: &str = "device:fan-plug";
const THERMO: &str = "device:thermostat";
const DOOR: &str = "device:front-door";
const DOOR_R: &str = "resource:front-door";
const SET: &str = "climate.set_target_temperature";

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
fn rid(s: &str) -> ResourceId {
    ResourceId::parse(s).unwrap()
}
fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

const PEOPLE: [(&str, &[&str], &[&str]); 3] =
    [("person:alice", &["owner"], &[]), ("person:bob", &["adult"], &[]), ("ai:assistant", &[], &["person:alice"])];

struct Home {
    node: Node,
    clock: Arc<AtomicU64>,
    keys: HashMap<String, Keypair>,
}

fn home() -> Home {
    home_with(|_| {}, false)
}

/// The sample home with its resources changed by `mutate`. With `split`, the
/// fan plug is served by an adapter host instance of its own.
fn home_with(mutate: impl FnOnce(&mut Vec<Resource>), split: bool) -> Home {
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let node_clock: chitala_node::Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let mut keys = HashMap::new();
    let mut principals = Vec::new();
    let mut agency = Vec::new();
    for (who, roles, serves) in PEOPLE {
        let k = Keypair::from_seed(&test_seed(who));
        principals.push((id(who), k.public_key(), roles.iter().map(|r| r.to_string()).collect()));
        if !serves.is_empty() {
            agency.push((id(who), serves.iter().map(|p| id(p)).collect()));
        }
        keys.insert(who.to_string(), k);
    }
    let boundary = TrustedExecutionBoundary::new(entropy());
    let (mut main, mut own) = (MockAdapter::new(), MockAdapter::new());
    for d in sample_devices() {
        let kind = VirtualKind::from_capabilities(&d.capabilities).unwrap();
        if split && d.id == id(FAN) {
            own.add(d.id.clone(), kind);
        } else {
            main.add(d.id.clone(), kind);
        }
    }
    let executor = if split {
        let mut routed = Routed::new();
        let others: Vec<EntityId> = sample_devices().into_iter().map(|d| d.id).filter(|d| d != &id(FAN)).collect();
        routed.add(in_process(&boundary, vec![Box::new(main)], node_clock.clone()), &others);
        routed.add(in_process(&boundary, vec![Box::new(own)], node_clock.clone()), &[id(FAN)]);
        Arc::new(routed) as Arc<dyn chitala_node::executor::Executor>
    } else {
        in_process(&boundary, vec![Box::new(main)], node_clock.clone())
    };
    let mut resources = sample_resources();
    mutate(&mut resources);
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: Keypair::from_seed(&test_seed("service:node")),
        authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
        principals,
        agency,
        devices: sample_devices(),
        resources,
        safety: Default::default(),
        executor,
        policy: chitala_node::PolicySource::Default,
        audit: AuditLog::in_memory(None),
        state: chitala_node::DomainState::default(),
        state_file: None,
        containment: ContainmentConfig::default(),
        monitor: MonitorConfig::default(),
        entropy: entropy(),
        clock: node_clock,
        clock_watch: None,
        boundary,
    })
    .unwrap();
    Home { node, clock, keys }
}

/// Make `device` the witness of `resource` (its state reference).
fn witnessed_by(rs: &mut [Resource], resource: &str, device: &str) {
    rs.iter_mut().find(|r| r.id.local() == resource).unwrap().state.as_mut().unwrap().device = id(device);
}

impl Home {
    fn advance(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    /// Time passes and the node does what its server loop does every tick.
    fn later(&mut self, ms: u64) {
        self.advance(ms);
        self.node.tick();
    }

    fn req(&mut self, who: &str, target: &str, c: &str, pl: Payload) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now());
        self.advance(1);
        self.node.handle(&bytes)
    }

    fn release(&mut self, who: &str, resource: &str) -> Response {
        self.req(who, "domain:home", "domain.safety_release", payload([("resource", resource)]))
    }

    fn simulate(&mut self, device: &str, change: Simulation) {
        self.node.simulate(&id(device), change).unwrap();
    }

    fn reported(&self, device: &str, field: &str) -> Option<ParamValue> {
        self.node.twins().get(&id(device)).and_then(|t| t.reported.get(field).cloned())
    }

    fn records(&self, kind: &str) -> Vec<Value> {
        self.node
            .audit()
            .lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| v["kind"] == kind)
            .collect()
    }

    fn recoveries(&self) -> Vec<Value> {
        self.records("decision").into_iter().filter(|d| d["safe_state"] == true).collect()
    }

    fn in_recovery(&self, resource: &str) -> bool {
        self.node.domain_state().recovery.contains_key(&rid(resource))
    }
}

fn status(r: &Response) -> &str {
    r.outcome.as_ref().and_then(|o| o["status"].as_str()).unwrap_or("none")
}

fn refused_by(r: &Response, rule: &str) -> bool {
    r.code == Some(DenyCode::Safety) && r.reason.as_deref().unwrap_or_default().contains(rule)
}

#[test]
fn an_action_its_witness_confirms_is_verified_at_once() {
    let mut h = home();
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    assert!(r.is_ok(), "{}", r.summary());
    let o = r.outcome.as_ref().unwrap();
    assert_eq!(o["status"], "verified");
    assert_eq!(o["expected"], json!({"on": true}));
    assert_eq!(o["observed"], json!({"on": true}));
    assert_eq!(o["witness"], LIGHT);
    assert_eq!(o["independent"], false, "the light vouches for itself");
    let exec = h.records("execution").pop().unwrap();
    assert_eq!(exec["verification"]["status"], "verified");
    assert_eq!(exec["outcome"], "ok", "the execution record keeps its own outcome field");
    assert!(h.node.pending_outcomes().is_empty());
    assert!(h.records("outcome").is_empty(), "nothing left to settle");
}

#[test]
fn a_slow_device_is_pending_until_its_witness_reports_the_effect() {
    let mut h = home();
    let events = h.node.subscribe(Filter::Kinds(vec![EventKind::Outcome]));
    h.simulate(THERMO, Simulation::Lag(2));
    let r = h.req("person:alice", THERMO, SET, payload([("celsius", 21i64)]));
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(status(&r), "pending");
    let o = r.outcome.as_ref().unwrap();
    assert_eq!(o["expected"], json!({"target_celsius": 21}));
    assert_eq!(o["observed"], json!({"target_celsius": 24}), "observed right after: not there yet");
    assert!(o["deadline_ms"].as_u64().unwrap() > h.node.now());
    assert_eq!(h.node.pending_outcomes().len(), 1);

    // the next tick observes the witness again: the target has been set
    h.later(1_000);
    assert!(h.node.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!(settled["status"], "verified");
    assert_eq!(settled["execution_seq"].as_u64(), r.audit_seq);
    let e = events.drain();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].data.get("status"), Some(&ParamValue::Text("verified".into())));
    assert!(!h.in_recovery("resource:thermostat"));
}

#[test]
fn a_stuck_lock_puts_the_door_in_recovery_and_the_node_locks_it_once() {
    let mut h = home();
    assert!(h.req("person:alice", DOOR, "lock.unlock", Payload::new()).is_ok());
    h.simulate(DOOR, Simulation::Stuck(true));

    // the lock claims it locked; observed right after, it did not
    let r = h.req("person:alice", DOOR, "lock.lock", Payload::new());
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(status(&r), "pending");
    assert_eq!(r.outcome.as_ref().unwrap()["observed"], json!({"locked": false}));
    h.later(1_000);
    assert_eq!(h.node.pending_outcomes().len(), 1, "not yet: a bolt may take its time");

    // past the registry's 5 s: diverged; the door goes into recovery and the
    // node runs its safe state, once
    h.later(5_000);
    let settled = h.records("outcome");
    assert_eq!(settled[0]["status"], "diverged");
    assert_eq!(settled[0]["observed"], json!({"locked": false}));
    assert!(h.in_recovery(DOOR_R));
    let rec = h.recoveries();
    assert_eq!(rec.len(), 1);
    assert_eq!((rec[0]["decision"].as_str(), rec[0]["capability"].as_str()), (Some("allow"), Some("lock.lock")));
    assert_eq!(rec[0]["actor"], "service:node");
    assert_eq!(rec[0]["trigger"], settled[0]["seq"]);
    assert_eq!(rec[0]["context"]["kind"], "recovery");
    let safety = h.records("safety").pop().unwrap();
    assert_eq!((safety["op"].as_str(), safety["by"].as_str()), (Some("recovery"), Some("service:node")));

    // the bolt is still jammed: the safe state diverges too, and nothing more is tried
    h.later(6_000);
    let settled = h.records("outcome");
    assert_eq!(settled.len(), 2);
    assert_eq!((settled[1]["status"].as_str(), settled[1]["safe_state"].as_bool()), (Some("diverged"), Some(true)));
    h.later(10_000);
    assert_eq!(h.recoveries().len(), 1, "a safe state that fails never leads to another");
    assert!(h.node.pending_outcomes().is_empty());

    // in recovery, nothing but the safe state runs, whoever asks
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(refused_by(&r, "SAFE-8-RECOVERY"), "{}", r.summary());
    // and only a person who may release it ends it: not an AI, not any adult
    assert!(!h.release("ai:assistant", DOOR_R).is_ok());
    assert!(!h.release("person:bob", DOOR_R).is_ok());
    assert!(h.in_recovery(DOOR_R));

    // the bolt is freed: the owner locks the door, which the recovery allows
    h.simulate(DOOR, Simulation::Stuck(false));
    let r = h.req("person:alice", DOOR, "lock.lock", Payload::new());
    assert_eq!(status(&r), "verified", "{}", r.summary());
    assert!(h.in_recovery(DOOR_R), "a person ends it, not a good outcome");
    let r = h.release("person:alice", DOOR_R);
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(r.result.as_ref().unwrap()["was_recovering"], true);
    assert!(!h.in_recovery(DOOR_R));
    h.later(61_000); // out of SAFE-6's window for high-risk actions
    assert!(h.req("person:alice", DOOR, "lock.unlock", Payload::new()).is_ok());
}

#[test]
fn the_safe_state_brings_the_door_back_when_the_lock_works_again() {
    let mut h = home();
    assert!(h.req("person:alice", DOOR, "lock.unlock", Payload::new()).is_ok());
    h.simulate(DOOR, Simulation::Stuck(true));
    let r = h.req("person:alice", DOOR, "lock.lock", Payload::new());
    assert_eq!(status(&r), "pending");
    // the jam clears by itself, but the earlier command was lost
    h.simulate(DOOR, Simulation::Stuck(false));
    h.later(6_000);
    assert_eq!(h.records("outcome")[0]["status"], "diverged");
    assert_eq!(h.recoveries().len(), 1);
    // the node's own lock.lock worked, and its witness confirms it at once
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
    let exec = h.records("execution").pop().unwrap();
    assert_eq!(exec["decision_seq"], h.recoveries()[0]["seq"]);
    assert_eq!(exec["verification"]["status"], "verified");
    assert!(h.in_recovery(DOOR_R), "the door is safe again, and a person still has to look");
}

#[test]
fn an_unconfirmed_low_risk_outcome_is_reported_not_recovered() {
    // the light's state comes from the fan plug, which goes offline
    let mut h = home_with(|rs| witnessed_by(rs, "living-room-light", FAN), false);
    let events = h.node.subscribe(Filter::Kinds(vec![EventKind::Outcome]));
    h.simulate(FAN, Simulation::Offline(true));
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(status(&r), "pending");
    assert_eq!(r.outcome.as_ref().unwrap()["observed"], Value::Null);
    h.later(2_500);
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "unconfirmed");
    assert_eq!(events.drain()[0].data.get("status"), Some(&ParamValue::Text("unconfirmed".into())));
    assert!(!h.in_recovery("resource:living-room-light"), "low risk: reported, not stopped");
    assert!(h.recoveries().is_empty());
}

#[test]
fn a_medium_risk_action_nobody_can_confirm_stops_its_resource() {
    // the thermostat's state comes from the fan plug, which goes offline after
    // the node has seen it (so its state is still fresh for SAFE-3)
    let mut h = home_with(|rs| witnessed_by(rs, "thermostat", FAN), false);
    h.simulate(FAN, Simulation::Offline(true));
    let r = h.req("person:alice", THERMO, SET, payload([("celsius", 21i64)]));
    assert_eq!(status(&r), "pending", "{}", r.summary());
    h.later(2_500);
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "unconfirmed");
    assert!(h.in_recovery("resource:thermostat"));
    assert!(h.recoveries().is_empty(), "no safe state declared: nothing to run");
    let r = h.req("person:alice", THERMO, SET, payload([("celsius", 22i64)]));
    assert!(refused_by(&r, "SAFE-8-RECOVERY"), "{}", r.summary());
}

#[test]
fn a_witness_on_another_adapter_host_is_independent() {
    let mut h = home_with(|rs| witnessed_by(rs, "living-room-light", FAN), true);
    let r = h.req("person:alice", FAN, "switch.turn_on", Payload::new());
    assert_eq!(status(&r), "verified");
    assert_eq!(r.outcome.as_ref().unwrap()["independent"], false);
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    assert_eq!(status(&r), "verified", "{}", r.summary());
    let o = r.outcome.as_ref().unwrap();
    assert_eq!((o["witness"].as_str(), o["independent"].as_bool()), (Some(FAN), Some(true)));
}

#[test]
fn a_failed_execution_reports_whether_it_took_effect_anyway() {
    let mut h = home();
    // the device could not be reached: did anything happen? The witness says no
    h.simulate(LIGHT, Simulation::FailNext(AdapterError::Unavailable("timed out".into())));
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::DeviceUnavailable));
    assert_eq!(status(&r), "not_applied");
    assert_eq!(r.outcome.as_ref().unwrap()["observed"], json!({"on": false}));
    // a device that refused says nothing happened: there is nothing to judge
    h.simulate(LIGHT, Simulation::FailNext(AdapterError::Refused("overheated".into())));
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::DeviceRefused));
    assert!(r.outcome.is_none());
    // and failures never lead to recovery
    assert!(h.node.pending_outcomes().is_empty() && h.node.domain_state().recovery.is_empty());
}

#[test]
fn a_newer_action_supersedes_a_pending_outcome() {
    let mut h = home();
    h.simulate(LIGHT, Simulation::Lag(3));
    let first = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    assert_eq!(status(&first), "pending");
    let second = h.req("person:alice", LIGHT, "light.turn_off", Payload::new());
    assert_eq!(status(&second), "verified");
    let settled = h.records("outcome");
    assert_eq!(settled.len(), 1);
    assert_eq!(
        (settled[0]["status"].as_str(), settled[0]["capability"].as_str()),
        (Some("superseded"), Some("light.turn_on"))
    );
    h.later(5_000);
    assert_eq!(h.records("outcome").len(), 1, "a superseded outcome is never judged");
}
