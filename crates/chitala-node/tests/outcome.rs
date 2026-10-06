//! Outcome verification and recovery end to end (v0.2 step 9, spec 22): did the
//! world end up as the action promised, according to the resource's witness;
//! and when it did not, the resource takes nothing but its safe state, which
//! the node runs once by itself, until a person releases it.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::{AdapterError, DeviceAdapter, Provenance, Simulation, VerifiedOrder};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_bus::Filter;
use chitala_identity::{test_seed, Keypair};
use chitala_model::{payload, CapabilityId, DenyCode, EntityId, EventKind, ExecCode, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::executor::{in_process, Routed};
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response, Step};
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
    /// How many times each device was observed.
    asked: Arc<Mutex<BTreeMap<EntityId, u32>>>,
    /// What the adapter says ties its states to the devices (`None`: the
    /// truth, a read from the device now).
    vouch: Arc<Mutex<Option<Provenance>>>,
}

/// The virtual devices, counting how often each one is observed.
struct Counting {
    inner: MockAdapter,
    asked: Arc<Mutex<BTreeMap<EntityId, u32>>>,
    vouch: Arc<Mutex<Option<Provenance>>>,
}

impl DeviceAdapter for Counting {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn manages(&self, device: &EntityId) -> bool {
        self.inner.manages(device)
    }
    fn observe(&mut self, device: &EntityId) -> Result<chitala_adapters::Observed, AdapterError> {
        *self.asked.lock().unwrap().entry(device.clone()).or_default() += 1;
        let mut o = self.inner.observe(device)?;
        if let Some(p) = *self.vouch.lock().unwrap() {
            o.provenance = p;
        }
        Ok(o)
    }
    fn execute(&mut self, order: VerifiedOrder) -> Result<Payload, AdapterError> {
        self.inner.execute(order)
    }
    fn simulate(&mut self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        self.inner.simulate(device, change)
    }
}

fn home() -> Home {
    home_with(|_| {}, false)
}

/// The sample home with its resources changed by `mutate`. With `split`, the
/// fan plug is served by an adapter host instance of its own.
fn home_with(mutate: impl FnOnce(&mut Vec<Resource>), split: bool) -> Home {
    build(mutate, split, chitala_node::DomainState::default(), T0, None)
}

/// The node crashes and starts again with the domain state it had persisted;
/// the virtual devices start afresh, and the adapter vouches as it did.
fn restart(h: Home) -> Home {
    let state = h.node.domain_state().clone();
    let (now, vouch) = (h.node.now() + 2_000, *h.vouch.lock().unwrap());
    drop(h);
    build(|_| {}, false, state, now, vouch)
}

fn build(
    mutate: impl FnOnce(&mut Vec<Resource>),
    split: bool,
    state: chitala_node::DomainState,
    t0: u64,
    vouch: Option<Provenance>,
) -> Home {
    let clock = Arc::new(AtomicU64::new(t0));
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
    let asked = Arc::new(Mutex::new(BTreeMap::new()));
    let vouch = Arc::new(Mutex::new(vouch));
    let main = Counting { inner: main, asked: Arc::clone(&asked), vouch: Arc::clone(&vouch) };
    let own = Counting { inner: own, asked: Arc::clone(&asked), vouch: Arc::clone(&vouch) };
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
        state,
        state_file: None,
        containment: ContainmentConfig::default(),
        monitor: MonitorConfig::default(),
        entropy: entropy(),
        clock: node_clock,
        clock_watch: None,
        boundary,
    })
    .unwrap();
    Home { node, clock, keys, asked, vouch }
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

    fn asked(&self, device: &str) -> u32 {
        self.asked.lock().unwrap().get(&id(device)).copied().unwrap_or(0)
    }

    /// Ticks one second apart; the seconds at which `device` was observed.
    fn asked_at(&mut self, device: &str, seconds: u32) -> Vec<u32> {
        let mut at = Vec::new();
        for s in 1..=seconds {
            let before = self.asked(device);
            self.later(1_000);
            if self.asked(device) > before {
                at.push(s);
            }
        }
        at
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
    // the thermostat's state comes from the fan plug, which drops off without
    // the node noticing: its state is still fresh for SAFE-3 when the action
    // is decided, and only the witness's observation afterwards fails (once
    // the node knows, the state is no evidence: F6, below)
    let mut h = home_with(|rs| witnessed_by(rs, "thermostat", FAN), false);
    h.node.simulate_unseen(&id(FAN), Simulation::Offline(true)).unwrap();
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
fn a_command_whose_fate_is_unknown_is_watched_and_a_certain_failure_is_not() {
    let mut h = home();
    // the answer was lost: did anything happen? The witness will tell
    h.simulate(LIGHT, Simulation::FailNext(AdapterError::Indeterminate("timed out".into())));
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown));
    assert_eq!(status(&r), "pending");
    assert_eq!(r.outcome.as_ref().unwrap()["execution"], "unknown");
    h.later(2_500);
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!((settled["status"].as_str(), settled["observed"].clone()), (Some("not_applied"), json!({"on": false})));
    // certain failures (unreachable, refused, unmappable) executed nothing:
    // there is nothing to watch
    for err in [
        AdapterError::Unavailable("offline".into()),
        AdapterError::Refused("overheated".into()),
        AdapterError::Failed("no such relay".into()),
    ] {
        let code = err.code();
        h.simulate(LIGHT, Simulation::FailNext(err));
        let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
        assert_eq!(r.error.as_ref().map(|e| e.code), Some(code));
        assert!(r.outcome.is_none(), "{code}");
    }
    // and none of it is a broken promise at low risk
    assert!(h.node.pending_outcomes().is_empty() && h.node.domain_state().recovery.is_empty());
}

/// v0.3 step ③A, finding F9b: a state is evidence of what an order did only
/// if its adapter confirmed it current, no earlier than the state was
/// produced. A fresh timestamp alone is not enough: a gateway re-emits a dead
/// device's cached value with a new one.
#[test]
fn only_a_state_confirmed_current_is_evidence_of_an_order() {
    for (vouch, expected, confirmed) in [
        (Provenance::Uncertain, "unconfirmed", false),
        // confirmed, but a minute before this state was produced
        (Provenance::ConfirmedCurrent { age_ms: 60_000 }, "unconfirmed", true),
        (Provenance::ConfirmedCurrent { age_ms: 0 }, "not_applied", true),
    ] {
        let mut h = home();
        *h.vouch.lock().unwrap() = Some(vouch);
        h.simulate(LIGHT, Simulation::FailNext(AdapterError::Indeterminate("timed out".into())));
        let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
        assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown));
        assert_eq!(status(&r), "pending", "{vouch:?}");
        h.later(2_500);
        let settled = h.records("outcome").pop().unwrap();
        assert_eq!(settled["status"], expected, "{vouch:?}");
        let twin = h.node.twins().get(&id(LIGHT)).unwrap();
        assert!(twin.source_at_ms.is_some(), "a fresh timestamp either way");
        assert_eq!(twin.confirmed_at_ms.is_some(), confirmed, "{vouch:?}: {twin:?}");
    }
}

/// F9b across a restart: the node dies after sending an order; at start-up
/// the witness's state, fresh but not confirmed current, settles nothing.
#[test]
fn after_a_restart_an_unconfirmed_state_settles_nothing() {
    for (vouch, expected) in [(Some(Provenance::Uncertain), "unconfirmed"), (None, "not_applied")] {
        let mut h = home();
        *h.vouch.lock().unwrap() = vouch;
        h.simulate(LIGHT, Simulation::Stuck(true));
        let r = Requester::new(id("person:alice"), h.keys["person:alice"].clone(), id("service:test"), entropy());
        let bytes = r.sign(h.node.registry(), &id(LIGHT), &cap("light.turn_on"), Payload::new(), h.node.now());
        h.advance(1);
        let Step::Device(mut pending) = h.node.begin(&bytes) else { panic!("a device action") };
        let _answer = pending.run(); // the node dies before it hears the answer
        drop(pending);
        // at start-up the light is read after the order (the virtual devices
        // start afresh: off); only a confirmed reading counts
        let mut h = restart(h);
        h.later(2_500);
        h.later(2_500);
        let settled = h.records("outcome").pop().unwrap();
        assert_eq!(settled["status"], expected, "{vouch:?}");
    }
}

/// The periodic pass observes the door outside the node lock: the door is
/// due, its observer reads it now; what it read is folded later.
macro_rules! observe_the_door_later {
    ($h:expr) => {{
        $h.advance(chitala_resource::DEFAULT_MAX_STATE_AGE_MS / 2 + 1);
        let now = $h.node.now();
        let observer =
            $h.node.due_observations(now).into_iter().find(|o| o.device() == &id(DOOR)).expect("the door is due");
        let read = observer.run();
        $h.advance(5);
        (observer, read)
    }};
}

fn door_locked(h: &Home) -> Option<ParamValue> {
    h.reported(DOOR, "locked")
}

/// Concurrency audit R3: an observation is ordered by when its answer arrived,
/// not by when the node got round to folding it. An earlier reading of the
/// door, folded after the door was unlocked, never makes the twin say locked.
#[test]
fn an_earlier_reading_folded_late_never_overwrites_a_newer_state() {
    let mut h = home();
    let (observer, read) = observe_the_door_later!(h); // reads "locked"
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(door_locked(&h), Some(ParamValue::Bool(false)));
    h.advance(5);
    h.node.observed_by(&observer, read);
    assert_eq!(door_locked(&h), Some(ParamValue::Bool(false)), "the earlier reading is history");
}

/// R3b: an earlier good reading, folded after the door could no longer be
/// observed, does not make it observable again (F6): Safety still refuses.
#[test]
fn an_earlier_good_reading_folded_late_never_hides_a_lost_device() {
    let mut h = home();
    let (observer, read) = observe_the_door_later!(h); // a good reading
    h.simulate(DOOR, Simulation::Offline(true));
    let r = h.req("person:alice", DOOR, "device.read_state", Payload::new());
    assert!(r.result.as_ref().is_some_and(|v| v.get("observe_error").is_some()), "{}", r.summary());
    let lost = |h: &Home| h.node.twins().get(&id(DOOR)).and_then(|t| t.unobservable_since_ms);
    assert!(lost(&h).is_some());
    h.advance(5);
    h.node.observed_by(&observer, read);
    assert!(lost(&h).is_some(), "the reading came before the loss: the door is still unobservable");
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(refused_by(&r, "SAFE-3"), "{}", r.summary());
}

/// R3, the other way round: a failed observation that came back before a good
/// one, folded after it, does not make the door unobservable.
#[test]
fn an_earlier_failure_folded_late_never_hides_a_newer_reading() {
    let mut h = home();
    h.simulate(DOOR, Simulation::Offline(true));
    let (observer, failed) = observe_the_door_later!(h);
    assert!(failed.0.is_err());
    h.simulate(DOOR, Simulation::Offline(false));
    let r = h.req("person:alice", DOOR, "device.read_state", Payload::new());
    assert!(r.result.as_ref().is_some_and(|v| v.get("observe_error").is_none()), "{}", r.summary());
    h.advance(5);
    h.node.observed_by(&observer, failed);
    let twin = h.node.twins().get(&id(DOOR)).unwrap();
    assert_eq!(twin.unobservable_since_ms, None, "the failure is history: the door was read after it");
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(r.is_ok(), "{}", r.summary());
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

// ─────────────── observability lost (v0.3 step ③A, finding F6) ───────────────

/// F6 (found against a real Home Assistant): the last known state of a device
/// that can no longer be observed is history, never evidence. A locked door
/// whose lock goes unavailable is not known to be locked: an unlock is refused
/// by Safety. The lock coming back is not enough either; only a fresh
/// observation makes its state count again.
#[test]
fn a_lock_that_cannot_be_observed_is_not_known_to_be_locked() {
    let mut h = home();
    assert!(h.req("person:alice", DOOR, "lock.lock", Payload::new()).is_ok());
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
    // the node looks at once (a simulated change is observed), and cannot see it
    h.simulate(DOOR, Simulation::Offline(true));
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(refused_by(&r, "SAFE-3-STATE"), "{}", r.summary());

    let view = h.req("person:alice", DOOR, "device.read_state", Payload::new()).result.unwrap();
    assert!(view["observe_error"].is_string(), "{view}");
    assert_eq!(view["freshness"], "unknown", "{view}");
    assert_eq!(view["reported"]["locked"], true, "the last known state is kept, as history: {view}");
    assert!(view["unobservable_since_ms"].is_u64(), "{view}");
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(refused_by(&r, "SAFE-3-STATE"), "{}", r.summary());

    // the lock is back, but nobody has looked at it yet
    h.node.simulate_unseen(&id(DOOR), Simulation::Offline(false)).unwrap();
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(refused_by(&r, "SAFE-3-STATE"), "{}", r.summary());

    // the node looks again on a later pass (F5 spaces the attempts), sees it
    // locked, and the state counts again
    for _ in 0..30 {
        if h.node.twins().freshness(&id(DOOR), h.node.now()) == chitala_state::Freshness::Fresh {
            break;
        }
        h.later(1_000);
    }
    assert_eq!(h.node.twins().freshness(&id(DOOR), h.node.now()), chitala_state::Freshness::Fresh);
    let view = h.req("person:alice", DOOR, "device.read_state", Payload::new()).result.unwrap();
    assert_eq!(view["freshness"], "fresh", "{view}");
    assert!(view.get("unobservable_since_ms").is_none(), "{view}");
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(r.is_ok(), "{}", r.summary());
}

/// F6, found when someone reads the device: a reading that fails makes its
/// state unknown for Safety too.
#[test]
fn a_reading_that_fails_makes_the_state_unknown() {
    let mut h = home();
    assert!(h.req("person:alice", DOOR, "lock.lock", Payload::new()).is_ok());
    h.node.simulate_unseen(&id(DOOR), Simulation::Offline(true)).unwrap();
    let view = h.req("person:alice", DOOR, "device.read_state", Payload::new()).result.unwrap();
    assert_eq!(view["freshness"], "unknown", "{view}");
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(refused_by(&r, "SAFE-3-STATE"), "{}", r.summary());
}

/// F6, found by the node on its own: the periodic pass notices that a device
/// it relies on cannot be observed any more.
#[test]
fn the_periodic_pass_notices_a_lost_device() {
    let mut h = home();
    assert!(h.req("person:alice", DOOR, "lock.lock", Payload::new()).is_ok());
    h.node.simulate_unseen(&id(DOOR), Simulation::Offline(true)).unwrap();
    // the door's state is relied on: it is looked at again before it gets old
    h.later(61_000);
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(refused_by(&r, "SAFE-3-STATE"), "{}", r.summary());
}

/// F6, through a witness: an order whose witness cannot be observed leaves the
/// witness's last state without value for the next decision that relies on it.
#[test]
fn a_witness_that_cannot_be_observed_is_no_evidence_for_the_next_action() {
    // the light and the thermostat are both witnessed by the fan plug
    let mut h = home_with(
        |rs| {
            witnessed_by(rs, "living-room-light", FAN);
            witnessed_by(rs, "thermostat", FAN);
        },
        false,
    );
    h.node.simulate_unseen(&id(FAN), Simulation::Offline(true)).unwrap();
    // a low-risk action needs no state; its witness is looked at afterwards
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    assert!(r.is_ok(), "{}", r.summary());
    // the thermostat (medium risk) relies on the same witness, now known lost
    let r = h.req("person:alice", THERMO, SET, payload([("celsius", 21i64)]));
    assert!(refused_by(&r, "SAFE-3-STATE"), "{}", r.summary());
}

// ───────────── asking a lost device again (v0.3 step ③A, finding F5) ─────────────

/// F5: a device that cannot be observed was asked again on every pass of the
/// node, once a second, for good. In the lab, an entity Home Assistant did not
/// have cost a REST read a second. It is now asked again after 1, 2, 4, 8 and
/// 16 s, then every 30 s, and after a good observation the pace starts over.
/// Safety does not change: meanwhile the state is unknown (F6).
#[test]
fn a_device_that_cannot_be_observed_is_asked_less_and_less_often() {
    let mut h = home();
    assert!(h.req("person:alice", DOOR, "lock.lock", Payload::new()).is_ok());
    h.simulate(DOOR, Simulation::Offline(true)); // looked at once, and lost
    assert_eq!(h.asked_at(DOOR, 120), [1, 3, 7, 15, 31, 61, 91]);
    let r = h.req("person:alice", DOOR, "lock.unlock", Payload::new());
    assert!(refused_by(&r, "SAFE-3-STATE"), "{}", r.summary());

    // back: seen at the next attempt, at most 30 s later
    h.node.simulate_unseen(&id(DOOR), Simulation::Offline(false)).unwrap();
    assert_eq!(h.asked_at(DOOR, 30), [1], "the attempt due at 121 s");
    assert!(h.node.twins().evidence(&id(DOOR), h.node.now()).is_some());

    // lost again later: looked at when its state is 60 s old (it was seen 29 s
    // before this loop), and the pace starts over from 1 s
    h.node.simulate_unseen(&id(DOOR), Simulation::Offline(true)).unwrap();
    let at = h.asked_at(DOOR, 66);
    assert_eq!(at.first(), Some(&31), "{at:?}");
    let gaps: Vec<u32> = at.windows(2).map(|w| w[1] - w[0]).collect();
    assert_eq!(gaps, [1, 2, 4, 8, 16], "{at:?}");
}

/// F5 never delays the witness of a pending outcome: its outcome is settled
/// within a few seconds, and asking it less often could turn `verified` into
/// `unconfirmed`. Once the outcome is settled, the pace applies again.
#[test]
fn a_pending_witness_is_still_asked_on_every_pass() {
    // the thermostat's witness is the fan plug, which drops off unseen; the
    // thermostat promises its effect within 2 s
    let mut h = home_with(|rs| witnessed_by(rs, "thermostat", FAN), false);
    h.node.simulate_unseen(&id(FAN), Simulation::Offline(true)).unwrap();
    let r = h.req("person:alice", THERMO, SET, payload([("celsius", 21i64)]));
    assert_eq!(status(&r), "pending", "{}", r.summary());
    assert_eq!(h.asked_at(FAN, 2), [1, 2], "on every pass while the outcome is pending");
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "unconfirmed");
    assert!(h.asked_at(FAN, 3).is_empty(), "settled: the pace applies again (4 s after the last failure)");
}
