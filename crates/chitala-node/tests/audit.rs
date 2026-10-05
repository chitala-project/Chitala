//! v0.2 release-candidate audit: the attack matrix (docs/audit/v0.2-rc-audit.md).
//! Intersections that tests of one feature at a time miss: one resource
//! through two devices, plans and leases meeting holds, recovery and unknown
//! executions. Each test was written red first where it found a gap.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::{AdapterError, Simulation};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::{Intent, LeaseClause, LeaseTerms, PlanStep};
use chitala_model::{payload, CapabilityId, DenyCode, DeviceDescriptor, EntityId, ParamValue, Payload, SecurityClass};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response, Step};
use chitala_resource::{CapabilityBinding, Resource, ResourceId};
use chitala_token::bytes_from_base64;
use serde_json::Value;

const T0: u64 = 1_790_000_000_000;
const DOOR: &str = "device:front-door";
const MOTOR: &str = "device:door-motor";
const THERMO: &str = "device:thermostat";
const THERMO_R: &str = "resource:thermostat";
const SET: &str = "climate.set_target_temperature";

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

struct Home {
    node: Node,
    clock: Arc<AtomicU64>,
    keys: HashMap<String, Keypair>,
}

/// The sample home plus a second lock device, with the resources changed by
/// `mutate`.
fn home_with(mutate: impl FnOnce(&mut Vec<Resource>)) -> Home {
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let node_clock: chitala_node::Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let mut keys = HashMap::new();
    let mut principals = Vec::new();
    for (who, roles) in [("person:alice", &["owner"][..]), ("ai:assistant", &[][..])] {
        let k = Keypair::from_seed(&test_seed(who));
        principals.push((id(who), k.public_key(), roles.iter().map(|r| r.to_string()).collect()));
        keys.insert(who.to_string(), k);
    }
    let mut devices = sample_devices();
    devices.push(DeviceDescriptor {
        id: id(MOTOR),
        name: "Door motor".into(),
        adapter: "mock".into(),
        room: None,
        security_class: SecurityClass::Sc3,
        capabilities: VirtualKind::Lock.capabilities(),
    });
    let mut mock = MockAdapter::new();
    for d in &devices {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).unwrap());
    }
    let mut resources = sample_resources();
    mutate(&mut resources);
    let boundary = TrustedExecutionBoundary::new(entropy());
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: Keypair::from_seed(&test_seed("service:node")),
        authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
        principals,
        agency: vec![(id("ai:assistant"), vec![id("person:alice")])],
        devices,
        resources,
        safety: Default::default(),
        executor: chitala_node::executor::in_process(&boundary, vec![Box::new(mock)], node_clock.clone()),
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

impl Home {
    fn signed(&self, who: &str, target: &str, c: &str) -> Vec<u8> {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), Payload::new(), self.node.now());
        self.clock.fetch_add(1, Ordering::SeqCst);
        bytes
    }

    fn req(&mut self, who: &str, target: &str, c: &str) -> Response {
        let bytes = self.signed(who, target, c);
        self.node.handle(&bytes)
    }

    fn req_with(&mut self, who: &str, target: &str, c: &str, pl: Payload) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now());
        self.clock.fetch_add(1, Ordering::SeqCst);
        self.node.handle(&bytes)
    }

    fn later(&mut self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
        self.node.tick();
    }

    fn delegate(&mut self, target: &str, c: &str) -> Vec<u8> {
        let pl = payload([
            ("holder", ParamValue::from("ai:assistant")),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(c)),
            ("ttl_s", ParamValue::Int(3600)),
        ]);
        let r = self.req_with("person:alice", "domain:home", "domain.delegate", pl);
        assert!(r.is_ok(), "{}", r.summary());
        bytes_from_base64(r.result.unwrap()["token"].as_str().unwrap()).unwrap()
    }

    fn intent(&self, c: &str, resource: &str, params: Payload, token: &[u8]) -> Intent {
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id("ai:assistant"),
            id("person:alice"),
            cap(c),
            ResourceId::parse(resource).unwrap(),
            self.node.now(),
            120_000,
        );
        i.params = params;
        i.authority = Some(token.to_vec());
        i
    }

    fn sign(&self, i: &Intent) -> Vec<u8> {
        let bytes = i.sign(&self.keys["ai:assistant"]);
        self.clock.fetch_add(1, Ordering::SeqCst);
        bytes
    }

    /// A thermostat lease for the agent: three uses, 20–24 °C, an hour.
    fn thermostat_lease(&mut self, token: &[u8]) -> [u8; 16] {
        let mut ask = self.intent(SET, THERMO_R, Payload::new(), token);
        ask.lease = Some(LeaseClause::Request(LeaseTerms {
            max_uses: 3,
            duration_ms: 3_600_000,
            envelope: [("celsius".to_string(), (20, 24))].into(),
        }));
        let r = self.node.handle(&self.sign(&ask));
        assert!(r.is_ok(), "{}", r.summary());
        let lease = r.result.unwrap()["lease"]["id"].as_str().unwrap().to_string();
        hex::decode(lease).unwrap().try_into().unwrap()
    }

    fn lease_use(&self, token: &[u8], lease: [u8; 16], celsius: i64) -> Vec<u8> {
        let mut u = self.intent(SET, THERMO_R, payload([("celsius", celsius)]), token);
        u.lease = Some(LeaseClause::Use(lease));
        self.sign(&u)
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

    fn in_recovery(&self, resource: &str) -> bool {
        self.node.domain_state().recovery.contains_key(&ResourceId::parse(resource).unwrap())
    }
}

/// The front door's bolt is thrown by one device and withdrawn by another.
fn two_devices_one_door(rs: &mut Vec<Resource>) {
    let door = rs.iter_mut().find(|r| r.id.local() == "front-door").unwrap();
    door.bindings = vec![
        CapabilityBinding { capability: cap("device.read_state"), device: id(DOOR), risk_floor: None },
        CapabilityBinding { capability: cap("lock.lock"), device: id(DOOR), risk_floor: None },
        CapabilityBinding { capability: cap("lock.unlock"), device: id(MOTOR), risk_floor: None },
    ];
}

/// H2: one resource, two devices. While an order on the front door is still
/// executing through one device, another order on the same door through the
/// other device must not interleave with it: both were cleared on the same
/// state, and each would judge its outcome against the other's effect.
#[test]
fn one_resource_through_two_devices_takes_one_action_at_a_time() {
    let mut h = home_with(two_devices_one_door);
    // the unlock goes to the motor and is still executing (phase 2 not run yet)
    let unlock = h.signed("person:alice", MOTOR, "lock.unlock");
    let Step::Device(mut pending) = h.node.begin(&unlock) else { panic!("the unlock is a device action") };
    // a lock of the same door, through the other device, while it executes
    let r = h.req("person:alice", DOOR, "lock.lock");
    assert_eq!(r.code, Some(DenyCode::Safety), "{}", r.summary());
    assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-7-BUSY"), "{}", r.summary());
    let outcome = pending.run();
    let done = h.node.finish(pending, outcome);
    assert!(done.is_ok(), "{}", done.summary());
    // once the first is answered, the door is free again
    let r = h.req("person:alice", DOOR, "lock.lock");
    assert!(r.is_ok(), "{}", r.summary());
}

/// H2, the other side: resources that are only neighbours (in one room) are
/// not one physical thing, and a busy light does not hold up the thermostat.
#[test]
fn resources_that_share_a_room_do_not_wait_for_each_other() {
    let mut h = home_with(|_| {});
    let on = h.signed("person:alice", "device:living-room-light", "light.turn_on");
    let Step::Device(mut pending) = h.node.begin(&on) else { panic!("a device action") };
    let r = h.req("person:alice", "device:fan-plug", "switch.turn_on");
    assert!(r.is_ok(), "{}", r.summary());
    let outcome = pending.run();
    assert!(h.node.finish(pending, outcome).is_ok());
}

/// A plan cancelled while its step's command is already on its way: the
/// command cannot be called back, its outcome is still judged and recorded,
/// and nothing after it starts.
#[test]
fn a_plan_cancelled_after_its_step_was_sent_records_the_step_and_goes_no_further() {
    let mut h = home_with(|_| {});
    let set = h.delegate(THERMO_R, SET);
    let light = h.delegate("resource:living-room-light", "light.turn_on");
    let mut plan = h.intent(SET, THERMO_R, payload([("celsius", 21i64)]), &set);
    let mut s2 =
        PlanStep::new(cap("light.turn_on"), ResourceId::parse("resource:living-room-light").unwrap(), Payload::new());
    s2.authority = Some(light);
    plan.then = vec![s2];
    let bytes = h.sign(&plan);
    let Step::Device(mut pending) = h.node.begin(&bytes) else { panic!("step 1 is a device action") };
    let sent = pending.run(); // the thermostat has its order
    let cancel = payload([("plan", chitala_intent::id_hex(&plan.id).as_str())]);
    let r = h.req_with("person:alice", "domain:home", "domain.plan_cancel", cancel);
    assert!(r.is_ok(), "{}", r.summary());
    // the answer arrives after the cancellation
    let r = h.node.finish(pending, sent);
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(r.outcome.as_ref().unwrap()["status"], "verified", "the step is still judged");
    assert_eq!(r.result.as_ref().unwrap()["plan"]["status"], "cancelled");
    assert!(h.node.continue_plan_of(&r).is_none(), "step 2 never starts");
    h.later(2_000);
    let light_on = h.node.twins().get(&id("device:living-room-light")).unwrap().reported.get("on").cloned();
    assert_eq!(light_on, Some(ParamValue::Bool(false)));
    assert!(h.node.domain_state().inflight.is_empty());
}

/// A safety hold placed while a command's fate is unknown: the outcome still
/// settles, a recovery and the hold stand side by side, and a release lifts
/// both — a person decides when the resource acts again.
#[test]
fn a_hold_during_an_unknown_execution_and_the_recovery_it_ends_in() {
    // the thermostat's state comes from a sensor (the fan plug here), which is silent
    let mut h = home_with(|rs| {
        rs.iter_mut().find(|r| r.id.local() == "thermostat").unwrap().state.as_mut().unwrap().device =
            id("device:fan-plug");
    });
    h.node.simulate(&id("device:fan-plug"), Simulation::Offline(true)).unwrap();
    h.node.simulate(&id(THERMO), Simulation::FailNext(AdapterError::Indeterminate("lost".into()))).unwrap();
    let r = h.req_with("person:alice", THERMO, SET, payload([("celsius", 21i64)]));
    assert_eq!(r.outcome.as_ref().unwrap()["status"], "pending", "{}", r.summary());
    // an owner holds the thermostat while nobody knows what happened
    let hold = payload([("resource", THERMO_R), ("reason", "checking the unit")]);
    assert!(h.req_with("person:alice", "domain:home", "domain.safety_hold", hold).is_ok());
    h.later(2_500);
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "unconfirmed");
    assert!(h.in_recovery(THERMO_R), "unknown at medium risk: recovery, beside the hold");
    let r = h.req_with("person:alice", "domain:home", "domain.safety_release", payload([("resource", THERMO_R)]));
    let lifted = r.result.unwrap();
    assert_eq!((lifted["was_held"].as_bool(), lifted["was_recovering"].as_bool()), (Some(true), Some(true)));
    assert!(!h.in_recovery(THERMO_R));
}

/// A lease on a resource that goes into recovery: the next use is refused by
/// Safety (SAFE-8) and not counted; the lease's other terms are untouched.
#[test]
fn a_lease_use_on_a_resource_in_recovery_is_refused_and_not_counted() {
    let mut h = home_with(|_| {});
    let token = h.delegate(THERMO_R, SET);
    let lease = h.thermostat_lease(&token);
    // the first use: the thermostat reports it, but it does not happen
    h.node.simulate(&id(THERMO), Simulation::Stuck(true)).unwrap();
    let r = h.node.handle(&h.lease_use(&token, lease, 22));
    assert_eq!(r.outcome.as_ref().unwrap()["status"], "pending", "{}", r.summary());
    h.later(2_500);
    assert!(h.in_recovery(THERMO_R));
    // the second use meets the recovery
    let r = h.node.handle(&h.lease_use(&token, lease, 23));
    assert_eq!(r.code, Some(DenyCode::Safety), "{}", r.summary());
    assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-8-RECOVERY"), "{}", r.summary());
    let id_hex = hex::encode(lease);
    assert_eq!(h.node.domain_state().leases[&id_hex].uses, 1, "a refused use is not counted");
}

/// A plan step and a lease use for the same resource at the same time: one
/// action at a time (SAFE-7); the lease use is refused and not counted, the
/// plan step completes.
#[test]
fn a_plan_step_and_a_lease_use_on_one_resource_do_not_interleave() {
    let mut h = home_with(|_| {});
    let token = h.delegate(THERMO_R, SET);
    let lease = h.thermostat_lease(&token);
    let plan_token = h.delegate("resource:living-room-light", "light.turn_on");
    let mut plan = h.intent(SET, THERMO_R, payload([("celsius", 20i64)]), &token);
    let mut s2 =
        PlanStep::new(cap("light.turn_on"), ResourceId::parse("resource:living-room-light").unwrap(), Payload::new());
    s2.authority = Some(plan_token);
    plan.then = vec![s2];
    let bytes = h.sign(&plan);
    let Step::Device(mut pending) = h.node.begin(&bytes) else { panic!("a device action") };
    let r = h.node.handle(&h.lease_use(&token, lease, 24));
    assert_eq!(r.code, Some(DenyCode::Safety), "{}", r.summary());
    assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-7-BUSY"), "{}", r.summary());
    assert_eq!(h.node.domain_state().leases[&hex::encode(lease)].uses, 0);
    let outcome = pending.run();
    let r = h.node.finish(pending, outcome);
    assert!(r.is_ok(), "{}", r.summary());
}
