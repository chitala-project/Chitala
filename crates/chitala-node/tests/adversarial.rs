//! The TOCTOU and adversarial suite of v0.2 step 4 (spec 13 "Time of check,
//! time of use"): what changes between a decision and its execution, or races
//! with it, never turns into an action the decision would not allow now.
//!
//! The node releases its lock while a device works, so these tests drive the
//! three phases by hand — `begin` (decide, clear, mint), then a change, then
//! `run` (send) and `finish` (record).

use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::{Approval, Intent, Verdict};
use chitala_model::{payload, CapabilityId, DenyCode, EntityId, ExecCode, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, PendingDevice, Requester, Response, Step};
use chitala_platform::memory::MemoryTime;
use chitala_platform::{TimeSource, TrustedClock};
use chitala_resource::{Resource, ResourceId};
use chitala_token::bytes_from_base64;
use serde_json::Value;

const T0: u64 = 1_790_000_000_000;
const LIGHT: &str = "device:living-room-light";
const LIGHT_R: &str = "resource:living-room-light";
const DOOR: &str = "device:front-door";
const DOOR_R: &str = "resource:front-door";

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn rid(s: &str) -> ResourceId {
    ResourceId::parse(s).unwrap()
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
fn key(s: &str) -> Keypair {
    Keypair::from_seed(&test_seed(s))
}
fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

struct Home {
    node: Node,
    time: Arc<MemoryTime>,
}

/// A home on a trusted clock over a test-driven time source; alice and bob both
/// hold the owner role, bob owns the door too.
fn home_with(resources: Vec<Resource>) -> Home {
    let time = Arc::new(MemoryTime::new(T0));
    let trusted = Arc::new(TrustedClock::new(time.clone() as Arc<dyn TimeSource>, 0));
    let clock = trusted.as_clock();
    let people: [(&str, &[&str]); 4] =
        [("person:alice", &["owner"]), ("person:bob", &["owner"]), ("person:carol", &["adult"]), ("ai:assistant", &[])];
    let mut mock = MockAdapter::new();
    for d in sample_devices() {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).unwrap());
    }
    let boundary = TrustedExecutionBoundary::new(entropy());
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: key("service:node"),
        authority_key: key("domain:home/authority"),
        principals: people
            .iter()
            .map(|(p, r)| (id(p), key(p).public_key(), r.iter().map(|x| x.to_string()).collect()))
            .collect(),
        agency: vec![(id("ai:assistant"), vec![id("person:alice")])],
        devices: sample_devices(),
        resources,
        safety: Default::default(),
        executor: chitala_node::executor::in_process(&boundary, vec![Box::new(mock)], clock.clone()),
        policy: chitala_node::PolicySource::Default,
        audit: AuditLog::in_memory(None),
        state: chitala_node::DomainState::default(),
        state_file: None,
        containment: ContainmentConfig::default(),
        monitor: MonitorConfig::default(),
        entropy: entropy(),
        clock,
        clock_watch: Some(trusted),
        boundary,
    })
    .unwrap();
    Home { node, time }
}

fn home() -> Home {
    let mut resources = sample_resources();
    let door = resources.iter_mut().find(|r| r.id == rid(DOOR_R)).unwrap();
    door.owners = vec![id("person:alice"), id("person:bob")];
    home_with(resources)
}

impl Home {
    fn tick(&self, ms: u64) {
        self.time.advance(ms);
    }

    fn signed(&self, who: &str, target: &str, c: &str, pl: Payload, token: Option<&[u8]>) -> Vec<u8> {
        let r = Requester::new(id(who), key(who), id("service:test"), entropy()).with_token(token.map(<[u8]>::to_vec));
        r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now())
    }

    fn req(&mut self, who: &str, target: &str, c: &str, pl: Payload) -> Response {
        let bytes = self.signed(who, target, c, pl, None);
        self.tick(1);
        self.node.handle(&bytes)
    }

    /// Decide, clear and mint — and stop before the order is sent.
    fn begin(&mut self, bytes: &[u8]) -> PendingDevice {
        self.tick(1);
        match self.node.begin(bytes) {
            Step::Device(p) => p,
            Step::Done(r) => panic!("expected an order, got {}", r.summary()),
        }
    }

    fn send(&mut self, mut p: PendingDevice) -> Response {
        let outcome = p.run();
        self.node.finish(p, outcome)
    }

    fn delegate(&mut self, holder: &str, target: &str, c: &str, ttl_s: i64) -> Vec<u8> {
        let pl = payload([
            ("holder", ParamValue::from(holder)),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(c)),
            ("ttl_s", ParamValue::Int(ttl_s)),
        ]);
        let r = self.req("person:alice", "domain:home", "domain.delegate", pl);
        assert!(r.is_ok(), "{}", r.summary());
        bytes_from_base64(r.result.unwrap()["token"].as_str().unwrap()).unwrap()
    }

    fn intent(&self, resource: &str, c: &str, token: &[u8]) -> Intent {
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id("ai:assistant"),
            id("person:alice"),
            cap(c),
            rid(resource),
            self.node.now(),
            120_000,
        );
        i.authority = Some(token.to_vec());
        i
    }

    fn approval(&self, who: &str, i: &Intent) -> Vec<u8> {
        let now = self.node.now();
        Approval {
            intent: i.id,
            intent_digest: i.digest(),
            approver: id(who),
            verdict: Verdict::Approve,
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            note: None,
        }
        .sign(&key(who))
    }

    fn reported(&self, device: &str, field: &str) -> Option<ParamValue> {
        self.node.twins().get(&id(device)).and_then(|t| t.reported.get(field).cloned())
    }

    fn audit(&self, kind: &str) -> Vec<Value> {
        self.node
            .audit()
            .lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| v["kind"] == kind)
            .collect()
    }
}

fn deny(r: &Response) -> (DenyCode, String) {
    assert!(!r.is_allow(), "expected deny, got {}", r.summary());
    (r.code.unwrap(), r.reason.clone().unwrap_or_default())
}

fn rejected(r: &Response, why: &str) {
    let e = r.error.as_ref().unwrap_or_else(|| panic!("expected an execution error, got {}", r.summary()));
    assert_eq!(e.code, ExecCode::OrderRejected, "{}", e.message);
    assert!(e.message.contains(why), "{}", e.message);
}

// ───────────────────────── Authority → Safety → Execution ─────────────────────────

#[test]
fn a_safety_hold_placed_after_the_decision_stops_the_order() {
    let mut h = home();
    let bytes = h.signed("person:alice", LIGHT, "light.turn_on", Payload::new(), None);
    let pending = h.begin(&bytes);
    // someone puts the whole living room on hold while the order is in flight
    h.node.hold(&rid("resource:living-room"), "electrician at work", &id("person:bob")).unwrap();
    rejected(&h.send(pending), "resource:living-room is under a safety hold");
    assert_ne!(h.reported(LIGHT, "on"), Some(ParamValue::Bool(true)));
    // new requests are refused by Safety itself, until the hold is released
    let (code, why) = deny(&h.req("person:alice", LIGHT, "light.turn_on", Payload::new()));
    assert_eq!(code, DenyCode::Safety);
    assert!(why.contains("SAFE-1-HOLD"), "{why}");
    assert!(h.node.release(&rid("resource:living-room"), &id("person:bob")));
    assert!(h.req("person:alice", LIGHT, "light.turn_on", Payload::new()).is_ok());
    // both are on the record
    let ops: Vec<String> = h.audit("safety").iter().map(|v| v["op"].as_str().unwrap().to_string()).collect();
    assert_eq!(ops, ["hold", "release"]);
}

#[test]
fn holds_are_a_domain_operation_of_owners() {
    let mut h = home();
    let hold = payload([("resource", ParamValue::from(DOOR_R)), ("reason", ParamValue::from("alarm armed"))]);
    // an adult may not place or lift holds; an owner may
    assert_eq!(
        deny(&h.req("person:carol", "domain:home", "domain.safety_hold", hold.clone())).0,
        DenyCode::PolicyDenied
    );
    assert!(h.req("person:alice", "domain:home", "domain.safety_hold", hold).is_ok());
    let (code, why) = deny(&h.req("person:bob", DOOR, "lock.unlock", Payload::new()));
    assert_eq!(code, DenyCode::Safety);
    assert!(why.contains("alarm armed"), "{why}");
    let release = payload([("resource", ParamValue::from(DOOR_R))]);
    assert!(h.req("person:bob", "domain:home", "domain.safety_release", release).is_ok());
    assert!(h.req("person:bob", DOOR, "lock.unlock", Payload::new()).is_ok());
    // an agent cannot even ask: it sends no commands
    let bytes = h.signed("ai:assistant", "domain:home", "domain.safety_release", payload([("resource", DOOR_R)]), None);
    assert_eq!(deny(&h.node.handle(&bytes)).0, DenyCode::IntentRequired);
}

#[test]
fn a_token_that_expires_in_flight_stops_the_order() {
    let mut h = home();
    let token = h.delegate("ai:assistant", LIGHT_R, "light.turn_on", 2);
    let i = h.intent(LIGHT_R, "light.turn_on", &token);
    let pending = h.begin(&i.sign(&key("ai:assistant")));
    // the device takes its time; the right ends before the order goes out
    h.tick(3_000);
    // (the order itself is still fresh: it is the right behind it that ended)
    rejected(&h.send(pending), "authority changed since the decision (token");
    assert_ne!(h.reported(LIGHT, "on"), Some(ParamValue::Bool(true)));
}

#[test]
fn an_approver_demoted_in_flight_stops_the_order() {
    let mut h = home();
    let token = h.delegate("ai:assistant", DOOR_R, "lock.unlock", 600);
    let i = h.intent(DOOR_R, "lock.unlock", &token);
    let r = h.node.handle(&i.sign(&key("ai:assistant")));
    assert!(r.is_escalated(), "{}", r.summary());
    // alice's approval decides — and is then found compromised: bob quarantines her
    let pending = h.begin(&h.approval("person:alice", &i));
    let r = h.req(
        "person:bob",
        "domain:home",
        "domain.set_principal_state",
        payload([("principal", "person:alice"), ("state", "QUARANTINED")]),
    );
    assert!(r.is_ok(), "{}", r.summary());
    rejected(&h.send(pending), "person:alice is now QUARANTINED");
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
}

// ───────────────────────── concurrency ─────────────────────────

#[test]
fn conflicting_actions_on_one_device_do_not_interleave() {
    let mut h = home();
    // two people act on the door at the same time; both are allowed by policy
    let unlock = h.signed("person:alice", DOOR, "lock.unlock", Payload::new(), None);
    let first = h.begin(&unlock);
    let (code, why) = deny(&h.req("person:bob", DOOR, "lock.lock", Payload::new()));
    assert_eq!(code, DenyCode::Safety);
    assert!(why.contains("SAFE-7-BUSY"), "{why}");
    // another device is not affected
    assert!(h.req("person:bob", LIGHT, "light.turn_on", Payload::new()).is_ok());
    // once the first order is answered the door is free again
    assert!(h.send(first).is_ok());
    assert!(h.req("person:bob", DOOR, "lock.lock", Payload::new()).is_ok());
}

#[test]
fn a_device_is_free_again_when_its_order_is_refused_or_expires() {
    let mut h = home();
    let token = h.delegate("ai:assistant", LIGHT_R, "light.turn_on", 600);
    // refused at the fence: the device is released
    let i = h.intent(LIGHT_R, "light.turn_on", &token);
    let pending = h.begin(&i.sign(&key("ai:assistant")));
    h.node.hold(&rid(LIGHT_R), "test", &id("person:bob")).unwrap();
    rejected(&h.send(pending), "safety hold");
    h.node.release(&rid(LIGHT_R), &id("person:bob"));
    assert!(h.req("person:alice", LIGHT, "light.turn_off", Payload::new()).is_ok());
    // an order whose phase 2 never came back blocks the device only until it expires
    let bytes = h.signed("person:alice", LIGHT, "light.turn_on", Payload::new(), None);
    let lost = h.begin(&bytes);
    assert_eq!(deny(&h.req("person:bob", LIGHT, "light.turn_off", Payload::new())).0, DenyCode::Safety);
    h.tick(chitala_csme::order::ORDER_TTL_MS + 1);
    assert!(h.req("person:bob", LIGHT, "light.turn_off", Payload::new()).is_ok());
    drop(lost);
}

#[test]
fn the_same_intent_submitted_twice_at_once_runs_once() {
    let mut h = home();
    let token = h.delegate("ai:assistant", LIGHT_R, "light.turn_on", 600);
    let bytes = h.intent(LIGHT_R, "light.turn_on", &token).sign(&key("ai:assistant"));
    let first = h.begin(&bytes);
    assert_eq!(deny(&h.node.handle(&bytes)).0, DenyCode::Replay);
    assert!(h.send(first).is_ok());
}

// ───────────────────────── approvals ─────────────────────────

#[test]
fn an_approval_cannot_be_replayed() {
    let mut h = home();
    let token = h.delegate("ai:assistant", DOOR_R, "lock.unlock", 600);
    let i = h.intent(DOOR_R, "lock.unlock", &token);
    assert!(h.node.handle(&i.sign(&key("ai:assistant"))).is_escalated());
    let yes = h.approval("person:alice", &i);
    h.tick(1);
    assert!(h.node.handle(&yes).is_ok());
    assert!(h.req("person:alice", DOOR, "lock.lock", Payload::new()).is_ok());
    // the same signed answer again: refused, the door stays locked
    h.tick(1);
    assert_eq!(deny(&h.node.handle(&yes)).0, DenyCode::Replay);
    // the intent again, to reuse the answer: refused as well
    h.tick(1);
    assert_eq!(deny(&h.node.handle(&i.sign(&key("ai:assistant")))).0, DenyCode::Replay);
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
}

#[test]
fn a_clock_set_back_cannot_reopen_an_expired_question() {
    let mut h = home();
    let token = h.delegate("ai:assistant", DOOR_R, "lock.unlock", 3600);
    let i = h.intent(DOOR_R, "lock.unlock", &token);
    assert!(h.node.handle(&i.sign(&key("ai:assistant"))).is_escalated());
    // the question expires, then someone sets the wall clock back
    h.tick(121_000);
    let late = h.approval("person:alice", &i);
    h.time.set_wall(T0);
    let (code, why) = deny(&h.node.handle(&late));
    assert_eq!(code, DenyCode::ApprovalInvalid, "{why}");
    assert!(h.node.pending_approvals().is_empty());
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
}

// ───────────────────────── state ─────────────────────────

#[test]
fn stale_state_is_refreshed_never_trusted() {
    let mut h = home();
    // nobody has looked at the door for longer than its state may be old
    h.tick(130_000);
    let (code, why) = deny(&h.req("person:alice", DOOR, "lock.unlock", Payload::new()));
    assert_eq!(code, DenyCode::Safety);
    assert!(why.contains("SAFE-3-STATE"), "{why}");
    // the node looks (ipc::refresh_state does this every few seconds)
    let now = h.node.now();
    for o in h.node.due_observations(now) {
        let outcome = o.run();
        h.node.observed_by(&o, outcome);
    }
    assert!(h.req("person:alice", DOOR, "lock.unlock", Payload::new()).is_ok());
}

// ───────────────────────── configuration changes ─────────────────────────

#[test]
fn an_ownership_change_needs_a_restart_that_drops_waiting_questions() {
    // before: alice and bob own the door; the agent asks
    let mut before = home();
    let token = before.delegate("ai:assistant", DOOR_R, "lock.unlock", 600);
    let i = before.intent(DOOR_R, "lock.unlock", &token);
    let r = before.node.handle(&i.sign(&key("ai:assistant")));
    assert!(r.is_escalated());
    // ownership (and policy) are configuration: changing them means a restart
    let mut resources = sample_resources();
    resources.iter_mut().find(|r| r.id == rid(DOOR_R)).unwrap().owners = vec![id("person:bob")];
    let mut after = home_with(resources);
    // alice's answer to the old question finds nothing waiting
    let (code, _) = deny(&after.node.handle(&after.approval("person:alice", &i)));
    assert_eq!(code, DenyCode::ApprovalInvalid);
    // the old intent cannot be replayed into the new node
    after.tick(1);
    assert!(!after.node.handle(&i.sign(&key("ai:assistant"))).is_allow());
    // asked again, the question goes to the new owner only
    let token = after.delegate("ai:assistant", DOOR_R, "lock.unlock", 600);
    let i = after.intent(DOOR_R, "lock.unlock", &token);
    let r = after.node.handle(&i.sign(&key("ai:assistant")));
    assert!(r.is_escalated());
    assert_eq!(r.approvers.as_deref(), Some(&["person:bob".to_string()][..]));
}
