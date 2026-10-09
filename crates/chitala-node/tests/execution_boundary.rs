//! Trusted Execution Boundary v0.2 — Single Path, Single Use, Provenance Bound
//! (spec `specs/19-execution-boundary.md`): the attacks.
//!
//! Every test runs the real node and the real adapter-host gate. A `Tap`
//! executor sits between them and keeps every order the boundary minted, so
//! the tests can replay, redirect, delay, tamper with or re-deliver real
//! orders, and make the adapter host lie in its receipts.
//!
//! The attacks that the type system rules out at compile time (forging a
//! `MintedOrder`, cloning a `Clearance`, reading the order key, pairing the
//! clearance of one intent with the grant of another) are in
//! `crates/chitala-boundary` (doctests and unit tests).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chitala_adapters::host::AdapterHost;
use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::{AdapterError, Simulation};
use chitala_audit::AuditLog;
use chitala_boundary::{context_digest, TrustedExecutionBoundary};
use chitala_csme::order::{payload_digest, ExecOrder, ExecutionReceipt};
use chitala_identity::{test_seed, Keypair};
use chitala_intent::{Approval, Intent, Verdict};
use chitala_model::{payload, CapabilityId, DenyCode, EntityId, ExecCode, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::executor::{Executed, Executor, Session};
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response, Step};
use chitala_resource::ResourceId;
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
fn key(s: &str) -> Keypair {
    Keypair::from_seed(&test_seed(s))
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

type Forgery = Box<dyn Fn(&mut Executed) + Send + Sync>;

/// A real adapter host (mock devices, real order gate) behind an executor that
/// keeps every order it is handed.
struct Tap {
    host: Mutex<AdapterHost>,
    session: Session,
    sent: Mutex<Vec<(EntityId, Vec<u8>)>>,
    /// Keep orders without executing them.
    hold: AtomicBool,
    /// Make the host lie about what it did.
    forge: Mutex<Option<Forgery>>,
}

impl Tap {
    fn new(boundary: &TrustedExecutionBoundary, executor: [u8; 16], clock: chitala_node::Clock) -> Arc<Self> {
        let mut mock = MockAdapter::new();
        for d in sample_devices() {
            mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).unwrap());
        }
        let host = AdapterHost::new(boundary.order_key(), executor, vec![Box::new(mock)], clock);
        Arc::new(Self {
            host: Mutex::new(host),
            session: Session { executor, order_key: boundary.order_key() },
            sent: Mutex::new(Vec::new()),
            hold: AtomicBool::new(false),
            forge: Mutex::new(None),
        })
    }

    /// Hand raw order bytes to the adapter host, as an attacker on the channel would.
    fn deliver(&self, device: &str, bytes: &[u8]) -> Result<(Payload, ExecutionReceipt), AdapterError> {
        self.host.lock().unwrap().execute(&id(device), bytes)
    }

    fn last_order(&self) -> Vec<u8> {
        self.sent.lock().unwrap().last().expect("an order was minted").1.clone()
    }

    fn forge(&self, f: impl Fn(&mut Executed) + Send + Sync + 'static) {
        *self.forge.lock().unwrap() = Some(Box::new(f));
    }
}

impl Executor for Tap {
    fn manages(&self, device: &EntityId) -> bool {
        self.host.lock().unwrap().manages(device)
    }
    fn session(&self, device: &EntityId) -> Option<Session> {
        self.manages(device).then_some(self.session)
    }
    fn execute(&self, device: &EntityId, order: chitala_boundary::MintedOrder) -> Result<Executed, AdapterError> {
        self.sent.lock().unwrap().push((device.clone(), order.bytes().to_vec()));
        if self.hold.load(Ordering::SeqCst) {
            return Err(AdapterError::Unavailable("held by the test".into()));
        }
        let (state, receipt) = self.host.lock().unwrap().execute(device, order.bytes())?;
        let mut executed = Executed::reported(state, Some(receipt));
        if let Some(f) = self.forge.lock().unwrap().as_ref() {
            f(&mut executed);
        }
        Ok(executed)
    }
    fn observe(&self, device: &EntityId) -> Result<chitala_adapters::Observed, AdapterError> {
        self.host.lock().unwrap().observe(device)
    }
    fn simulate(&self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        self.host.lock().unwrap().simulate(device, change)
    }
}

struct Home {
    node: Node,
    tap: Arc<Tap>,
    order_key: chitala_identity::PublicKey,
    clock: Arc<AtomicU64>,
}

fn clock_at(t: &Arc<AtomicU64>) -> chitala_node::Clock {
    let c = Arc::clone(t);
    Arc::new(move || c.load(Ordering::SeqCst))
}

fn home_at(clock: Arc<AtomicU64>) -> Home {
    home_with(clock, sample_resources())
}

fn home_with(clock: Arc<AtomicU64>, resources: Vec<chitala_resource::Resource>) -> Home {
    let boundary = TrustedExecutionBoundary::new(entropy());
    let order_key = boundary.order_key();
    let tap = Tap::new(&boundary, [0xA1; 16], clock_at(&clock));
    let principals = [("person:alice", "owner"), ("person:bob", "adult"), ("ai:assistant", "")]
        .into_iter()
        .map(|(p, r)| (id(p), key(p).public_key(), if r.is_empty() { vec![] } else { vec![r.to_string()] }))
        .collect();
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: key("service:node"),
        authority_key: key("domain:home/authority"),
        principals,
        agency: vec![(id("ai:assistant"), vec![id("person:alice")])],
        devices: sample_devices(),
        resources,
        safety: Default::default(),
        executor: tap.clone(),
        policy: chitala_node::PolicySource::Default,
        audit: AuditLog::in_memory(None),
        state: chitala_node::DomainState::default(),
        state_file: None,
        containment: ContainmentConfig::default(),
        monitor: MonitorConfig::default(),
        entropy: entropy(),
        clock: clock_at(&clock),
        clock_watch: None,
        boundary,
    })
    .unwrap();
    Home { node, tap, order_key, clock }
}

fn home() -> Home {
    home_at(Arc::new(AtomicU64::new(T0)))
}

impl Home {
    fn tick(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn signed(&self, who: &str, target: &str, capability: &str, pl: Payload, token: Option<&[u8]>) -> Vec<u8> {
        let r = Requester::new(id(who), key(who), id("service:test"), entropy()).with_token(token.map(<[u8]>::to_vec));
        r.sign(self.node.registry(), &id(target), &cap(capability), pl, self.node.now())
    }

    fn req(&mut self, who: &str, target: &str, capability: &str, pl: Payload) -> Response {
        let bytes = self.signed(who, target, capability, pl, None);
        self.tick(1);
        self.node.handle(&bytes)
    }

    fn intent_of(&self, resource: &str, capability: &str, token: Option<&[u8]>) -> Intent {
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id("ai:assistant"),
            id("person:alice"),
            cap(capability),
            ResourceId::parse(resource).unwrap(),
            self.node.now(),
            60_000,
        );
        i.authority = token.map(<[u8]>::to_vec);
        i
    }

    fn submit_intent(&mut self, i: &Intent) -> Response {
        self.tick(1);
        self.node.handle(&i.sign(&key("ai:assistant")))
    }

    /// Alice delegates `capability` on `target` to her AI; returns (token, revocation id).
    fn delegate(&mut self, target: &str, capability: &str) -> (Vec<u8>, String) {
        let pl = payload([
            ("holder", ParamValue::from("ai:assistant")),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(capability)),
            ("ttl_s", ParamValue::Int(600)),
        ]);
        let r = self.req("person:alice", "domain:home", "domain.delegate", pl);
        assert!(r.is_ok(), "{}", r.summary());
        let res = r.result.unwrap();
        (bytes_from_base64(res["token"].as_str().unwrap()).unwrap(), res["revocation_id"].as_str().unwrap().to_string())
    }

    fn approve(&mut self, i: &Intent, digest: [u8; 32]) -> Response {
        let now = self.node.now();
        let a = Approval {
            intent: i.id,
            intent_digest: digest,
            approver: id("person:alice"),
            verdict: Verdict::Approve,
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            note: None,
        };
        self.tick(1);
        self.node.handle(&a.sign(&key("person:alice")))
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
}

fn deny_code(r: &Response) -> DenyCode {
    assert!(!r.is_allow(), "expected deny, got {}", r.summary());
    r.code.unwrap()
}

fn exec_code(r: &Response) -> ExecCode {
    assert!(r.is_allow(), "expected an allowed request, got {}", r.summary());
    r.error.as_ref().unwrap_or_else(|| panic!("expected an execution error, got {}", r.summary())).code
}

// ───────────────────────── the single path, with provenance ─────────────────────────

/// A person's request and an AI's intent take the same path, and the audit log
/// ties each order to its decision and each receipt to its order.
#[test]
fn every_physical_action_is_one_order_with_a_verified_receipt() {
    let mut h = home();
    // a person's direct request
    assert!(h.req("person:alice", LIGHT, "light.turn_on", Payload::new()).is_ok());
    let human_order = ExecOrder::open(&h.tap.last_order(), &h.order_key).unwrap();
    assert_eq!(human_order.resource, id(LIGHT_R), "requests are cleared on their governed resource");
    // an AI's intent
    let (token, _) = h.delegate(LIGHT_R, "light.turn_off");
    let i = h.intent_of(LIGHT_R, "light.turn_off", Some(&token));
    assert!(h.submit_intent(&i).is_ok());
    let ai_order = ExecOrder::open(&h.tap.last_order(), &h.order_key).unwrap();
    assert_eq!((ai_order.subject, ai_order.subject_digest), (i.id, i.digest()));
    assert_eq!(h.reported(LIGHT, "on"), Some(ParamValue::Bool(false)));

    // provenance: decision record → order → receipt → execution record
    let decisions = h.records("decision");
    let executions = h.records("execution");
    for order in [&human_order, &ai_order] {
        let decision = decisions.iter().find(|d| d["seq"] == order.evidence_seq).expect("the evidence exists");
        assert_eq!(decision["safety"], "cleared");
        assert_eq!(context_digest(&decision["context"]), order.context_digest, "context digest");
        let exec =
            executions.iter().find(|e| e["order"] == hex::encode(order.id)).expect("the execution names its order");
        assert_eq!(exec["outcome"], "ok");
        assert_eq!(exec["decision_seq"], order.evidence_seq);
        assert!(exec["receipt"]["state_digest"].is_string(), "the verified receipt is on the record");
    }
}

// ───────────────────────── 1. replay ─────────────────────────

#[test]
fn a_replayed_order_is_refused() {
    let mut h = home();
    assert!(h.req("person:alice", LIGHT, "light.turn_on", Payload::new()).is_ok());
    let order = h.tap.last_order();
    let err = h.tap.deliver(LIGHT, &order).unwrap_err();
    assert!(matches!(&err, AdapterError::Rejected(m) if m.contains("already executed")), "{err}");
}

// ───────────────────────── 2. expiry ─────────────────────────

#[test]
fn an_order_delivered_after_its_ttl_is_refused() {
    let mut h = home();
    h.tap.hold.store(true, Ordering::SeqCst);
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    assert_eq!(exec_code(&r), ExecCode::DeviceUnavailable, "the order was held back");
    let order = h.tap.last_order();
    h.tick(chitala_csme::order::ORDER_TTL_MS + 1);
    let err = h.tap.deliver(LIGHT, &order).unwrap_err();
    assert!(matches!(&err, AdapterError::Rejected(m) if m.contains("expired")), "{err}");
    assert_ne!(h.reported(LIGHT, "on"), Some(ParamValue::Bool(true)), "nothing happened");
}

// ───────────────────────── 3. parameters changed after the decision ─────────────────────────

#[test]
fn parameters_cannot_change_after_the_decision() {
    let mut h = home();
    let pl = payload([("brightness_pct", 10i64)]);
    assert!(h.req("person:alice", LIGHT, "light.set_brightness", pl).is_ok());
    let order = h.tap.last_order();
    // flip bytes of the signed order: it no longer verifies
    let mut tampered = order.clone();
    let at = tampered.len() - 70;
    tampered[at] ^= 0x01;
    assert!(matches!(h.tap.deliver(LIGHT, &tampered), Err(AdapterError::Rejected(_))));

    // a human approved one intent; the AI cannot have another one executed under it
    let (token, _) = h.delegate(DOOR_R, "lock.unlock");
    let i = h.intent_of(DOOR_R, "lock.unlock", Some(&token));
    assert!(h.submit_intent(&i).is_escalated());
    let mut changed = i.clone();
    changed.context.purpose = Some("let everyone in".into());
    let r = h.approve(&i, changed.digest());
    assert_eq!(deny_code(&r), DenyCode::ApprovalInvalid);
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)), "the door stays locked");
}

// ───────────────────────── 4. resource / device changed ─────────────────────────

#[test]
fn an_order_cannot_be_redirected_to_another_device() {
    let mut h = home();
    h.tap.hold.store(true, Ordering::SeqCst);
    let _ = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    let order = h.tap.last_order();
    let err = h.tap.deliver(DOOR, &order).unwrap_err();
    assert!(matches!(&err, AdapterError::Rejected(m) if m.contains("not device:front-door")), "{err}");
}

// ───────────────────────── 5. authority changes between decision and execution ─────────────────────────

#[test]
fn a_revocation_after_the_decision_stops_the_order() {
    let mut h = home();
    let (token, rid) = h.delegate(LIGHT_R, "light.turn_on");
    let i = h.intent_of(LIGHT_R, "light.turn_on", Some(&token));
    let bytes = i.sign(&key("ai:assistant"));
    h.tick(1);
    // phase 1: decided, cleared, minted
    let Step::Device(mut pending) = h.node.begin(&bytes) else { panic!("expected a device step") };
    // meanwhile (the node lock is free during phase 2) the owner revokes the token
    let revoke = h.signed(
        "person:alice",
        "domain:home",
        "domain.revoke_token",
        payload([("revocation_id", rid.as_str())]),
        None,
    );
    assert!(h.node.handle(&revoke).is_ok());
    // phase 2: the order is not sent, because the decision is out of date
    let outcome = pending.run();
    assert!(matches!(&outcome, Err(AdapterError::Rejected(m)) if m.contains("authority changed")), "{outcome:?}");
    let r = h.node.finish(pending, outcome);
    assert_eq!(exec_code(&r), ExecCode::OrderRejected);
    assert!(h.tap.sent.lock().unwrap().is_empty(), "nothing reached the adapter host");
    assert_ne!(h.reported(LIGHT, "on"), Some(ParamValue::Bool(true)));
}

/// A revocation after the fence and before the device acts (spec 19). The
/// order passed the fence and left the node; here it is held on its way to
/// the adapter host. The revocation does not reach it: the adapter host's
/// gate knows nothing of authority, and carries the order out within its
/// lifetime. Only the lifetime bounds it (`an_order_delivered_after_its_ttl_is_refused`).
///
/// The tap models a hostile or slow channel: it reports the order as not
/// delivered, then hands its bytes to the gate. This shows what the gate does
/// with an order that arrives after a revocation. It is no evidence of how
/// the production transport classifies such an order.
#[test]
fn a_revocation_after_the_fence_does_not_reach_an_order_on_its_way() {
    let mut h = home();
    let (token, _) = h.delegate(LIGHT_R, "light.turn_on");
    h.tap.hold.store(true, Ordering::SeqCst);
    let i = h.intent_of(LIGHT_R, "light.turn_on", Some(&token));
    let r = h.submit_intent(&i);
    assert_eq!(exec_code(&r), ExecCode::DeviceUnavailable, "past the fence, held on its way: {}", r.summary());
    let order = h.tap.last_order();
    let r = h.req("person:alice", "domain:home", "domain.revoke_all", Payload::new());
    assert!(r.is_ok(), "{}", r.summary());
    let (state, _) = h.tap.deliver(LIGHT, &order).expect("the gate accepts it within its lifetime");
    assert_eq!(state.get("on"), Some(&ParamValue::Bool(true)), "carried out after the revocation");
}

#[test]
fn a_revocation_while_a_human_decides_voids_the_approval() {
    let mut h = home();
    let (token, rid) = h.delegate(DOOR_R, "lock.unlock");
    let i = h.intent_of(DOOR_R, "lock.unlock", Some(&token));
    assert!(h.submit_intent(&i).is_escalated());
    let r = h.req("person:alice", "domain:home", "domain.revoke_token", payload([("revocation_id", rid.as_str())]));
    assert!(r.is_ok());
    let r = h.approve(&i, i.digest());
    assert_eq!(deny_code(&r), DenyCode::TokenRevoked, "approval re-runs Authority");
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
}

// ───────────────────────── 7. two executors, one order ─────────────────────────

#[test]
fn one_order_is_executed_by_one_executor_once() {
    let mut h = home();
    assert!(h.req("person:alice", LIGHT, "light.turn_on", Payload::new()).is_ok());
    let order = h.tap.last_order();
    // a second adapter host with the same order key and the same devices,
    // but another instance: it refuses the order
    let boundary_like = h.order_key;
    let mut mock = MockAdapter::new();
    for d in sample_devices() {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).unwrap());
    }
    let mut other = AdapterHost::new(boundary_like, [0xB2; 16], vec![Box::new(mock)], clock_at(&h.clock));
    let err = other.execute(&id(LIGHT), &order).unwrap_err();
    assert!(matches!(&err, AdapterError::Rejected(m) if m.contains("another adapter host instance")), "{err}");
    // and the instance it was for executes it only once
    assert!(h.tap.deliver(LIGHT, &order).is_err());
}

// ───────────────────────── 8. restart, then replay ─────────────────────────

#[test]
fn orders_die_with_the_node_that_minted_them() {
    let clock = Arc::new(AtomicU64::new(T0));
    let mut before = home_at(Arc::clone(&clock));
    before.tap.hold.store(true, Ordering::SeqCst);
    let _ = before.req("person:alice", DOOR, "lock.unlock", Payload::new());
    let order = before.tap.last_order();
    drop(before);
    // the node restarts within the order's lifetime: new boundary, new order key
    let after = home_at(clock);
    let err = after.tap.deliver(DOOR, &order).unwrap_err();
    assert!(matches!(&err, AdapterError::Rejected(m) if m.contains("order key")), "{err}");
    assert_eq!(after.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
}

// ───────────────────────── 9. forged receipts ─────────────────────────

#[test]
fn a_lying_adapter_host_is_not_believed() {
    let cases: Vec<(&str, Forgery)> = vec![
        ("no receipt", Box::new(|e: &mut Executed| e.receipt = None)),
        ("another order", Box::new(|e: &mut Executed| e.receipt.as_mut().unwrap().order[0] ^= 1)),
        ("other order bytes", Box::new(|e: &mut Executed| e.receipt.as_mut().unwrap().order_digest[0] ^= 1)),
        ("another instance", Box::new(|e: &mut Executed| e.receipt.as_mut().unwrap().executor = [0; 16])),
        ("another device", Box::new(|e: &mut Executed| e.receipt.as_mut().unwrap().device = id(DOOR))),
        // the host reports a state its receipt does not vouch for
        ("another state", Box::new(|e: &mut Executed| e.state = payload([("on", false)]))),
    ];
    for (what, forgery) in cases {
        let mut h = home();
        h.tap.forge(forgery);
        let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
        assert_eq!(exec_code(&r), ExecCode::ReceiptInvalid, "{what}");
        let exec = h.records("execution").pop().unwrap();
        assert!(exec["receipt_error"].is_string(), "{what}: the lie is on the record");
        // the report is not believed; the witness, observed on its own, tells
        // whether the action took effect anyway (spec 22)
        let outcome = r.outcome.as_ref().unwrap();
        assert_eq!(outcome["status"], "applied", "{what}");
        assert_eq!(exec["verification"]["status"], "applied", "{what}");
        assert_eq!(h.reported(LIGHT, "on"), Some(ParamValue::Bool(true)), "{what}: what the witness observed");
    }
}

// ───────────────────────── 10. no way around the boundary ─────────────────────────

#[test]
fn the_node_identity_key_cannot_command_a_device() {
    let mut h = home();
    h.tap.hold.store(true, Ordering::SeqCst);
    let _ = h.req("person:alice", LIGHT, "light.turn_on", Payload::new());
    // re-sign a genuine order with the node's identity key — the strongest key
    // node code holds — and it is still not an order
    let order = ExecOrder::open(&h.tap.last_order(), &h.order_key).unwrap();
    let forged = order.sign(&key("service:node"));
    let err = h.tap.deliver(LIGHT, &forged).unwrap_err();
    assert!(matches!(&err, AdapterError::Rejected(m) if m.contains("order key")), "{err}");
    // nor is a hand-made order with a matching digest
    let mut made = order.clone();
    made.id = [9; 16];
    made.params = payload([("brightness_pct", 100i64)]);
    made.params_digest = payload_digest(&made.params);
    assert!(h.tap.deliver(LIGHT, &made.sign(&key("service:node"))).is_err());
}

#[test]
fn the_node_process_has_no_device_io() {
    let dir = std::env::temp_dir().join(format!("chitala-tebio-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    chitala_node::hosted::init_domain(&dir).unwrap();
    let loaded = chitala_node::LoadedConfig::load(dir.join(chitala_node::setup::CONFIG_FILE)).unwrap();
    let platform = loaded.platform().unwrap();
    // device I/O belongs to adapter hosts; the node's platform cannot open anything
    for a in ["serial:ttyusb0", "gpio:door-strike", "i2c:relay"] {
        let address = chitala_platform::DeviceAddress::new(a).unwrap();
        assert!(platform.devices.open(&address).is_err(), "{a}");
    }
    assert!(platform.devices.devices().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn safety_applies_to_people_too() {
    let mut h = home();
    // SAFE-6: an owner cannot make the lock oscillate either
    let mut refused = None;
    for n in 0..10 {
        let cap = if n % 2 == 0 { "lock.unlock" } else { "lock.lock" };
        let r = h.req("person:alice", DOOR, cap, Payload::new());
        if !r.is_allow() {
            refused = Some(r);
            break;
        }
    }
    let r = refused.expect("the rate rule refused at some point");
    assert_eq!(deny_code(&r), DenyCode::Safety);
    assert!(r.reason.unwrap().contains("SAFE-6-RATE"));
}

#[test]
fn an_ungoverned_device_is_never_actuated() {
    // the fan plug is enrolled, but no governed resource binds it: Safety has
    // nothing to check it against, so nobody — not even the owner — actuates it
    let resources = sample_resources().into_iter().filter(|r| r.id.as_entity().local() != "fan").collect();
    let mut h = home_with(Arc::new(AtomicU64::new(T0)), resources);
    let r = h.req("person:alice", "device:fan-plug", "switch.turn_on", Payload::new());
    assert_eq!(deny_code(&r), DenyCode::Safety);
    assert!(r.reason.unwrap().contains("not bound to a governed resource"));
    assert!(h.tap.sent.lock().unwrap().is_empty(), "no order was minted");
    // reading its state is not an action
    assert!(h.req("person:alice", "device:fan-plug", "device.read_state", Payload::new()).is_ok());
}

// ───────────────────────── restart of an adapter host (memory platform) ─────────────────────────

/// An order minted for one adapter host instance never runs on the next one,
/// whose replay set is empty: a restarted host would otherwise execute it again.
mod adapter_host_restart {
    use super::*;
    use chitala_node::{Domain, NodeConfig, NodeEnv, StoredObject};
    use chitala_platform::memory::{self, Program};
    use chitala_platform::{StoragePath, TimeSource, TrustedClock, Visibility};
    use std::io::{BufRead, BufReader, Write};

    #[test]
    fn a_stale_order_reaching_a_restarted_host_is_refused() {
        let (platform, ctl) = memory::platform("teb-restart", T0);
        let first_order: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let replayed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let instances = Arc::new(AtomicU64::new(0));
        let time: Arc<dyn TimeSource> = Arc::clone(&platform.time);
        let (fo, rp, n) = (Arc::clone(&first_order), Arc::clone(&replayed), Arc::clone(&instances));
        let program: Program = Arc::new(move |input, mut output, _env| {
            let clock = Arc::new(TrustedClock::new(Arc::clone(&time), 0)).as_clock();
            let mut reader = BufReader::new(input);
            let mut init = String::new();
            let _ = reader.read_line(&mut init);
            let Ok(chitala_adapters::host::HostRequest::Init(init)) = serde_json::from_str(init.trim()) else { return };
            let Ok(mut host) = AdapterHost::from_init(init, clock) else { return };
            let _ = writeln!(output, "{{\"ok\":true}}");
            if n.fetch_add(1, Ordering::SeqCst) == 0 {
                // the first instance keeps the first order it gets and dies
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line.contains("\"op\":\"execute\"") {
                        *fo.lock().unwrap() = Some(line);
                        return;
                    }
                    let _ = writeln!(output, "{}", host.handle_line(&line));
                }
            }
            // the restarted instance is handed the stale order before anything else
            if let Some(stale) = fo.lock().unwrap().clone() {
                *rp.lock().unwrap() = Some(host.handle_line(&stale));
            }
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let _ = writeln!(output, "{}", host.handle_line(&line));
            }
        });
        ctl.exec.register("adapter-host", program);
        let summary = chitala_node::setup::init_domain(platform.storage.as_ref(), platform.keys.as_ref()).unwrap();
        let text = platform.storage.read(&summary.config, Visibility::Shared).unwrap().unwrap();
        let config: NodeConfig = serde_json::from_slice(&text).unwrap();
        let stored = |p: &str| StoredObject::new(Arc::clone(&platform.storage), StoragePath::new(p).unwrap());
        let env = NodeEnv {
            audit_log: stored(&config.audit_log),
            state_file: stored(&config.state_file),
            policy_file: None,
            adapter_host: "adapter-host".into(),
            home_assistant_env: Vec::new(),
            history_evaluator: None,
        };
        let domain = Domain { config, platform, endpoint: chitala_platform::Endpoint::new("node").unwrap() };
        let mut node = chitala_node::start_node(&domain, &env).unwrap();
        let alice = Requester::new(
            id("person:alice"),
            domain.keypair(&id("person:alice")).unwrap(),
            id("service:cli"),
            Arc::clone(&domain.platform.entropy),
        );
        let send = |node: &mut Node, c: &str| {
            ctl.time.advance(10);
            let bytes = alice.sign(node.registry(), &id(LIGHT), &cap(c), Payload::new(), node.now());
            node.handle(&bytes)
        };
        // the first instance takes the order and dies before it answers: it may
        // have acted, and the node cannot tell (R1 of the concurrency audit)
        let r = send(&mut node, "light.turn_on");
        assert_eq!(exec_code(&r), ExecCode::ExecutionUnknown);
        // a second later the host is restarted (with a new session) for the next request
        ctl.time.advance(chitala_node::executor::MIN_RESPAWN_INTERVAL.as_millis() as u64);
        let r = send(&mut node, "light.turn_off");
        assert!(r.is_ok(), "{}", r.summary());
        let replay = replayed.lock().unwrap().clone().expect("the restarted host saw the stale order");
        assert!(replay.contains("X_ORDER_REJECTED") && replay.contains("another adapter host instance"), "{replay}");
        assert_eq!(instances.load(Ordering::SeqCst), 2);
    }
}
