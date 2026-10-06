//! The adapter conformance suite (spec 26), the node's half: every adapter,
//! on its rig, through the whole chain (Authority → Safety → the trusted
//! boundary → the adapter → outcome verification and recovery). Whatever the
//! adapter, Chitala ends with the same judgement of what an order did, and
//! never sends a command twice.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chitala_adapters::conformance::{Fault, HaRig, MatterRig, MockRig, Rig};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_model::{CapabilityId, DeviceDescriptor, EntityId, ExecCode, Payload, SecurityClass};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::{Node, NodeParts, Requester, Response};
use chitala_resource::{Boundary, CapabilityBinding, Resource, ResourceId, ResourceKind, SafeState, StateRef};
use serde_json::{json, Value};

const T0: u64 = 1_790_000_000_000;

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
fn rid(s: &str) -> ResourceId {
    ResourceId::new(s).unwrap()
}
fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

/// A home with one front door, its lock driven by the rig's adapter, its
/// safe state locked (spec 24).
struct Home {
    rig: Box<dyn Rig>,
    node: Node,
    clock: Arc<AtomicU64>,
    alice: Keypair,
}

fn home(mut rig: Box<dyn Rig>) -> Home {
    // the node's clock: the test's own steps plus the real time that passes,
    // as a real clock does (states age in real time, F9)
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let started = Instant::now();
    let node_clock: chitala_node::Clock =
        Arc::new(move || c.load(Ordering::SeqCst) + u64::try_from(started.elapsed().as_millis()).unwrap_or(0));
    let lock = rig.lock();
    let adapter = rig.adapter();
    let alice = Keypair::from_seed(&test_seed("person:alice"));
    let boundary = TrustedExecutionBoundary::new(entropy());
    let executor = chitala_node::executor::in_process(&boundary, vec![adapter], node_clock.clone());
    let caps = ["lock.lock", "lock.unlock"];
    let door = Resource {
        id: rid("front-door"),
        kind: ResourceKind::Door,
        name: "front door".into(),
        parent: Some(rid("home")),
        owners: vec![],
        boundary: Boundary::Interior,
        zone: None,
        bindings: caps
            .iter()
            .map(|c| CapabilityBinding { capability: cap(c), device: lock.clone(), risk_floor: None })
            .collect(),
        state: Some(StateRef { device: lock.clone(), max_age_ms: 120_000 }),
        envelope: vec![],
        two_key: false,
        safe_state: Some(SafeState { capability: cap("lock.lock"), params: Payload::new() }),
    };
    let site = Resource {
        id: rid("home"),
        kind: ResourceKind::Site,
        name: "home".into(),
        parent: None,
        owners: vec![id("person:alice")],
        boundary: Boundary::Interior,
        zone: None,
        bindings: vec![],
        state: None,
        envelope: vec![],
        two_key: false,
        safe_state: None,
    };
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: Keypair::from_seed(&test_seed("service:node")),
        authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
        principals: vec![(id("person:alice"), alice.public_key(), vec!["owner".into()])],
        agency: vec![],
        devices: vec![DeviceDescriptor {
            id: lock,
            name: "front door lock".into(),
            adapter: rig.adapter_name().into(),
            room: None,
            security_class: SecurityClass::Sc1,
            capabilities: ["device.read_state", "lock.lock", "lock.unlock"].iter().map(|c| cap(c)).collect(),
        }],
        resources: vec![site, door],
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
    Home { rig, node, clock, alice }
}

impl Home {
    fn name(&self) -> &'static str {
        self.rig.adapter_name()
    }

    fn lock(&self) -> EntityId {
        self.rig.lock()
    }

    fn req(&mut self, c: &str) -> Response {
        let r = Requester::new(id("person:alice"), self.alice.clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &self.lock(), &cap(c), Payload::new(), self.node.now());
        self.clock.fetch_add(1, Ordering::SeqCst);
        self.node.handle(&bytes)
    }

    /// Ticks of the node's server loop, a second of its time apart, while
    /// real time lets the backend answer.
    fn ticks_until(&mut self, what: &str, f: impl Fn(&Node) -> bool) {
        for _ in 0..400 {
            if f(&self.node) {
                return;
            }
            self.clock.fetch_add(100, Ordering::SeqCst);
            self.node.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("{}: timed out waiting until {what}", self.name());
    }

    /// The node's server loop for a while of real time: nothing is resent.
    fn idle(&mut self, ticks: usize) {
        for _ in 0..ticks {
            self.clock.fetch_add(1_000, Ordering::SeqCst);
            self.node.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The outcome of the order answered by `r`: in the answer if it was
    /// settled at once, else once the node has settled it.
    fn settled(&mut self, r: &Response) -> Value {
        if status(r) != "pending" {
            return r.outcome.clone().unwrap_or(Value::Null);
        }
        self.ticks_until("settled", |n| n.pending_outcomes().is_empty());
        self.last_outcome()
    }

    fn last_outcome(&self) -> Value {
        self.node
            .audit()
            .lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .rfind(|v| v["kind"] == "outcome")
            .unwrap_or(Value::Null)
    }

    fn in_recovery(&self) -> bool {
        self.node.domain_state().recovery.contains_key(&rid("front-door"))
    }

    /// The owner unlocks the door, and it is verified: where every check starts.
    fn unlocked(&mut self) {
        let name = self.name();
        let r = self.req("lock.unlock");
        assert!(r.is_ok(), "{name}: {}", r.summary());
        assert_eq!(status(&r), "verified", "{name}: {}", r.summary());
        assert_eq!(self.rig.bolt(), Some(false), "{name}");
    }
}

fn status(r: &Response) -> &str {
    r.outcome.as_ref().and_then(|o| o["status"].as_str()).unwrap_or("none")
}

fn code(r: &Response) -> Option<ExecCode> {
    r.error.as_ref().map(|e| e.code)
}

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
