//! The node with one adapter, for the suites that put an adapter through
//! the whole chain (specs 26, 28): one front door, its lock driven by a rig's
//! adapter, its safe state locked.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chitala_adapters::conformance::Rig;
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_model::{CapabilityId, DeviceDescriptor, EntityId, ExecCode, Payload, SecurityClass};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::{Node, NodeParts, Requester, Response};
use chitala_resource::{Boundary, CapabilityBinding, Resource, ResourceId, ResourceKind, SafeState, StateRef};
use serde_json::Value;

pub const T0: u64 = 1_790_000_000_000;

pub fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
pub fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
pub fn rid(s: &str) -> ResourceId {
    ResourceId::new(s).unwrap()
}
pub fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

/// A home with one front door, its lock driven by the rig's adapter, its
/// safe state locked (spec 24); more doors, one per further rig.
pub struct Home {
    pub rig: Box<dyn Rig>,
    /// Further doors' rigs: door `door-2`, `door-3`, …
    pub others: Vec<Box<dyn Rig>>,
    pub node: Node,
    pub clock: Arc<AtomicU64>,
    pub alice: Keypair,
    pub max_age_ms: u64,
}

pub fn home(rig: Box<dyn Rig>) -> Home {
    home_with(rig, 120_000)
}

/// A home whose doors' state is relied on for at most `max_age_ms`.
pub fn home_with(rig: Box<dyn Rig>, max_age_ms: u64) -> Home {
    start(rig, Vec::new(), max_age_ms, chitala_node::DomainState::default(), T0)
}

/// A home with a door for each rig (their locks must have distinct ids).
pub fn home_of(rig: Box<dyn Rig>, others: Vec<Box<dyn Rig>>) -> Home {
    start(rig, others, 120_000, chitala_node::DomainState::default(), T0)
}

/// The node crashes and starts again on the same devices, with the domain
/// state it had persisted; its clock goes on from where it was.
pub fn restart(h: Home) -> Home {
    let Home { rig, others, node, max_age_ms, .. } = h;
    let state = node.domain_state().clone();
    let now = node.now() + 2_000;
    drop(node);
    start(rig, others, max_age_ms, state, now)
}

/// The resource id of the door a rig's lock is at: the first rig's is the
/// front door, the next ones `door-2`, `door-3`, …
pub fn door(index: usize) -> String {
    if index == 0 {
        "front-door".into()
    } else {
        format!("door-{}", index + 1)
    }
}

fn door_of(index: usize, lock: &EntityId, max_age_ms: u64) -> Resource {
    let caps = ["lock.lock", "lock.unlock"];
    Resource {
        id: rid(&door(index)),
        kind: ResourceKind::Door,
        name: door(index),
        parent: Some(rid("home")),
        owners: vec![],
        boundary: Boundary::Interior,
        zone: None,
        bindings: caps
            .iter()
            .map(|c| CapabilityBinding { capability: cap(c), device: lock.clone(), risk_floor: None })
            .collect(),
        state: Some(StateRef { device: lock.clone(), max_age_ms }),
        envelope: vec![],
        two_key: false,
        safe_state: Some(SafeState { capability: cap("lock.lock"), params: Payload::new() }),
    }
}

fn start(
    mut rig: Box<dyn Rig>,
    mut others: Vec<Box<dyn Rig>>,
    max_age_ms: u64,
    state: chitala_node::DomainState,
    t0: u64,
) -> Home {
    // the node's clock: the test's own steps plus the real time that passes,
    // as a real clock does (states age in real time, F9)
    let clock = Arc::new(AtomicU64::new(t0));
    let c = Arc::clone(&clock);
    let started = Instant::now();
    let node_clock: chitala_node::Clock =
        Arc::new(move || c.load(Ordering::SeqCst) + u64::try_from(started.elapsed().as_millis()).unwrap_or(0));
    let alice = Keypair::from_seed(&test_seed("person:alice"));
    let boundary = TrustedExecutionBoundary::new(entropy());
    let mut adapters = vec![rig.adapter()];
    let mut devices = Vec::new();
    let mut resources = vec![Resource {
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
    }];
    let rigs: Vec<(EntityId, &'static str)> = std::iter::once((rig.lock(), rig.adapter_name()))
        .chain(others.iter().map(|r| (r.lock(), r.adapter_name())))
        .collect();
    for r in &mut others {
        adapters.push(r.adapter());
    }
    for (index, (lock, adapter)) in rigs.iter().enumerate() {
        devices.push(DeviceDescriptor {
            id: lock.clone(),
            name: format!("{} lock", door(index)),
            adapter: (*adapter).into(),
            room: None,
            security_class: SecurityClass::Sc1,
            capabilities: ["device.read_state", "lock.lock", "lock.unlock"].iter().map(|c| cap(c)).collect(),
        });
        resources.push(door_of(index, lock, max_age_ms));
    }
    let executor = chitala_node::executor::in_process(&boundary, adapters, node_clock.clone());
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: Keypair::from_seed(&test_seed("service:node")),
        authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
        principals: vec![(id("person:alice"), alice.public_key(), vec!["owner".into()])],
        agency: vec![],
        devices,
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
    Home { rig, others, node, clock, alice, max_age_ms }
}

impl Home {
    pub fn name(&self) -> &'static str {
        self.rig.adapter_name()
    }

    pub fn lock(&self) -> EntityId {
        self.rig.lock()
    }

    pub fn req(&mut self, c: &str) -> Response {
        let lock = self.lock();
        self.req_on(&lock, c, Payload::new())
    }

    /// The owner requests `c` on `target`.
    pub fn req_on(&mut self, target: &EntityId, c: &str, params: Payload) -> Response {
        let bytes = self.signed(target, c, params);
        self.node.handle(&bytes)
    }

    /// The owner's signed request for `c` on `target`, not sent yet.
    pub fn signed(&mut self, target: &EntityId, c: &str, params: Payload) -> Vec<u8> {
        let r = Requester::new(id("person:alice"), self.alice.clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), target, &cap(c), params, self.node.now());
        self.clock.fetch_add(1, Ordering::SeqCst);
        bytes
    }

    /// The owner ends the door's recovery.
    pub fn release(&mut self) -> Response {
        let params = chitala_model::payload([("resource", "resource:front-door")]);
        self.req_on(&id("domain:home"), "domain.safety_release", params)
    }

    /// Ticks of the node's server loop, a second of its time apart, while
    /// real time lets the backend answer.
    pub fn ticks_until(&mut self, what: &str, f: impl Fn(&Node) -> bool) {
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
    pub fn idle(&mut self, ticks: usize) {
        for _ in 0..ticks {
            self.clock.fetch_add(1_000, Ordering::SeqCst);
            self.node.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The outcome of the order answered by `r`: in the answer if it was
    /// settled at once, else once the node has settled it.
    pub fn settled(&mut self, r: &Response) -> Value {
        if status(r) != "pending" {
            return r.outcome.clone().unwrap_or(Value::Null);
        }
        self.ticks_until("settled", |n| n.pending_outcomes().is_empty());
        self.last_outcome()
    }

    /// The audit records of `kind`, in order.
    pub fn records(&self, kind: &str) -> Vec<Value> {
        self.node
            .audit()
            .lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| v["kind"] == kind)
            .collect()
    }

    pub fn last_outcome(&self) -> Value {
        self.node
            .audit()
            .lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .rfind(|v| v["kind"] == "outcome")
            .unwrap_or(Value::Null)
    }

    pub fn in_recovery(&self) -> bool {
        self.node.domain_state().recovery.contains_key(&rid("front-door"))
    }

    /// The owner unlocks the door, and it is verified: where every check starts.
    pub fn unlocked(&mut self) {
        let name = self.name();
        let r = self.req("lock.unlock");
        assert!(r.is_ok(), "{name}: {}", r.summary());
        assert_eq!(status(&r), "verified", "{name}: {}", r.summary());
        assert_eq!(self.rig.bolt(), Some(false), "{name}");
    }
}

pub fn status(r: &Response) -> &str {
    r.outcome.as_ref().and_then(|o| o["status"].as_str()).unwrap_or("none")
}

pub fn code(r: &Response) -> Option<ExecCode> {
    r.error.as_ref().map(|e| e.code)
}
