//! A home with a simulated ground robot (spec 30), for the robot suites
//! (specs 30, 31): the sample home, the robot in its living room, owners,
//! a guest and AIs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::robot_sim::RobotSim;
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::Intent;
use chitala_model::{payload, ParamValue, Payload, Pose};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources, sample_robot};
use chitala_node::{Node, NodeParts, Requester, Response};
use chitala_resource::{Resource, ResourceId};
use chitala_token::bytes_from_base64;
use serde_json::Value;

pub use super::{cap, entropy, id, T0};

pub const ROBOT: &str = "device:robot";
pub const ROBOT_R: &str = "resource:robot";

const PEOPLE: [(&str, &[&str], &[&str]); 4] = [
    ("person:alice", &["owner"], &[]),
    ("person:guest", &["guest"], &[]),
    ("ai:assistant", &[], &["person:alice"]),
    ("ai:other", &[], &["person:alice"]),
];

pub fn robot() -> Resource {
    sample_robot().1
}

pub struct Home {
    pub node: Node,
    pub clock: Arc<AtomicU64>,
    pub sim: RobotSim,
    pub keys: std::collections::HashMap<String, Keypair>,
}

pub fn home() -> Home {
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let sim = RobotSim::new(Arc::new(move || c.load(Ordering::SeqCst)));
    sim.add(id(ROBOT), Pose::new(0, 0, 0));
    let mut h = start(sim, clock, chitala_node::DomainState::default());
    h.pass(100);
    h
}

/// The node crashes and starts again on the same robot, with the domain
/// state it had persisted (through JSON, as on disk); its clock goes on
/// from where it was.
pub fn restart(h: Home) -> Home {
    let Home { node, clock, sim, .. } = h;
    let saved = serde_json::to_string(node.domain_state()).unwrap();
    let state: chitala_node::DomainState = serde_json::from_str(&saved).unwrap();
    drop(node);
    clock.fetch_add(2_000, Ordering::SeqCst);
    start(sim, clock, state)
}

fn start(sim: RobotSim, clock: Arc<AtomicU64>, state: chitala_node::DomainState) -> Home {
    let c = Arc::clone(&clock);
    let node_clock: chitala_node::Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let mut keys = std::collections::HashMap::new();
    let (mut principals, mut agency) = (Vec::new(), Vec::new());
    for (who, roles, serves) in PEOPLE {
        let k = Keypair::from_seed(&test_seed(who));
        principals.push((id(who), k.public_key(), roles.iter().map(|r| r.to_string()).collect()));
        if !serves.is_empty() {
            agency.push((id(who), serves.iter().map(|p| id(p)).collect()));
        }
        keys.insert(who.to_string(), k);
    }
    let mut mock = MockAdapter::new();
    for d in sample_devices() {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).unwrap());
    }
    let (descriptor, resource) = sample_robot();
    let mut devices = sample_devices();
    devices.push(descriptor);
    let mut resources = sample_resources();
    resources.push(resource);
    let boundary = TrustedExecutionBoundary::new(entropy());
    let adapters: Vec<Box<dyn chitala_adapters::DeviceAdapter>> = vec![Box::new(mock), Box::new(sim.clone())];
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: Keypair::from_seed(&test_seed("service:node")),
        authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
        principals,
        agency,
        devices,
        resources,
        safety: Default::default(),
        executor: chitala_node::executor::in_process(&boundary, adapters, node_clock.clone()),
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
    Home { node, clock, sim, keys }
}

pub fn ints(params: &[(&str, i64)]) -> Payload {
    params.iter().map(|(k, v)| (k.to_string(), ParamValue::Int(*v))).collect()
}

impl Home {
    /// Time passes, and the node observes what is due.
    pub fn pass(&mut self, ms: u64) {
        let mut left = ms;
        while left > 0 {
            let step = left.min(200);
            self.clock.fetch_add(step, Ordering::SeqCst);
            self.node.tick();
            left -= step;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    pub fn req(&mut self, who: &str, target: &str, c: &str, pl: Payload) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now());
        self.clock.fetch_add(1, Ordering::SeqCst);
        self.node.handle(&bytes)
    }

    /// The owner, on the robot.
    pub fn owner(&mut self, c: &str, params: &[(&str, i64)]) -> Response {
        self.req("person:alice", ROBOT, c, ints(params))
    }

    pub fn delegate(&mut self, holder: &str, target: &str, c: &str) -> Vec<u8> {
        let pl = payload([
            ("holder", ParamValue::from(holder)),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(c)),
            ("ttl_s", ParamValue::Int(3600)),
        ]);
        let r = self.req("person:alice", "domain:home", "domain.delegate", pl);
        assert!(r.is_ok(), "{}", r.summary());
        bytes_from_base64(r.result.unwrap()["token"].as_str().unwrap()).unwrap()
    }

    pub fn ai(&mut self, ai: &str, c: &str, params: &[(&str, i64)], token: Option<&[u8]>) -> Response {
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id(ai),
            id("person:alice"),
            cap(c),
            ResourceId::parse(ROBOT_R).unwrap(),
            self.node.now(),
            120_000,
        );
        i.params = ints(params);
        i.authority = token.map(<[u8]>::to_vec);
        let bytes = i.sign(&self.keys[ai]);
        self.clock.fetch_add(1, Ordering::SeqCst);
        self.node.handle(&bytes)
    }

    /// Every outcome judged: settled later (`outcome` records), or at once
    /// (an execution's `verification`).
    pub fn outcomes(&self) -> Vec<Value> {
        self.node
            .audit()
            .lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter_map(|v| match v["kind"].as_str() {
                Some("outcome") => Some(v),
                Some("execution") if v["verification"]["status"] != "pending" => Some(v["verification"].clone()),
                _ => None,
            })
            .filter(|v| !v.is_null())
            .collect()
    }

    pub fn last_outcome(&self) -> Value {
        self.outcomes().pop().unwrap_or(Value::Null)
    }

    pub fn in_recovery(&self) -> bool {
        self.node.domain_state().recovery.contains_key(&ResourceId::parse(ROBOT_R).unwrap())
    }

    pub fn settle(&mut self) {
        for _ in 0..600 {
            if self.node.pending_outcomes().is_empty() {
                return;
            }
            self.pass(100);
        }
        panic!("outcomes still pending: {:?}", self.node.pending_outcomes());
    }
}

/// Refused by Safety, by `rule`.
pub fn refused_by(r: &Response, rule: &str) -> bool {
    !r.is_ok() && r.summary().contains(rule)
}

impl Home {
    /// The owner ends the robot's recovery, or its hold.
    pub fn release(&mut self) -> Response {
        let release = payload([("resource", ParamValue::from(ROBOT_R))]);
        self.req("person:alice", "domain:home", "domain.safety_release", release)
    }
}
