//! v0.2 release-candidate audit: the attack matrix (docs/audit/v0.2-rc-audit.md).
//! Intersections that tests of one feature at a time miss: one resource
//! through two devices, plans and leases meeting holds, recovery and unknown
//! executions. Each test was written red first where it found a gap.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_model::{CapabilityId, DenyCode, DeviceDescriptor, EntityId, Payload, SecurityClass};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response, Step};
use chitala_resource::{CapabilityBinding, Resource};

const T0: u64 = 1_790_000_000_000;
const DOOR: &str = "device:front-door";
const MOTOR: &str = "device:door-motor";

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
