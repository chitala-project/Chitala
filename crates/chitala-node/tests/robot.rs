//! A ground robot through the whole chain (Robot Profile v0.1, spec 30): an
//! AI moves it with a token, Safety keeps it inside its limits (SAFE-5,
//! SAFE-9), a stop always wins, and its outcome is a pose within a tolerance.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::robot_sim::{self, Localization, RobotSim};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::Intent;
use chitala_model::{
    payload, CapabilityId, DeviceDescriptor, EntityId, Geofence, ParamValue, Payload, Pose, SecurityClass,
};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response};
use chitala_resource::{
    Boundary, CapabilityBinding, MotionLimits, ParamLimit, Resource, ResourceId, ResourceKind, SafeState, StateRef,
};
use chitala_token::bytes_from_base64;
use serde_json::Value;

const T0: u64 = 1_790_000_000_000;
const ROBOT: &str = "device:robot";
const ROBOT_R: &str = "resource:robot";

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}

fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}

fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

const PEOPLE: [(&str, &[&str], &[&str]); 4] = [
    ("person:alice", &["owner"], &[]),
    ("person:guest", &["guest"], &[]),
    ("ai:assistant", &[], &["person:alice"]),
    ("ai:other", &[], &["person:alice"]),
];

/// The robot in the living room: a 5 m × 4 m geofence around the origin's
/// corner, at most 800 mm/s and 90°/s, a pose at most 1 s old; its safe
/// state is a stop.
fn robot() -> Resource {
    let device = id(ROBOT);
    let limit = |c: &str, param: &str, min, max| ParamLimit { capability: cap(c), param: param.into(), min, max };
    Resource {
        id: ResourceId::parse(ROBOT_R).unwrap(),
        kind: ResourceKind::Robot,
        name: "Robot".into(),
        parent: Some(ResourceId::parse("resource:living-room").unwrap()),
        owners: vec![],
        boundary: Boundary::default(),
        zone: None,
        bindings: robot_sim::capabilities()
            .into_iter()
            .map(|capability| CapabilityBinding { capability, device: device.clone(), risk_floor: None })
            .collect(),
        state: Some(StateRef { device, max_age_ms: 2_000 }),
        envelope: vec![
            limit("robot.move_linear", "speed_mm_s", 50, 800),
            limit("robot.goto_pose", "speed_mm_s", 50, 800),
            limit("robot.rotate", "speed_mdeg_s", 5_000, 90_000),
        ],
        two_key: false,
        safe_state: Some(SafeState { capability: cap("robot.stop"), params: Payload::new() }),
        motion: Some(MotionLimits {
            geofence: Geofence(vec![[-1_000, -1_000], [4_000, -1_000], [4_000, 3_000], [-1_000, 3_000]]),
            max_localization_age_ms: 1_000,
        }),
    }
}

struct Home {
    node: Node,
    clock: Arc<AtomicU64>,
    sim: RobotSim,
    keys: std::collections::HashMap<String, Keypair>,
}

fn home() -> Home {
    let clock = Arc::new(AtomicU64::new(T0));
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
    let sim = RobotSim::new(Arc::clone(&node_clock));
    sim.add(id(ROBOT), Pose::new(0, 0, 0));
    let mut devices = sample_devices();
    devices.push(DeviceDescriptor {
        id: id(ROBOT),
        name: "Robot".into(),
        adapter: robot_sim::ADAPTER.into(),
        capabilities: robot_sim::capabilities(),
        security_class: SecurityClass::Sc2,
        room: Some("living-room".into()),
    });
    let mut resources = sample_resources();
    resources.push(robot());
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
    let mut h = Home { node, clock, sim, keys };
    h.pass(100);
    h
}

fn ints(params: &[(&str, i64)]) -> Payload {
    params.iter().map(|(k, v)| (k.to_string(), ParamValue::Int(*v))).collect()
}

impl Home {
    /// Time passes, and the node observes what is due.
    fn pass(&mut self, ms: u64) {
        let mut left = ms;
        while left > 0 {
            let step = left.min(200);
            self.clock.fetch_add(step, Ordering::SeqCst);
            self.node.tick();
            left -= step;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    fn req(&mut self, who: &str, target: &str, c: &str, pl: Payload) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now());
        self.clock.fetch_add(1, Ordering::SeqCst);
        self.node.handle(&bytes)
    }

    /// The owner, on the robot.
    fn owner(&mut self, c: &str, params: &[(&str, i64)]) -> Response {
        self.req("person:alice", ROBOT, c, ints(params))
    }

    fn delegate(&mut self, holder: &str, target: &str, c: &str) -> Vec<u8> {
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

    fn ai(&mut self, ai: &str, c: &str, params: &[(&str, i64)], token: Option<&[u8]>) -> Response {
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

    fn records(&self, kind: &str) -> Vec<Value> {
        self.node
            .audit()
            .lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| v["kind"] == kind)
            .collect()
    }

    /// Every outcome judged: settled later (`outcome` records), or at once
    /// (an execution's `verification`).
    fn outcomes(&self) -> Vec<Value> {
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

    fn last_outcome(&self) -> Value {
        self.outcomes().pop().unwrap_or(Value::Null)
    }

    fn in_recovery(&self) -> bool {
        self.node.domain_state().recovery.contains_key(&ResourceId::parse(ROBOT_R).unwrap())
    }

    fn settle(&mut self) {
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
fn refused_by(r: &Response, rule: &str) -> bool {
    !r.is_ok() && r.summary().contains(rule)
}

/// An AI moves the robot with its token; the outcome is the pose the motion
/// leads to, from where the robot was, within the tolerance.
#[test]
fn an_ai_moves_the_robot_and_its_pose_is_verified() {
    let mut h = home();
    let r = h.ai("ai:assistant", "robot.move_linear", &[("distance_mm", 1_000), ("speed_mm_s", 500)], None);
    assert!(!r.is_ok(), "no token, no motion: {}", r.summary());
    let token = h.delegate("ai:assistant", ROBOT_R, "robot.move_linear");
    // 5 s of motion: longer than the outcome's own 3 s, which it is added to
    let r = h.ai("ai:assistant", "robot.move_linear", &[("distance_mm", 2_000), ("speed_mm_s", 400)], Some(&token));
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(h.node.pending_outcomes().len(), 1, "under way");
    h.settle();
    let o = h.last_outcome();
    assert_eq!(o["status"], "verified", "{o}");
    assert_eq!(o["expected_pose"]["pose"]["x_mm"], 2_000, "{o}");
    assert_eq!(o["observed_pose"]["x_mm"], 2_000, "{o}");
    // from where it is now, not from where it began
    let r = h.ai("ai:assistant", "robot.move_linear", &[("distance_mm", -500), ("speed_mm_s", 500)], Some(&token));
    assert!(r.is_ok(), "{}", r.summary());
    h.settle();
    let o = h.last_outcome();
    assert_eq!(
        (o["status"].as_str(), o["expected_pose"]["pose"]["x_mm"].as_i64()),
        (Some("verified"), Some(1_500)),
        "{o}"
    );
    assert_eq!(h.sim.pose(&id(ROBOT)), Some(Pose::new(1_500, 0, 0)));
    // the same token does not turn it
    let r = h.ai("ai:assistant", "robot.rotate", &[("angle_mdeg", 90_000), ("speed_mdeg_s", 45_000)], Some(&token));
    assert!(!r.is_ok(), "{}", r.summary());
}

/// SAFE-5 and SAFE-9: the robot moves only within its limits, from a known
/// recent pose, with nothing in its way and its emergency stop released.
#[test]
fn safety_keeps_the_robot_within_its_limits() {
    let mut h = home();
    let robot = id(ROBOT);
    let go = |h: &mut Home, d: i64, v: i64| h.owner("robot.move_linear", &[("distance_mm", d), ("speed_mm_s", v)]);
    assert!(refused_by(&go(&mut h, 500, 900), "SAFE-5-ENVELOPE"), "faster than the resource allows");
    assert!(refused_by(&go(&mut h, 4_500, 500), "SAFE-9-MOTION"), "out of the geofence");
    let r = h.owner("robot.goto_pose", &[("x_mm", 3_000), ("y_mm", 3_500), ("theta_mdeg", 0), ("speed_mm_s", 500)]);
    assert!(refused_by(&r, "geofence"), "{}", r.summary());

    h.sim.obstacle(&robot, true);
    h.pass(1_000);
    assert!(refused_by(&go(&mut h, 500, 500), "obstacle"));
    h.sim.obstacle(&robot, false);
    h.sim.emergency_stop(&robot, true);
    h.pass(1_000);
    assert!(refused_by(&go(&mut h, 500, 500), "emergency stop"));
    h.sim.emergency_stop(&robot, false);
    h.sim.localization(&robot, Localization::Lost);
    h.pass(1_000);
    assert!(refused_by(&go(&mut h, 500, 500), "not localised"));
    h.sim.localization(&robot, Localization::Stale);
    h.pass(1_500);
    assert!(refused_by(&go(&mut h, 500, 500), "fixed"), "a pose fixed 1.5 s ago");
    h.sim.localization(&robot, Localization::Live);
    h.pass(1_000);

    // one motion at a time
    assert!(go(&mut h, 2_000, 500).is_ok());
    h.pass(1_000);
    assert!(refused_by(&go(&mut h, 500, 500), "still moving"));
    assert_eq!(h.sim.commands(&robot), 1, "nothing refused reached the robot");
}

/// A stop always wins: under a safety hold, with the emergency stop pressed,
/// with its pose unknown, from a guest. Nobody but its owner moves it.
#[test]
fn a_stop_always_wins() {
    let mut h = home();
    let robot = id(ROBOT);
    let hold = payload([("resource", ParamValue::from(ROBOT_R))]);
    assert!(h.req("person:alice", "domain:home", "domain.safety_hold", hold).is_ok());
    let r = h.owner("robot.move_linear", &[("distance_mm", 500), ("speed_mm_s", 500)]);
    assert!(refused_by(&r, "SAFE-1-HOLD"), "{}", r.summary());
    let r = h.owner("robot.stop", &[]);
    assert!(r.is_ok(), "under a hold: {}", r.summary());

    h.sim.emergency_stop(&robot, true);
    h.sim.localization(&robot, Localization::Lost);
    h.pass(500);
    assert!(h.owner("robot.stop", &[]).is_ok(), "pressed and lost");
    // a guest stops it, and does not move it
    assert!(h.req("person:guest", ROBOT, "robot.stop", Payload::new()).is_ok());
    let r = h.req("person:guest", ROBOT, "robot.move_linear", ints(&[("distance_mm", 100), ("speed_mm_s", 100)]));
    assert!(!r.is_ok(), "{}", r.summary());
    // stops are no actuations to hold motions back
    for _ in 0..10 {
        assert!(h.owner("robot.stop", &[]).is_ok());
    }
}

/// Stops are no actuations: however many, they never hold a motion back
/// under the rate (SAFE-6).
#[test]
fn stops_do_not_count_against_the_rate() {
    let mut h = home();
    for _ in 0..10 {
        assert!(h.owner("robot.stop", &[]).is_ok());
    }
    h.pass(500);
    let r = h.owner("robot.move_linear", &[("distance_mm", 300), ("speed_mm_s", 300)]);
    assert!(r.is_ok(), "{}", r.summary());
}

/// A robot is governed only within limits: a resource that binds a motion
/// without a geofence, or without a bound on its speed, is refused.
#[test]
fn a_robot_without_limits_is_refused() {
    let registry = chitala_model::CapabilityRegistry::core_v0_1();
    let check = |r: Resource| chitala_resource::ResourceGraph::new(vec![r], &registry).map(|_| ());
    let mut r = robot();
    r.parent = None;
    r.owners = vec![id("person:alice")];
    assert_eq!(check(r.clone()).map_err(|e| e.to_string()), Ok(()));
    let mut no_fence = r.clone();
    no_fence.motion = None;
    assert!(check(no_fence).unwrap_err().to_string().contains("no motion limits"));
    let mut fast = r.clone();
    fast.envelope.retain(|l| l.capability.as_str() != "robot.rotate");
    assert!(check(fast).unwrap_err().to_string().contains("speed_mdeg_s"));
    let mut concave = r.clone();
    concave.motion.as_mut().unwrap().geofence =
        Geofence(vec![[0, 0], [4_000, 0], [4_000, 1_000], [1_000, 1_000], [1_000, 3_000], [0, 3_000]]);
    assert!(check(concave).unwrap_err().to_string().contains("convex"));
    let mut no_stop = r.clone();
    no_stop.safe_state = None;
    assert!(check(no_stop).unwrap_err().to_string().contains("safe state is its stop"));
    let mut still = r;
    still.bindings.retain(|b| !b.capability.as_str().starts_with("robot."));
    still.safe_state = None;
    still.envelope.clear();
    assert!(check(still).unwrap_err().to_string().contains("binds no motion"), "limits with nothing to limit");
}

/// A right to move a robot includes the right to stop it; nothing else does.
#[test]
fn a_motion_right_includes_the_stop() {
    let mut h = home();
    let moves = h.delegate("ai:assistant", ROBOT_R, "robot.goto_pose");
    let lights = h.delegate("ai:other", "resource:living-room-light", "light.turn_on");
    assert!(h.ai("ai:assistant", "robot.stop", &[], Some(&moves)).is_ok());
    assert!(!h.ai("ai:other", "robot.stop", &[], Some(&lights)).is_ok());
    assert!(!h.ai("ai:other", "robot.stop", &[], None).is_ok());
}

/// Wheel slip ends the motion short: diverged, and recovery stops the robot.
/// A stall never arrives: diverged at the deadline, and the stop is sent.
#[test]
fn slip_and_stalls_break_the_promise_and_recovery_stops_the_robot() {
    let mut h = home();
    let robot = id(ROBOT);
    h.sim.slip(&robot, 0.9);
    assert!(h.owner("robot.move_linear", &[("distance_mm", 2_000), ("speed_mm_s", 500)]).is_ok());
    h.settle();
    let outcomes = h.outcomes();
    let moved = outcomes.iter().find(|o| o["capability"] == "robot.move_linear").unwrap();
    assert_eq!(moved["status"], "diverged", "1800 mm of 2000: {moved}");
    assert!(h.in_recovery());
    let stop = outcomes.iter().find(|o| o["capability"] == "robot.stop").expect("the safe state ran");
    assert_eq!(stop["status"], "verified", "{stop}");
    assert_eq!(h.sim.commands(&robot), 2, "the motion, then the stop");
    let release = payload([("resource", ParamValue::from(ROBOT_R))]);
    assert!(h.req("person:alice", "domain:home", "domain.safety_release", release.clone()).is_ok());

    h.sim.slip(&robot, 1.0);
    h.sim.stall(&robot, true);
    assert!(h.owner("robot.rotate", &[("angle_mdeg", 90_000), ("speed_mdeg_s", 90_000)]).is_ok());
    h.settle();
    let stops = h.outcomes().iter().filter(|o| o["capability"] == "robot.stop").count();
    assert_eq!(stops, 2, "the recovery's stop, each time");
    assert!(!h.sim.moving(&robot), "the stall's motion was stopped");
}

/// A motion interrupted by a stop is superseded, not failed.
#[test]
fn a_stop_supersedes_the_motion_it_interrupts() {
    let mut h = home();
    assert!(h.owner("robot.move_linear", &[("distance_mm", 3_000), ("speed_mm_s", 500)]).is_ok());
    h.pass(1_000);
    assert!(h.owner("robot.stop", &[]).is_ok());
    h.settle();
    let outcomes = h.outcomes();
    let status = |c: &str| outcomes.iter().find(|o| o["capability"] == c).map(|o| o["status"].clone());
    assert_eq!(status("robot.move_linear"), Some(Value::from("superseded")));
    assert_eq!(status("robot.stop"), Some(Value::from("verified")));
    assert!(!h.in_recovery());
}
