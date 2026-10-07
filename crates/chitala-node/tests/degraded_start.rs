//! A node whose adapter host does not come up starts degraded, not at all
//! (Project Lead, 2026-10-07). An adapter is outside the Trusted Core: if it
//! could keep the node from starting by never answering, it would hold a
//! denial of service over Authority and Safety. So the node starts, audits
//! the adapter as unavailable, and fails closed for that adapter's devices
//! only: their orders are not sent (`X_DEVICE_UNAVAILABLE`). Everything else
//! runs. The adapter host is started again only on demand, at most once per
//! `MIN_RESPAWN_INTERVAL`, and always in a new session.

use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chitala_adapters::host::{AdapterHost, HostRequest};
use chitala_model::{CapabilityId, CapabilityRegistry, EntityId, ExecCode, Payload};
use chitala_node::executor::MIN_RESPAWN_INTERVAL;
use chitala_node::{Domain, Node, NodeConfig, NodeEnv, Requester, Response, StoredObject};
use chitala_platform::memory::{self, MemoryControls, Program};
use chitala_platform::{StoragePath, TimeSource, TrustedClock, Visibility};

const T0: u64 = 1_790_000_000_000;

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}

/// An adapter host that answers as the real one does, except that while
/// `robot_down` is set it closes, without answering, an init for the
/// robot's adapter. It records the executor session of every init.
fn adapter_host(
    time: Arc<dyn TimeSource>,
    robot_down: Arc<AtomicBool>,
    sessions: Arc<Mutex<Vec<(String, String)>>>,
) -> Program {
    Arc::new(move |input, mut output, _env| {
        let clock = Arc::new(TrustedClock::new(Arc::clone(&time), 0)).as_clock();
        let mut reader = BufReader::new(input);
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        let Ok(HostRequest::Init(init)) = serde_json::from_str(line.trim()) else { return };
        let adapter = init.devices.first().map(|d| d.adapter.clone()).unwrap_or_default();
        sessions.lock().unwrap().push((adapter.clone(), init.executor.clone()));
        if adapter == chitala_adapters::robot_sim::ADAPTER && robot_down.load(Ordering::SeqCst) {
            return;
        }
        let Ok(mut host) = AdapterHost::from_init(init, clock) else { return };
        let _ = writeln!(output, "{{\"ok\":true}}");
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let _ = writeln!(output, "{}", host.handle_line(&line));
        }
    })
}

struct Home {
    node: Node,
    domain: Domain,
    ctl: MemoryControls,
    robot_down: Arc<AtomicBool>,
    sessions: Arc<Mutex<Vec<(String, String)>>>,
}

/// The sample home with the sample robot added: two adapters, `mock` (the
/// light, the door, …) and `robot-sim`, each in its own adapter host.
fn home_with_the_robot_down() -> Home {
    let (platform, ctl) = memory::platform("degraded-start", T0);
    let robot_down = Arc::new(AtomicBool::new(true));
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let program = adapter_host(Arc::clone(&platform.time), Arc::clone(&robot_down), Arc::clone(&sessions));
    ctl.exec.register("adapter-host", program);
    let summary = chitala_node::setup::init_domain(platform.storage.as_ref(), platform.keys.as_ref()).unwrap();
    let text = platform.storage.read(&summary.config, Visibility::Shared).unwrap().unwrap();
    let mut config: NodeConfig = serde_json::from_slice(&text).unwrap();
    let (robot, resource) = chitala_node::setup::sample_robot();
    config.devices.push(robot);
    config.resources.push(resource);
    let path = |p: &str| StoragePath::new(p).unwrap();
    let stored = |p: &str| StoredObject::new(Arc::clone(&platform.storage), path(p));
    let env = NodeEnv {
        audit_log: stored(&config.audit_log),
        state_file: stored(&config.state_file),
        policy_file: None,
        adapter_host: "adapter-host".into(),
        home_assistant_env: Vec::new(),
        history_evaluator: None,
    };
    let domain = Domain { config, platform, endpoint: chitala_platform::Endpoint::new("node").unwrap() };
    let node =
        chitala_node::start_node(&domain, &env).expect("a node whose adapter host does not come up still starts");
    Home { node, domain, ctl, robot_down, sessions }
}

impl Home {
    fn request(&mut self, who: &str, target: &str, capability: &str) -> Response {
        let key = self.domain.keypair(&id(who)).unwrap();
        let bytes = Requester::new(id(who), key, id("service:test"), Arc::clone(&self.domain.platform.entropy)).sign(
            &CapabilityRegistry::core_v0_1(),
            &id(target),
            &CapabilityId::parse(capability).unwrap(),
            Payload::new(),
            self.domain.platform.time.wall_ms(),
        );
        self.node.handle(&bytes)
    }

    /// The node's own audit records of `event`, read from the stored log.
    fn audited(&self, event: &str) -> Vec<serde_json::Value> {
        let path = StoragePath::new(&self.domain.config.audit_log).unwrap();
        let text = self.domain.platform.storage.read(&path, Visibility::Private).unwrap().unwrap();
        String::from_utf8(text)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|v| v["kind"] == "node" && v["event"] == event)
            .collect()
    }

    fn robot_inits(&self) -> Vec<String> {
        let sessions = self.sessions.lock().unwrap();
        sessions.iter().filter(|(a, _)| a == chitala_adapters::robot_sim::ADAPTER).map(|(_, s)| s.clone()).collect()
    }
}

fn exec_code(r: &Response) -> Option<ExecCode> {
    r.error.as_ref().map(|e| e.code)
}

#[test]
fn an_adapter_that_does_not_come_up_leaves_the_node_running_and_degraded() {
    let h = home_with_the_robot_down();
    let unavailable = h.audited("adapter_unavailable");
    assert_eq!(unavailable.len(), 1, "one adapter is audited as unavailable at start: {unavailable:?}");
    assert_eq!(unavailable[0]["adapter"], chitala_adapters::robot_sim::ADAPTER);
    assert_eq!(h.audited("start").len(), 1, "the node started");
    let hello = h.node.hello();
    assert_eq!(hello["readiness"]["state"], "degraded", "{hello}");
    assert_eq!(hello["readiness"]["unavailable_adapters"], serde_json::json!([chitala_adapters::robot_sim::ADAPTER]));
}

#[test]
fn the_unavailable_adapters_devices_fail_closed_and_the_rest_runs() {
    let mut h = home_with_the_robot_down();
    // the robot's adapter is down: its order is not sent
    let r = h.request("person:alice", "device:robot", "robot.stop");
    assert!(!r.is_ok(), "{r:?}");
    assert_eq!(exec_code(&r), Some(ExecCode::DeviceUnavailable), "{r:?}");
    // the other adapter, Authority and Safety run as ever
    let r = h.request("person:alice", "device:living-room-light", "light.turn_on");
    assert!(r.is_ok(), "the light's adapter is up: {r:?}");
    let r = h.request("person:child", "device:front-door", "lock.unlock");
    assert!(!r.is_ok() && r.error.is_none(), "Authority still refuses the child: {r:?}");
}

#[test]
fn a_down_adapter_is_not_retried_blindly_and_comes_back_only_in_a_new_session() {
    let mut h = home_with_the_robot_down();
    assert_eq!(h.robot_inits().len(), 1, "one attempt at start");
    // within the respawn interval, another request does not start it again
    let r = h.request("person:alice", "device:robot", "robot.stop");
    assert_eq!(exec_code(&r), Some(ExecCode::DeviceUnavailable), "{r:?}");
    assert_eq!(h.robot_inits().len(), 1, "no new attempt within {MIN_RESPAWN_INTERVAL:?}");

    // the adapter can come up now; after the interval a request starts it again
    h.robot_down.store(false, Ordering::SeqCst);
    h.ctl.time.advance_monotonic(MIN_RESPAWN_INTERVAL.as_millis() as u64 + 1);
    let r = h.request("person:alice", "device:robot", "robot.stop");
    assert!(r.is_ok(), "the robot's adapter host is up again: {r:?}");
    let inits = h.robot_inits();
    assert_eq!(inits.len(), 2, "one more attempt, on demand: {inits:?}");
    assert_ne!(inits[0], inits[1], "in a new executor session, not the one of the attempt that failed");
    assert_eq!(h.node.hello()["readiness"]["state"], "ready");
}
