//! The whole chain on Home Assistant (v0.3 step 2, specs 22, 24, 25): Authority
//! → Safety → the trusted boundary → the Home Assistant adapter → a fake Home
//! Assistant → outcome verification and recovery. The adapter only executes
//! and observes, never sends a command twice, and never makes up a state;
//! Chitala decides what a command whose fate is unknown did.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use chitala_adapters::fake_ha::{Behaviour, FakeHa, TOKEN};
use chitala_adapters::fake_matter::FakeMatter;
use chitala_adapters::home_assistant::link::Timing;
use chitala_adapters::home_assistant::HomeAssistantAdapter;
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::{Intent, PlanStep};
use chitala_model::{
    payload, CapabilityId, DeviceDescriptor, EntityId, ExecCode, ParamValue, Payload, RiskClass, SecurityClass,
};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::{Node, NodeParts, Requester, Response, Step};
use chitala_resource::{Boundary, CapabilityBinding, Resource, ResourceId, ResourceKind, SafeState, StateRef};
use chitala_token::bytes_from_base64;
use serde_json::{json, Value};

const T0: u64 = 1_790_000_000_000;
const TOKEN_ENV: &str = "CHITALA_TEST_NODE_FAKE_HA_TOKEN";
const LIGHT: &str = "device:light";
const PLUG: &str = "device:plug";
const LOCK: &str = "device:lock";

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

fn until(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn device(local: &str, caps: &[&str]) -> DeviceDescriptor {
    DeviceDescriptor {
        id: id(local),
        name: local.into(),
        adapter: "home-assistant".into(),
        room: None,
        security_class: SecurityClass::Sc1,
        capabilities: caps.iter().map(|c| cap(c)).collect(),
    }
}

fn resource(local: &str, kind: ResourceKind, device: Option<(&str, &[&str])>) -> Resource {
    Resource {
        id: rid(local),
        kind,
        name: local.into(),
        parent: (local != "home").then(|| rid("home")),
        owners: if local == "home" { vec![id("person:alice")] } else { vec![] },
        boundary: Boundary::Interior,
        zone: None,
        bindings: device
            .map(|(d, caps)| {
                caps.iter().map(|c| CapabilityBinding { capability: cap(c), device: id(d), risk_floor: None }).collect()
            })
            .unwrap_or_default(),
        state: device.map(|(d, _)| StateRef { device: id(d), max_age_ms: 120_000 }),
        envelope: vec![],
        two_key: false,
        safe_state: None,
        motion: None,
    }
}

struct Home {
    ha: FakeHa,
    /// The Matter server behind Home Assistant's Matter devices, if any.
    matter: Option<FakeMatter>,
    node: Node,
    clock: Arc<AtomicU64>,
    keys: HashMap<String, Keypair>,
}

/// A home whose light, plug and lock live in (a fake) Home Assistant, with the
/// Home profile's recommendations: the plug's turn_on at medium risk and safe
/// state off, the door's safe state locked (spec 24).
fn home() -> Home {
    static ENV: OnceLock<()> = OnceLock::new();
    ENV.get_or_init(|| std::env::set_var(TOKEN_ENV, TOKEN));
    start(FakeHa::start(), chitala_node::DomainState::default(), T0)
}

/// The node crashes and starts again on the same Home Assistant, with the
/// domain state it had persisted (`domain_state()` is what the state file holds).
fn restart(h: Home) -> Home {
    let Home { ha, matter, node, .. } = h;
    let state = node.domain_state().clone();
    // the clock goes on from where the node left it
    let now = node.now() + 2_000;
    drop(node);
    start_with(ha, matter, state, now)
}

fn start(ha: FakeHa, state: chitala_node::DomainState, t0: u64) -> Home {
    start_with(ha, None, state, t0)
}

fn start_with(ha: FakeHa, matter: Option<FakeMatter>, state: chitala_node::DomainState, t0: u64) -> Home {
    // the node's clock: the test's own steps plus the real time that passes,
    // as a real clock does (Home Assistant's states age in real time, F9)
    let clock = Arc::new(AtomicU64::new(t0));
    let c = Arc::clone(&clock);
    let started = Instant::now();
    let node_clock: chitala_node::Clock =
        Arc::new(move || c.load(Ordering::SeqCst) + u64::try_from(started.elapsed().as_millis()).unwrap_or(0));
    let mut keys = HashMap::new();
    let mut principals = Vec::new();
    for (who, roles) in [("person:alice", &["owner"][..]), ("ai:assistant", &[][..])] {
        let k = Keypair::from_seed(&test_seed(who));
        principals.push((id(who), k.public_key(), roles.iter().map(|r| r.to_string()).collect()));
        keys.insert(who.to_string(), k);
    }
    let entities: BTreeMap<EntityId, String> =
        [(LIGHT, "light.living_room"), (PLUG, "switch.kettle"), (LOCK, "lock.front_door")]
            .into_iter()
            .map(|(d, e)| (id(d), e.to_string()))
            .collect();
    let timing = Timing {
        connect: Duration::from_secs(2),
        call: Duration::from_millis(500),
        poll: Duration::from_millis(5),
        ping_every: Duration::from_secs(5),
        min_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(80),
        auth_min: Duration::from_millis(20),
        auth_max: Duration::from_millis(80),
    };
    let mut adapter = HomeAssistantAdapter::with_link(&ha.url(), TOKEN_ENV, entities, false, Some(timing)).unwrap();
    if let Some(m) = &matter {
        adapter = adapter.with_matter_evidence(&m.url(), timing.call).unwrap();
    }
    // the link is up and bootstrapped before the node starts
    until("the link bootstrapped", || ha.world().bootstraps >= 1);
    std::thread::sleep(Duration::from_millis(50));
    let boundary = TrustedExecutionBoundary::new(entropy());
    let executor = chitala_node::executor::in_process(&boundary, vec![Box::new(adapter)], node_clock.clone());
    let mut plug = resource("kettle", ResourceKind::Switch, Some((PLUG, &["switch.turn_on", "switch.turn_off"])));
    plug.bindings[0].risk_floor = Some(RiskClass::Medium);
    plug.safe_state = Some(SafeState { capability: cap("switch.turn_off"), params: Payload::new() });
    let mut door = resource("front-door", ResourceKind::Door, Some((LOCK, &["lock.lock", "lock.unlock"])));
    door.safe_state = Some(SafeState { capability: cap("lock.lock"), params: Payload::new() });
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: Keypair::from_seed(&test_seed("service:node")),
        authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
        principals,
        agency: vec![(id("ai:assistant"), vec![id("person:alice")])],
        devices: vec![
            device(LIGHT, &["device.read_state", "light.turn_on", "light.turn_off"]),
            device(PLUG, &["device.read_state", "switch.turn_on", "switch.turn_off"]),
            device(LOCK, &["device.read_state", "lock.lock", "lock.unlock"]),
        ],
        resources: vec![
            resource("home", ResourceKind::Site, None),
            resource("living-room-light", ResourceKind::Light, Some((LIGHT, &["light.turn_on", "light.turn_off"]))),
            plug,
            door,
        ],
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
    Home { ha, matter, node, clock, keys }
}

impl Home {
    fn matter(&self) -> &FakeMatter {
        self.matter.as_ref().expect("a home with a Matter server")
    }

    /// The Matter lock (node 4) dies, or comes back.
    fn lock_alive(&self, alive: bool) {
        self.matter().world().nodes.get_mut(&4).unwrap().alive = alive;
    }

    fn advance(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn req(&mut self, who: &str, target: &str, c: &str) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), Payload::new(), self.node.now());
        self.advance(1);
        self.node.handle(&bytes)
    }

    fn delegate(&mut self, target: &str, c: &str) -> Vec<u8> {
        let pl = payload([
            ("holder", ParamValue::from("ai:assistant")),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(c)),
            ("ttl_s", ParamValue::Int(3600)),
        ]);
        let r = Requester::new(id("person:alice"), self.keys["person:alice"].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id("domain:home"), &cap("domain.delegate"), pl, self.node.now());
        self.advance(1);
        let r = self.node.handle(&bytes);
        assert!(r.is_ok(), "{}", r.summary());
        bytes_from_base64(r.result.unwrap()["token"].as_str().unwrap()).unwrap()
    }

    /// The node's server loop for `ms` of real time, at its own pace (one tick
    /// every 50 ms): for effects that take real time, such as a motor.
    fn wait_real(&mut self, ms: u64) {
        let end = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < end {
            self.node.tick();
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Ticks of the node's server loop, while real time lets the fake answer.
    fn ticks_until(&mut self, what: &str, f: impl Fn(&Node) -> bool) {
        for _ in 0..400 {
            if f(&self.node) {
                return;
            }
            self.advance(100);
            self.node.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("timed out waiting until {what}");
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

    fn calls(&self) -> Vec<String> {
        self.ha.calls().into_iter().map(|(s, e, _)| format!("{s} {e}")).collect()
    }
}

fn status(r: &Response) -> &str {
    r.outcome.as_ref().and_then(|o| o["status"].as_str()).unwrap_or("none")
}

#[test]
fn an_owner_s_action_reaches_home_assistant_once_and_is_verified() {
    let mut h = home();
    let r = h.req("person:alice", LIGHT, "light.turn_on");
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(status(&r), "verified", "{}", r.summary());
    assert_eq!(h.calls(), ["light.turn_on light.living_room"]);
    assert_eq!(h.ha.world().states["light.living_room"]["state"], "on");
}

#[test]
fn a_command_lost_after_sending_ends_applied_and_is_never_resent() {
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    // the answer is lost, and the bolt moves a moment later, as a motor does
    h.ha.behave("lock.front_door", Behaviour::LoseThenSlowEffect);
    let r = h.req("person:alice", LOCK, "lock.lock");
    // the adapter does not know what happened, and says so
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(status(&r), "pending", "{}", r.summary());
    // the lock reports after the order, within its 5 s: the door did lock
    h.wait_real(2_000);
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!(settled["status"], "applied");
    assert_eq!(settled["observed"], json!({"locked": true}));
    assert!(h.node.domain_state().recovery.is_empty());
    assert_eq!(h.calls(), ["lock.unlock lock.front_door", "lock.lock lock.front_door"], "never sent twice");
    // and nothing retries it later either
    for _ in 0..20 {
        h.advance(1_000);
        h.node.tick();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(h.calls().len(), 2);

    // the bolt moved at once and the connection broke right after: the link
    // serves nothing from a dying connection, and REST dates a state only to
    // the second. Nothing proves the lock moved after the order: unconfirmed,
    // recovery, and still never sent twice (F9)
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    h.ha.behave("lock.front_door", Behaviour::LoseAfterSend);
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "unconfirmed");
    assert!(h.node.domain_state().recovery.contains_key(&rid("front-door")));
    assert_eq!(h.calls().len(), 2, "never sent twice");
}

#[test]
fn a_lock_still_moving_is_pending_until_it_arrives() {
    let mut h = home();
    h.ha.behave("lock.front_door", Behaviour::Moving);
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(status(&r), "pending", "unlocking is not unlocked: {}", r.summary());
    assert_eq!(r.outcome.as_ref().unwrap()["observed"], json!({}));
    // the bolt arrives a moment later
    h.ha.world().set("lock.front_door", "unlocked", json!({}));
    h.ticks_until("verified", |n| n.pending_outcomes().is_empty());
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "verified");
    assert!(h.node.domain_state().recovery.is_empty());
}

#[test]
fn a_jammed_lock_puts_the_door_in_recovery_with_one_safe_state_attempt() {
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    h.ha.behave("lock.front_door", Behaviour::Stuck);
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(status(&r), "pending", "{}", r.summary());
    h.ha.world().set("lock.front_door", "jammed", json!({}));
    h.ticks_until("the door is in recovery", |n| n.domain_state().recovery.contains_key(&rid("front-door")));
    let first = h.records("outcome");
    assert_eq!(first[0]["status"], "diverged");
    assert_eq!(first[0]["observed"], json!({}), "a jammed lock reports no `locked`");
    // the safe state went to Home Assistant once; the lock is still jammed
    h.ticks_until("the safe state settled", |n| n.pending_outcomes().is_empty());
    for _ in 0..20 {
        h.advance(1_000);
        h.node.tick();
    }
    assert_eq!(
        h.calls(),
        ["lock.unlock lock.front_door", "lock.lock lock.front_door", "lock.lock lock.front_door"],
        "one command, one safe state, nothing more"
    );
    assert_eq!(h.records("outcome").len(), 2);
}

/// v0.3 step ③A, finding F6, on Home Assistant: Home Assistant reports the
/// lock `unavailable`. Once the node has looked, the `locked` it saw before is
/// history, not evidence, and Safety refuses an unlock: nothing reaches Home
/// Assistant. When Home Assistant reports the lock locked again and the node
/// has looked, the unlock goes through.
#[test]
fn a_lock_home_assistant_reports_unavailable_is_not_known_to_be_locked() {
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.lock").is_ok());
    h.ha.world().set("lock.front_door", "unavailable", json!({}));
    // the door's state is relied on: the node looks at it again before it gets
    // old (each pass a minute apart, while the link hears of the change)
    for _ in 0..200 {
        if h.node.twins().evidence(&id(LOCK), h.node.now()).is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        h.advance(60_000);
        h.node.tick();
    }
    assert!(h.node.twins().evidence(&id(LOCK), h.node.now()).is_none(), "the door cannot be observed");
    assert_eq!(h.node.twins().get(&id(LOCK)).unwrap().reported.get("locked"), Some(&ParamValue::Bool(true)));
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-3-STATE"), "{}", r.summary());
    assert_eq!(h.calls(), ["lock.lock lock.front_door"], "nothing was sent");

    h.ha.world().set("lock.front_door", "locked", json!({}));
    h.ticks_until("the door is observed again", |n| n.twins().evidence(&id(LOCK), n.now()).is_some());
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert!(r.is_ok(), "{}", r.summary());
}

#[test]
fn a_device_that_drops_off_leaves_its_outcome_unconfirmed_not_diverged() {
    let mut h = home();
    h.ha.behave("light.living_room", Behaviour::DropsOff);
    let r = h.req("person:alice", LIGHT, "light.turn_on");
    // Home Assistant accepted the call, but the light cannot be observed: the
    // adapter has no state to vouch for, so it reports the fate as unknown
    // instead of inventing one, and Chitala watches for the witness
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(status(&r), "pending", "{}", r.summary());
    assert_eq!(r.outcome.as_ref().unwrap()["observed"], Value::Null, "unavailable is no observation");
    assert_eq!(r.outcome.as_ref().unwrap()["execution"], "unknown");
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "unconfirmed");
    assert!(h.node.domain_state().recovery.is_empty(), "a light is low risk: reported, not stopped");
    let twin = h.node.twins().get(&id(LIGHT)).unwrap();
    assert_eq!(twin.reported.get("on"), Some(&ParamValue::Bool(false)), "the twin keeps what was last observed");
    assert_eq!(h.calls(), ["light.turn_on light.living_room"]);
}

/// The Project Lead's three cases (2026-10-05). 1: a command that certainly
/// was not delivered is not applied, and transport failure alone never puts a
/// resource in recovery.
#[test]
fn a_command_never_delivered_leads_to_no_recovery() {
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    h.ha.kill();
    std::thread::sleep(Duration::from_millis(100));
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::DeviceUnavailable), "{}", r.summary());
    assert!(r.outcome.is_none(), "nothing executed, nothing to watch");
    for _ in 0..10 {
        h.advance(1_000);
        h.node.tick();
    }
    assert!(h.node.domain_state().recovery.is_empty());
    assert!(h.node.pending_outcomes().is_empty());
    assert_eq!(h.calls(), ["lock.unlock lock.front_door"], "the lock command never reached Home Assistant");
}

/// 2: a command that may have been delivered, and a witness that can tell:
/// the actual outcome, applied or not, and no recovery either way.
#[test]
fn a_command_whose_fate_is_unknown_takes_the_outcome_the_witness_shows() {
    // it did lock, the answer was lost: applied, once the lock reports it
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    h.ha.behave("lock.front_door", Behaviour::LoseThenSlowEffect);
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(r.outcome.as_ref().unwrap()["execution"], "unknown");
    h.wait_real(2_000);
    assert!(h.node.pending_outcomes().is_empty());
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "applied");
    assert!(h.node.domain_state().recovery.is_empty());

    // it did not lock, the answer was lost, and the lock reports again after
    // the order (still unlocked): that report is evidence, not applied
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    h.ha.behave("lock.front_door", Behaviour::LoseWithoutEffect);
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(status(&r), "pending", "the state from before the order settles nothing: {}", r.summary());
    // the lost call broke the connection; once the link is back, the lock reports
    h.wait_real(300);
    h.ha.world().set("lock.front_door", "unlocked", json!({}));
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!((settled["status"].as_str(), settled["execution"].as_str()), (Some("not_applied"), Some("unknown")));
    assert_eq!(settled["observed"], json!({"locked": false}));
    assert!(h.node.domain_state().recovery.is_empty(), "a known state needs no recovery");
    assert_eq!(h.calls().len(), 2, "never sent twice");
}

/// v0.3 step ③A, finding F9 (the Project Lead's invariant): outcome evidence
/// must prove the state was produced after the order could have acted.
/// Reading a state after the command is not enough. Home Assistant goes on
/// serving a device's last state while the device is dead, for minutes with
/// Matter. Here the lock "dies": Home Assistant takes the call, nothing
/// happens, and it keeps answering the state it had before the order. That
/// state is history, not evidence: the outcome is `unconfirmed`, the door goes
/// into recovery, and nothing is sent a second time.
#[test]
fn a_cached_state_from_before_the_order_never_settles_an_unknown_execution() {
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok()); // unlocked, reported before the next order
    h.ha.behave("lock.front_door", Behaviour::LoseWithoutEffect);
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(status(&r), "pending", "the cached state settles nothing: {}", r.summary());
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!((settled["status"].as_str(), settled["execution"].as_str()), (Some("unconfirmed"), Some("unknown")));
    assert_eq!(settled["observed"], Value::Null, "no evidence after the order");
    assert!(h.node.domain_state().recovery.contains_key(&rid("front-door")), "nobody can establish it: recovery");
    assert!(h.records("decision").iter().all(|d| d["safe_state"] != true), "no blind safe state");
    assert_eq!(h.calls().len(), 2, "never sent twice");
}

/// F9, found on the real Home Assistant with a Matter lock that had died:
/// Home Assistant shows a lock `unlocking` the moment it takes the call (its
/// own optimistic state, not the lock's), then nothing. A state in motion is
/// not the lock's answer: `not_applied` needs the witness to report a settled
/// state (the expected keys), so this ends `unconfirmed`, with recovery.
#[test]
fn a_lock_still_moving_at_the_deadline_is_not_known_to_have_failed() {
    let mut h = home();
    h.ha.behave("lock.front_door", Behaviour::LoseWithoutEffect);
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    // after the order: in motion, as Home Assistant's optimistic state says
    h.wait_real(300);
    h.ha.world().set("lock.front_door", "unlocking", json!({}));
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!(settled["status"], "unconfirmed", "in motion is not 'did not take effect'");
    assert!(h.node.domain_state().recovery.contains_key(&rid("front-door")));
    assert_eq!(h.calls().len(), 1, "never sent twice");
}

/// Concurrency audit R3: a witness's reading folded after a newer one is
/// history, for outcomes too. The lock shows `unlocked` (the periodic pass
/// reads it), then `locked` again, read by a request and folded first; the
/// earlier reading, folded last, must not settle the unlock as applied.
#[test]
fn an_earlier_reading_of_a_witness_folded_late_is_no_evidence() {
    let mut h = home();
    h.ha.behave("lock.front_door", Behaviour::LoseWithoutEffect);
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    h.wait_real(300);
    // no ticks from here: only what this test folds is folded
    h.ha.world().set("lock.front_door", "unlocked", json!({}));
    std::thread::sleep(Duration::from_millis(300));
    let now = h.node.now();
    let observer = h.node.due_observations(now).into_iter().find(|o| o.device() == &id(LOCK)).expect("the witness");
    let earlier = observer.run(); // "unlocked"
    h.ha.world().set("lock.front_door", "locked", json!({}));
    std::thread::sleep(Duration::from_millis(300));
    let read = h.req("person:alice", LOCK, "device.read_state"); // "locked", folded first
    assert_eq!(read.result.as_ref().map(|v| v["reported"]["locked"].clone()), Some(json!(true)), "{}", read.summary());
    h.node.observed_by(&observer, earlier);
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!(settled["status"], "not_applied", "the lock is locked: {settled}");
    assert_eq!(settled["observed"], json!({"locked": true}));
}

/// A home whose lock is a Matter device (node 4) in Home Assistant, read for
/// evidence through a Matter server, alive or not, and starts `door`
/// ("locked" or "unlocked").
fn matter_home(alive: bool, door: &str) -> Home {
    static ENV: OnceLock<()> = OnceLock::new();
    ENV.get_or_init(|| std::env::set_var(TOKEN_ENV, TOKEN));
    let ha = FakeHa::start();
    let matter = FakeMatter::start();
    ha.wire("lock.front_door", 4, &matter);
    matter.world().lock(4, if door == "locked" { 1 } else { 2 });
    matter.world().nodes.get_mut(&4).unwrap().alive = alive;
    ha.world().set("lock.front_door", door, json!({}));
    let h = start_with(ha, Some(matter), chitala_node::DomainState::default(), T0);
    until("the registry is read", || h.ha.world().registry_reads >= 1);
    std::thread::sleep(Duration::from_millis(50));
    h
}

/// F9b, found on the real Home Assistant with a Matter lock that had died:
/// Home Assistant takes the lock command, shows `locking` (its own optimistic
/// state), and when the lock does not confirm, it writes the value it held,
/// `unlocked`, again with a new timestamp (30 s later for real; here at
/// once, inside the window, as after a node restart). A gateway's timestamp is
/// not physical freshness. Home Assistant's state of a Matter device is never
/// evidence (F10); the lock itself is read through the Matter server and does
/// not answer, so nothing is: `unconfirmed`, with recovery, never
/// `not_applied`.
#[test]
fn a_dead_matter_lock_s_cached_state_with_a_new_timestamp_is_no_evidence() {
    let mut h = matter_home(false, "unlocked");
    h.ha.behave("lock.front_door", Behaviour::LoseWithoutEffect);
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(status(&r), "pending", "{}", r.summary());
    // after the order: Home Assistant's optimistic state, then its cached value
    h.wait_real(300);
    h.ha.world().set("lock.front_door", "locking", json!({}));
    h.wait_real(600);
    h.ha.world().set("lock.front_door", "unlocked", json!({}));
    h.wait_real(300);
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!(settled["status"], "unconfirmed", "a cached value re-emitted is not the lock's answer: {settled}");
    assert_eq!(settled["observed"], Value::Null, "no evidence after the order");
    assert!(h.node.domain_state().recovery.contains_key(&rid("front-door")), "nobody can establish it: recovery");
    assert!(h.records("decision").iter().all(|d| d["safe_state"] != true), "no blind safe state");
    assert_eq!(h.calls(), ["lock.lock lock.front_door"], "never sent twice");
    assert!(!h.matter().commands().is_empty(), "the lock was read");
    assert!(h.ha.world().matter_commands.is_empty(), "never through Home Assistant's Matter API");
}

/// F9b, the other side: a Matter lock that answers. Its state after the
/// order, confirmed by an exchange that began after Home Assistant reported
/// it, settles the outcome as before: `verified` after a reported command;
/// after one whose answer was lost, `applied` when the lock moved and
/// `not_applied` when it did not.
#[test]
fn a_live_matter_lock_s_fresh_state_settles_its_outcome() {
    let mut h = matter_home(true, "locked");
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(status(&r), "verified", "{}", r.summary());
    assert!(h.matter().commands().iter().any(|c| c == "read_attribute"), "read from the lock itself");

    // the answer lost; the lock moves a moment later
    h.ha.behave("lock.front_door", Behaviour::LoseThenSlowEffect);
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    h.wait_real(1_600);
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "applied");

    // the answer lost; the lock did nothing, and says so
    h.ha.behave("lock.front_door", Behaviour::LoseWithoutEffect);
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    h.wait_real(300);
    h.ha.world().set("lock.front_door", "locked", json!({}));
    h.wait_real(300);
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!(settled["status"], "not_applied", "{settled}");
    assert!(!h.node.domain_state().recovery.contains_key(&rid("front-door")), "a known state: no recovery");
    assert_eq!(h.calls().len(), 3, "never sent twice");
}

/// F10, found testing F9b on the real lab: Home Assistant's state of a Matter
/// device can lag the device — under backpressure the Matter server sends an
/// interview's result ahead of the update it found. Here the lock did unlock,
/// yet Home Assistant writes its cached `locked` again after the order. The
/// adapter reads the lock itself, so the unlock is `applied`: never
/// `not_applied` with the door open.
#[test]
fn a_matter_lock_s_own_state_beats_home_assistant_s_stale_one() {
    let mut h = matter_home(true, "locked");
    h.ha.behave("lock.front_door", Behaviour::LoseWithoutEffect);
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    // the lock unlocks; its report is stuck behind Home Assistant's backlog,
    // and Home Assistant writes the value it held
    h.matter().world().lock(4, 2);
    h.wait_real(100);
    h.ha.world().set("lock.front_door", "locked", json!({}));
    h.wait_real(300);
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!(settled["status"], "applied", "the lock itself says it unlocked: {settled}");
    assert_eq!(settled["observed"], json!({"locked": false}));
    assert!(h.matter().commands().iter().all(|c| c == "read_attribute"), "{:?}", h.matter().commands());
    assert_eq!(h.calls(), ["lock.unlock lock.front_door"], "never sent twice");
}

/// F11 (found testing F10): evidence an outcome holds belongs to the reading
/// that gave it. The live lock confirms it is still locked after an unlock
/// whose answer was lost; then it unlocks, reports, and dies before anyone can
/// confirm that. The newer reading cannot vouch for itself, but it no longer
/// states the confirmed fact: the old evidence is gone. By the deadline the
/// door's state is unknown: `unconfirmed`, with recovery, never `not_applied`.
#[test]
fn a_confirmed_state_superseded_by_one_nobody_can_confirm_is_no_longer_evidence() {
    let mut h = matter_home(true, "locked");
    h.ha.behave("lock.front_door", Behaviour::LoseWithoutEffect);
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    h.wait_real(300);
    h.ha.world().set("lock.front_door", "locked", json!({})); // confirmed by the lock
    h.wait_real(300);
    h.lock_alive(false);
    h.ha.world().set("lock.front_door", "unlocked", json!({})); // then it unlocks and dies
    h.wait_real(600);
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!(settled["status"], "unconfirmed", "the last confirmed state was superseded: {settled}");
    assert!(h.node.domain_state().recovery.contains_key(&rid("front-door")), "nobody can establish it: recovery");
    assert_eq!(h.calls(), ["lock.unlock lock.front_door"], "never sent twice");
}

/// F11, the other side: a newer reading nobody can confirm that still states
/// the same fact (the lock locked; only an attribute moved) leaves the
/// evidence as it was: the unlock did not take effect.
#[test]
fn a_newer_reading_of_the_same_fact_keeps_the_evidence() {
    let mut h = matter_home(true, "locked");
    h.ha.behave("lock.front_door", Behaviour::LoseWithoutEffect);
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    h.wait_real(300);
    h.ha.world().set("lock.front_door", "locked", json!({})); // confirmed by the lock
    h.wait_real(300);
    h.lock_alive(false);
    h.ha.world().set("lock.front_door", "locked", json!({"changed_by": "keypad"}));
    h.wait_real(600);
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!(settled["status"], "not_applied", "{settled}");
    assert!(!h.node.domain_state().recovery.contains_key(&rid("front-door")));
}

/// 3: a command that may have been delivered, and a witness that cannot tell,
/// at medium risk or more: the resource goes into recovery, and nothing is sent
/// a second time "to be sure" — no safe state without an observation.
#[test]
fn a_command_whose_fate_nobody_can_establish_puts_the_door_in_recovery_without_a_second_command() {
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    h.ha.behave("lock.front_door", Behaviour::LoseAndDie);
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(status(&r), "pending", "{}", r.summary());
    assert_eq!(r.outcome.as_ref().unwrap()["observed"], Value::Null);
    h.ticks_until("the door is in recovery", |n| n.domain_state().recovery.contains_key(&rid("front-door")));
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!((settled["status"].as_str(), settled["execution"].as_str()), (Some("unconfirmed"), Some("unknown")));
    let why = &h.node.domain_state().recovery[&rid("front-door")];
    assert!(why.contains("no safe state runs without an observation"), "{why}");
    // no blind retry: no safe-state decision, no second lock command, ever
    for _ in 0..20 {
        h.advance(1_000);
        h.node.tick();
    }
    assert!(h.records("decision").iter().all(|d| d["safe_state"] != true), "no safe state without evidence");
    assert_eq!(h.calls(), ["lock.unlock lock.front_door", "lock.lock lock.front_door"]);
    // in recovery, nothing but the safe state runs, for anyone
    let r = h.req("person:alice", LOCK, "lock.unlock");
    assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-8-RECOVERY"), "{}", r.summary());
}

#[test]
fn a_broken_home_assistant_makes_nothing_up() {
    let mut h = home();
    {
        // it takes connections and drops them: requests may or may not be read
        let mut w = h.ha.world();
        w.ws_up = false;
        w.rest_up = false;
        w.restarts += 1;
    }
    std::thread::sleep(Duration::from_millis(100));
    let r = h.req("person:alice", LIGHT, "light.turn_on");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(status(&r), "pending");
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "unconfirmed");
    assert!(h.calls().is_empty());
    let twin = h.node.twins().get(&id(LIGHT)).unwrap();
    assert_eq!(twin.reported.get("on"), Some(&ParamValue::Bool(false)), "the twin keeps what was last observed");
}

#[test]
fn an_agent_s_leaving_home_plan_runs_on_home_assistant_step_by_step() {
    let mut h = home();
    // someone left everything on and the door open
    assert!(h.req("person:alice", LIGHT, "light.turn_on").is_ok());
    assert!(h.req("person:alice", PLUG, "switch.turn_on").is_ok());
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    let light = h.delegate("resource:living-room-light", "light.turn_off");
    let plug = h.delegate("resource:kettle", "switch.turn_off");
    let door = h.delegate("resource:front-door", "lock.lock");
    let mut plan = Intent::new(
        chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
        id("ai:assistant"),
        id("person:alice"),
        cap("light.turn_off"),
        ResourceId::parse("resource:living-room-light").unwrap(),
        h.node.now(),
        120_000,
    );
    plan.context.purpose = Some("leaving home".into());
    plan.authority = Some(light);
    let mut s2 = PlanStep::new(cap("switch.turn_off"), ResourceId::parse("resource:kettle").unwrap(), Payload::new());
    s2.authority = Some(plug);
    let mut s3 = PlanStep::new(cap("lock.lock"), ResourceId::parse("resource:front-door").unwrap(), Payload::new());
    s3.authority = Some(door);
    plan.then = vec![s2, s3];
    let bytes = plan.sign(&h.keys["ai:assistant"]);
    h.advance(1);
    let r = h.node.handle(&bytes);
    assert!(r.is_ok(), "{}", r.summary());
    let p = &r.result.as_ref().unwrap()["plan"];
    assert_eq!(p["status"], "done", "{p}");
    for s in p["steps"].as_array().unwrap() {
        assert_eq!(s["outcome"]["status"], "verified", "{s}");
    }
    // in order, each once
    assert_eq!(
        h.calls()[3..],
        ["light.turn_off light.living_room", "switch.turn_off switch.kettle", "lock.lock lock.front_door"]
    );
    let w = h.ha.world();
    assert_eq!(
        (w.states["light.living_room"]["state"].as_str(), w.states["switch.kettle"]["state"].as_str()),
        (Some("off"), Some("off"))
    );
    assert_eq!(w.states["lock.front_door"]["state"], "locked");
}

/// Audit (v0.2 RC, High): a command whose fate is unknown is still pending
/// when the node crashes. A plan may stop at a restart; the uncertainty about
/// the physical world must not vanish with it.
#[test]
fn an_unknown_execution_survives_a_restart() {
    // Home Assistant stays down: nobody can establish what happened, and the
    // door goes into recovery after the restart, without a second command
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    h.ha.behave("lock.front_door", Behaviour::LoseAndDie);
    let r = h.req("person:alice", LOCK, "lock.lock");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(status(&r), "pending");
    let mut h = restart(h);
    assert_eq!(h.node.pending_outcomes().len(), 1, "the uncertainty came back with the node");
    h.ticks_until("the door is in recovery", |n| n.domain_state().recovery.contains_key(&rid("front-door")));
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "unconfirmed");
    assert_eq!(h.calls(), ["lock.unlock lock.front_door", "lock.lock lock.front_door"], "never resent");

    // Home Assistant is back by the time the node restarts. What it held from
    // before settles nothing (its age is unknown, F9); once the lock reports
    // after the order, the witness tells what happened (it did lock)
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    h.ha.behave("lock.front_door", Behaviour::LoseAndDie);
    assert_eq!(status(&h.req("person:alice", LOCK, "lock.lock")), "pending");
    {
        let mut w = h.ha.world();
        w.ws_up = true;
        w.rest_up = true;
    }
    let mut h = restart(h);
    for _ in 0..5 {
        h.advance(100);
        h.node.tick();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(h.node.pending_outcomes().len(), 1, "the bootstrapped state is no evidence");
    h.ha.world().set("lock.front_door", "locked", json!({}));
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    assert_eq!(h.records("outcome").pop().unwrap()["status"], "applied");
    assert!(h.node.domain_state().recovery.is_empty());
}

/// Audit (v0.2 RC, High): the Project Lead's scenario. A plan step sends a
/// command whose fate becomes unknown, and the node crashes. The plan does not
/// resume; the uncertainty about the door does.
#[test]
fn a_plan_stops_at_a_crash_but_its_step_s_uncertainty_does_not() {
    let mut h = home();
    assert!(h.req("person:alice", LIGHT, "light.turn_on").is_ok());
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    let light = h.delegate("resource:living-room-light", "light.turn_off");
    let door = h.delegate("resource:front-door", "lock.lock");
    h.ha.behave("lock.front_door", Behaviour::LoseAndDie);
    let mut plan = Intent::new(
        chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
        id("ai:assistant"),
        id("person:alice"),
        cap("light.turn_off"),
        ResourceId::parse("resource:living-room-light").unwrap(),
        h.node.now(),
        120_000,
    );
    plan.authority = Some(light);
    let mut lock = PlanStep::new(cap("lock.lock"), ResourceId::parse("resource:front-door").unwrap(), Payload::new());
    lock.authority = Some(door);
    plan.then = vec![lock];
    let bytes = plan.sign(&h.keys["ai:assistant"]);
    h.advance(1);
    let r = h.node.handle(&bytes);
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(r.result.as_ref().unwrap()["plan"]["status"], "stopped");
    assert_eq!(h.node.domain_state().inflight.len(), 1, "the lock's fate is on record");
    // crash
    let mut h = restart(h);
    assert_eq!(h.node.pending_outcomes().len(), 1);
    h.ticks_until("the door is in recovery", |n| n.domain_state().recovery.contains_key(&rid("front-door")));
    assert!(h.node.domain_state().inflight.is_empty(), "settled: nothing left uncertain on record");
    assert_eq!(h.calls().iter().filter(|c| c.starts_with("lock.lock")).count(), 1, "never resent");
}

#[test]
fn settled_actions_leave_nothing_in_flight() {
    let mut h = home();
    assert!(h.req("person:alice", LIGHT, "light.turn_on").is_ok());
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    assert!(h.node.domain_state().inflight.is_empty());
    // a certain failure leaves nothing either
    h.ha.kill();
    std::thread::sleep(Duration::from_millis(100));
    let r = h.req("person:alice", LIGHT, "light.turn_off");
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::DeviceUnavailable), "{}", r.summary());
    assert!(h.node.domain_state().inflight.is_empty());
}

fn lock_request(h: &Home) -> Vec<u8> {
    let r = Requester::new(id("person:alice"), h.keys["person:alice"].clone(), id("service:test"), entropy());
    let bytes = r.sign(h.node.registry(), &id(LOCK), &cap("lock.lock"), Payload::new(), h.node.now());
    h.advance(1);
    bytes
}

/// Audit (v0.2 RC), WAL crash point C: the order is minted and on record, and
/// the node dies before sending it. After the restart its fate is unknown: the
/// node watches the door, finds it did not lock, and never sends it again.
#[test]
fn crash_after_the_order_is_on_record_but_before_it_is_sent() {
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    let bytes = lock_request(&h);
    let Step::Device(pending) = h.node.begin(&bytes) else { panic!("a device action") };
    drop(pending); // the node dies here
    assert_eq!(h.node.domain_state().inflight.len(), 1);
    let mut h = restart(h);
    assert_eq!(h.node.pending_outcomes().len(), 1, "watched as a command that may have run");
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    // the node cannot know it was never sent, and nothing reported after the
    // order: the state from before it is no evidence (F9)
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!((settled["status"].as_str(), settled["execution"].as_str()), (Some("unconfirmed"), Some("unknown")));
    assert!(h.node.domain_state().recovery.contains_key(&rid("front-door")), "a person must look");
    assert_eq!(h.calls(), ["lock.unlock lock.front_door"], "the lock was never sent, and never resent");
}

/// WAL crash point D: the order reached Home Assistant and the node died
/// before the receipt and the outcome were on record. After the restart the
/// witness's next report shows what happened; nothing is sent again.
#[test]
fn crash_after_the_order_was_sent_but_before_its_outcome_is_on_record() {
    let mut h = home();
    assert!(h.req("person:alice", LOCK, "lock.unlock").is_ok());
    let bytes = lock_request(&h);
    let Step::Device(mut pending) = h.node.begin(&bytes) else { panic!("a device action") };
    let _answer = pending.run(); // executed by Home Assistant; the node dies before finishing
    drop(pending);
    let mut h = restart(h);
    // what Home Assistant held from before the restart has no age anyone can
    // tell; the lock's next report, after the order, settles it (F9)
    h.ha.world().set("lock.front_door", "locked", json!({}));
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let settled = h.records("outcome").pop().unwrap();
    assert_eq!((settled["status"].as_str(), settled["execution"].as_str()), (Some("applied"), Some("unknown")));
    assert!(h.node.domain_state().recovery.is_empty());
    assert_eq!(h.calls(), ["lock.unlock lock.front_door", "lock.lock lock.front_door"], "never resent");
}

/// A small deterministic random source for the property test.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Orders the node minted (decisions of physical actions, safe states included).
fn minted(h: &Home) -> usize {
    h.records("decision").iter().filter(|d| d["decision"] == "allow" && d.get("context").is_some()).count()
}

/// Audit (v0.2 RC): random runs of commands, Home Assistant faults, crashes at
/// the write-ahead record's critical points, restarts, outages and time. After
/// every run, whatever happened:
/// - no command reached Home Assistant more often than orders were minted
///   (nothing is ever sent twice);
/// - once Home Assistant is back and time has passed, nothing is left
///   uncertain: no pending outcome, nothing in flight;
/// - every broken or unknowable promise on the door (medium/high) ended in
///   recovery, and the door is in recovery only because of one.
///
/// `CHITALA_PROPERTY_SEEDS` raises the number of runs (default 12).
#[test]
fn random_faults_crashes_and_restarts_keep_every_invariant() {
    let seeds: u64 = std::env::var("CHITALA_PROPERTY_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(12);
    for seed in 1..=seeds {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0x2545_F491_4F6C_DD1D));
        let mut h = home();
        let (mut minted_total, mut outcomes) = (0usize, Vec::<Value>::new());
        // orders a crash caught after they were minted: each must be judged after the restart
        let mut crashed = Vec::<String>::new();
        let mut log = Vec::new();
        for _ in 0..18 {
            let op = rng.below(10);
            log.push(op);
            match op {
                0..=3 => {
                    let b = match rng.below(9) {
                        0 => Behaviour::Instant,
                        1 => Behaviour::Moving,
                        2 => Behaviour::Stuck,
                        3 => Behaviour::LoseAfterSend,
                        4 => Behaviour::LoseWithoutEffect,
                        5 => Behaviour::LoseAndDie,
                        6 => Behaviour::DropsOff,
                        7 => Behaviour::Error("service_validation_error"),
                        _ => Behaviour::Error("home_assistant_error"),
                    };
                    h.ha.behave("lock.front_door", b);
                    let c = if rng.below(2) == 0 { "lock.lock" } else { "lock.unlock" };
                    let _ = h.req("person:alice", LOCK, c);
                }
                4 => {
                    let c = if rng.below(2) == 0 { "light.turn_on" } else { "light.turn_off" };
                    let _ = h.req("person:alice", LIGHT, c);
                }
                5 => {
                    // crash point C or D on a lock command
                    let bytes = lock_request(&h);
                    if let Step::Device(mut p) = h.node.begin(&bytes) {
                        if rng.below(2) == 0 {
                            let _ = p.run();
                        }
                        let decided = h.records("decision").pop().unwrap();
                        crashed.push(decided["mid"].as_str().unwrap().to_string());
                    }
                    minted_total += minted(&h);
                    outcomes.extend(h.records("outcome"));
                    h = restart(h);
                }
                6 => {
                    minted_total += minted(&h);
                    outcomes.extend(h.records("outcome"));
                    h = restart(h);
                }
                7 => {
                    let up = rng.below(2) == 0;
                    let mut w = h.ha.world();
                    w.ws_up = up;
                    w.rest_up = up;
                    if !up {
                        w.restarts += 1;
                    }
                }
                8 => {
                    // a moving lock arrives somewhere
                    let s = if rng.below(2) == 0 { "locked" } else { "unlocked" };
                    h.ha.world().set("lock.front_door", s, json!({}));
                }
                _ => {
                    for _ in 0..rng.below(4) + 1 {
                        h.advance(1_500);
                        h.node.tick();
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
            }
        }
        // quiescence: Home Assistant back, time passes
        {
            let mut w = h.ha.world();
            w.ws_up = true;
            w.rest_up = true;
        }
        for _ in 0..12 {
            h.advance(1_000);
            h.node.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
        minted_total += minted(&h);
        outcomes.extend(h.records("outcome"));
        let ctx = format!("seed {seed}, ops {log:?}");
        assert!(h.calls().len() <= minted_total, "{ctx}: {} calls for {minted_total} orders", h.calls().len());
        assert!(h.node.pending_outcomes().is_empty(), "{ctx}: still pending");
        assert!(h.node.domain_state().inflight.is_empty(), "{ctx}: still in flight");
        let broken = outcomes.iter().any(|o| {
            o["resource"] == "resource:front-door"
                && o["safe_state"] != true
                && matches!(o["status"].as_str(), Some("diverged" | "unconfirmed"))
        });
        for mid in &crashed {
            let judged = outcomes.iter().filter(|o| o["mid"] == mid.as_str()).count();
            assert_eq!(judged, 1, "{ctx}: the order {mid} caught by a crash was judged {judged} times");
        }
        let recovering = h.node.domain_state().recovery.contains_key(&rid("front-door"));
        assert_eq!(recovering, broken, "{ctx}: recovery iff a broken or unknowable promise on the door");
    }
}
