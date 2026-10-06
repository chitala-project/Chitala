//! `device.read_history` (spec 29): history is read through the node, as a
//! capability, under Authority like any other access; never as the log. A
//! person reads what policy lets them; an AI only what a token grants, on a
//! resource that exposes it; the answer is a summary, never the records.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_history::Record;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::Intent;
use chitala_model::{payload, CapabilityId, EntityId, ExecCode, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response};
use chitala_resource::ResourceId;
use chitala_token::bytes_from_base64;
use serde_json::json;

const T0: u64 = 1_790_000_000_000;
const LIGHT: &str = "device:living-room-light";
const LIGHT_R: &str = "resource:living-room-light";
const DOOR_R: &str = "resource:front-door";
const FAN_R: &str = "resource:fan";
const HOUR: u64 = 3_600_000;

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}

fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}

fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

const PEOPLE: [(&str, &[&str], &[&str]); 6] = [
    ("person:alice", &["owner"], &[]),
    ("person:bob", &["adult"], &[]),
    ("person:guest", &["guest"], &[]),
    ("person:kid", &["child"], &[]),
    ("ai:assistant", &[], &["person:alice"]),
    ("ai:other", &[], &["person:alice"]),
];

struct Home {
    node: Node,
    clock: Arc<AtomicU64>,
    keys: std::collections::HashMap<String, Keypair>,
}

/// The light was off, then on for the last half hour.
fn history() -> Vec<Record> {
    let on = |at, v: bool| Record::Observed { device: id(LIGHT), at, observed_at: at, state: payload([("on", v)]) };
    vec![on(T0 - HOUR, false), on(T0 - HOUR / 2, true)]
}

/// The sample home, where every resource offers its device's history but
/// the fan's. `with_history`: whether
/// the node keeps one.
fn home(with_history: bool) -> Home {
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
    let mut resources = sample_resources();
    for r in &mut resources {
        if r.id.to_string() == FAN_R {
            r.bindings.retain(|b| b.capability.as_str() != "device.read_history");
        }
    }
    let mut mock = MockAdapter::new();
    for d in sample_devices() {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).unwrap());
    }
    let boundary = TrustedExecutionBoundary::new(entropy());
    let mut node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: Keypair::from_seed(&test_seed("service:node")),
        authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
        principals,
        agency,
        devices: sample_devices(),
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
    if with_history {
        node.set_history(Arc::new(history()));
    }
    Home { node, clock, keys }
}

/// The light's time on over the last hour.
fn on_last_hour() -> Payload {
    payload([("key", ParamValue::from("on")), ("value", ParamValue::from("true")), ("since_s", ParamValue::Int(3_600))])
}

impl Home {
    fn req(&mut self, who: &str, target: &str, c: &str, pl: Payload) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now());
        self.clock.fetch_add(1, Ordering::SeqCst);
        self.node.handle(&bytes)
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

    /// An AI asks for the history of `resource`, with `token` if any.
    fn ai_reads(&mut self, ai: &str, resource: &str, token: Option<&[u8]>) -> Response {
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id(ai),
            id("person:alice"),
            cap("device.read_history"),
            ResourceId::parse(resource).unwrap(),
            self.node.now(),
            120_000,
        );
        i.params = on_last_hour();
        i.authority = token.map(<[u8]>::to_vec);
        let bytes = i.sign(&self.keys[ai]);
        self.clock.fetch_add(1, Ordering::SeqCst);
        self.node.handle(&bytes)
    }
}

/// The answer for the light's last hour, by the history's own arithmetic:
/// off, then on since half an hour before `T0` (the clock moves on by a
/// millisecond a request).
fn the_light_s_last_hour(v: &serde_json::Value) {
    let to = v["to_ms"].as_u64().unwrap();
    let on = to - (T0 - HOUR / 2);
    assert_eq!(v["from_ms"], json!(to - HOUR), "{v}");
    assert_eq!(
        [
            &v["in_value_ms"],
            &v["known_ms"],
            &v["unknown_ms"],
            &v["transitions"],
            &v["longest_run_ms"],
            &v["current_run_ms"]
        ],
        [&json!(on), &json!(HOUR), &json!(0), &json!(1), &json!(on), &json!(on)],
        "{v}"
    );
    assert_eq!(v["utilization"], json!(on as f64 / HOUR as f64), "{v}");
}

fn denied(r: &Response) -> bool {
    !r.is_ok() && r.error.as_ref().is_none_or(|e| e.code != ExecCode::Internal)
}

/// The owner reads the light's history: a summary, by the history's own
/// arithmetic, and nothing of the log itself.
#[test]
fn the_owner_reads_a_summary_never_the_log() {
    let mut h = home(true);
    let r = h.req("person:alice", LIGHT, "device.read_history", on_last_hour());
    assert!(r.is_ok(), "{}", r.summary());
    let v = r.result.unwrap();
    the_light_s_last_hour(&v);
    assert_eq!(v["value"], json!(true));
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert!(!keys.iter().any(|k| k.contains("record") || *k == "state" || *k == "timeline"), "{keys:?}");
}

/// Reading history is of medium risk: it shows when people are home. By the
/// default policy an adult may; a guest and a child may not.
#[test]
fn a_guest_and_a_child_cannot_read_history_by_default() {
    let mut h = home(true);
    assert!(h.req("person:bob", LIGHT, "device.read_history", on_last_hour()).is_ok());
    for who in ["person:guest", "person:kid"] {
        let r = h.req(who, LIGHT, "device.read_history", on_last_hour());
        assert!(denied(&r), "{who}: {}", r.summary());
    }
    // while the state now, low risk, they may read
    assert!(h.req("person:guest", LIGHT, "device.read_state", Payload::new()).is_ok());
}

/// An AI reads history only with a token, only on the resource it was
/// given, and only on a resource that exposes its device's history.
#[test]
fn an_ai_reads_only_the_history_it_was_given() {
    let mut h = home(true);
    assert!(denied(&h.ai_reads("ai:assistant", LIGHT_R, None)), "no token, no history");
    let token = h.delegate("ai:assistant", LIGHT_R, "device.read_history");
    let r = h.ai_reads("ai:assistant", LIGHT_R, Some(&token));
    assert!(r.is_ok(), "{}", r.summary());
    let v = r.result.unwrap();
    the_light_s_last_hour(&v);
    assert!(denied(&h.ai_reads("ai:assistant", DOOR_R, Some(&token))), "the door was not given");
    assert!(denied(&h.ai_reads("ai:other", LIGHT_R, Some(&token))), "another AI's token");
    // a resource that does not expose its history: not even its owner can
    // hand it over
    let pl = payload([
        ("holder", ParamValue::from("ai:assistant")),
        ("target", ParamValue::from(FAN_R)),
        ("capability", ParamValue::from("device.read_history")),
        ("ttl_s", ParamValue::Int(3600)),
    ]);
    let r = h.req("person:alice", "domain:home", "domain.delegate", pl);
    assert!(!r.is_ok() && r.summary().contains("offers device.read_history"), "{}", r.summary());
}

/// A node that keeps no history says so; a window outside the bounds is
/// refused before anything is read.
#[test]
fn no_history_and_bad_windows_are_said_plainly() {
    let mut h = home(false);
    let r = h.req("person:alice", LIGHT, "device.read_history", on_last_hour());
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::Internal), "{}", r.summary());
    assert!(r.summary().contains("keeps no history"), "{}", r.summary());
    let mut h = home(true);
    for since in [10, 40 * 24 * 3_600] {
        let mut pl = on_last_hour();
        pl.insert("since_s".into(), ParamValue::Int(since));
        let r = h.req("person:alice", LIGHT, "device.read_history", pl);
        assert!(!r.is_ok(), "since {since}: {}", r.summary());
    }
}
