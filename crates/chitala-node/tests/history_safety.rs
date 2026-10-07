//! `SAFE-10-HISTORY` through the node (spec 32), and what is tried against
//! it. History may make Safety stricter; it never supplies evidence that
//! turns a DENY into an ALLOW.
//!
//! The fan of the sample home plays a pump: at most 30 minutes on in a row.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_history::eval::{EvalRequest, Evaluator, HistoryEvaluator, LogEvaluator};
use chitala_history::log::HistoryLog;
use chitala_history::Record;
use chitala_history_check::SignedConstraint;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::Intent;
use chitala_model::{payload, CapabilityId, EntityId, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response};
use chitala_platform::{memory, Storage, StoragePath};
use chitala_resource::ResourceId;
use chitala_token::bytes_from_base64;

const T0: u64 = 1_790_000_000_000;
const MIN: u64 = 60_000;
const FAN: &str = "device:fan-plug";
const FAN_R: &str = "resource:fan";
const EVALUATOR: &str = "service:history";

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}

fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}

fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(memory::test_entropy())
}

const PEOPLE: [(&str, &[&str], &[&str]); 5] = [
    ("person:alice", &["owner"], &[]),
    ("person:guest", &["guest"], &[]),
    ("ai:assistant", &[], &["person:alice"]),
    (EVALUATOR, &[], &[]),
    ("service:impostor", &[], &[]),
];

struct Home {
    node: Node,
    clock: Arc<AtomicU64>,
    keys: std::collections::HashMap<String, Keypair>,
    history: HistoryLog,
    storage: Arc<dyn Storage>,
    path: StoragePath,
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
    let boundary = TrustedExecutionBoundary::new(entropy());
    let mut node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: Keypair::from_seed(&test_seed("service:node")),
        authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
        principals,
        agency,
        devices: sample_devices(),
        resources: sample_resources(),
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
    let (platform, _) = memory::platform("history-safety", 0);
    let storage = Arc::clone(&platform.storage);
    let path = StoragePath::new("history.jsonl").unwrap();
    let evaluator = Evaluator::new(id(EVALUATOR), "test", keys[EVALUATOR].clone());
    node.set_history_evaluator(
        id(EVALUATOR),
        Arc::new(LogEvaluator::new(evaluator, Arc::clone(&storage), path.clone())),
    );
    let history = HistoryLog::new(Arc::clone(&storage), path.clone());
    Home { node, clock, keys, history, storage, path }
}

impl Home {
    fn req(&mut self, who: &str, target: &str, c: &str, pl: Payload) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now());
        self.clock.fetch_add(1, Ordering::SeqCst);
        self.node.handle(&bytes)
    }

    fn domain(&mut self, who: &str, c: &str, pl: Payload) -> Response {
        self.req(who, "domain:home", c, pl)
    }

    /// The owner sets the pump's rule: at most `minutes` on in a row.
    fn continuous_rule(&mut self, minutes: u64) -> Response {
        self.domain("person:alice", "domain.history_rule_set", rule(minutes))
    }

    /// The fan's history: `(minutes before now, Some(on) | None for lost)`.
    fn ran(&mut self, events: &[(u64, Option<bool>)]) {
        for (ago, on) in events {
            let at = T0 - ago * MIN;
            let r = match on {
                Some(v) => Record::Observed { device: id(FAN), at, observed_at: at, state: payload([("on", *v)]) },
                None => Record::Unobservable { device: id(FAN), at },
            };
            self.history.append(&r).unwrap();
        }
    }

    fn turn_on(&mut self) -> Response {
        self.req("person:alice", FAN, "switch.turn_on", Payload::new())
    }
}

fn rule(minutes: u64) -> Payload {
    payload([
        ("resource", ParamValue::from(FAN_R)),
        ("rule_id", ParamValue::from("pump-continuous")),
        ("capability", ParamValue::from("switch.turn_on")),
        ("key", ParamValue::from("on")),
        ("value", ParamValue::from("true")),
        ("predicate", ParamValue::from("max_continuous_ms")),
        ("limit", ParamValue::Int(i64::try_from(minutes * MIN).unwrap())),
        ("max_unknown_ms", ParamValue::Int(i64::try_from(5 * MIN).unwrap())),
    ])
}

fn refused(r: &Response, cause: &str) -> bool {
    !r.is_ok() && r.summary().contains("SAFE-10-HISTORY") && r.summary().contains(cause)
}

/// Without a rule nothing changes; with one, the pump's own history decides
/// whether it adds a denial, and each cause is told apart.
#[test]
fn a_history_rule_adds_a_denial_and_says_why() {
    let mut h = home();
    h.ran(&[(60, Some(false)), (35, Some(true))]);
    assert!(h.turn_on().is_ok(), "no rule: history adds nothing");
    let r = h.continuous_rule(30);
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(r.result.as_ref().unwrap()["version"], 1);
    assert!(refused(&h.turn_on(), "LIMIT_EXCEEDED"), "on for 35 minutes");
    assert!(h.req("person:alice", FAN, "switch.turn_off", Payload::new()).is_ok(), "turning it off is not governed");
    // a second fan history: on 20, unknown 15, on 5: possibly 40
    let mut h = home();
    h.ran(&[(60, Some(false)), (40, Some(true)), (20, None), (5, Some(true))]);
    assert!(h.continuous_rule(30).is_ok());
    assert!(refused(&h.turn_on(), "INSUFFICIENT_HISTORY"));
    // and one that kept to its limit: history adds no denial
    let mut h = home();
    h.ran(&[(60, Some(false)), (10, Some(true))]);
    assert!(h.continuous_rule(30).is_ok());
    let r = h.turn_on();
    assert!(r.is_ok(), "{}", r.summary());
}

/// Rules are the owners' (and admins' explicitly allowed): never an AI's,
/// whatever its token; not a guest's. A rule never governs a stop or a
/// resource's safe state. Each change is a new version, bumps the epoch, and
/// removing the rule returns the domain to what it was.
#[test]
fn rules_are_set_by_owners_only_and_versioned() {
    let mut h = home();
    let token = {
        let pl = payload([
            ("holder", ParamValue::from("ai:assistant")),
            ("target", ParamValue::from("domain:home")),
            ("capability", ParamValue::from("domain.history_rule_set")),
            ("ttl_s", ParamValue::Int(600)),
        ]);
        let r = h.domain("person:alice", "domain.delegate", pl);
        r.result.and_then(|v| v["token"].as_str().map(|t| bytes_from_base64(t).unwrap()))
    };
    let mut i = Intent::new(
        chitala_intent::new_intent_id(memory::test_entropy()),
        id("ai:assistant"),
        id("person:alice"),
        cap("domain.history_rule_set"),
        ResourceId::parse("resource:home").unwrap(),
        h.node.now(),
        60_000,
    );
    i.params = rule(30);
    i.authority = token;
    let r = h.node.handle(&i.sign(&h.keys["ai:assistant"]));
    assert!(!r.is_ok() && r.summary().contains("E_UNSUPPORTED_BY_TARGET"), "not through an intent: {}", r.summary());
    // nor as a request, with a token for it: the default policy forbids it (C11)
    let r = Requester::new(id("ai:assistant"), h.keys["ai:assistant"].clone(), id("service:test"), entropy())
        .with_token(i.authority.clone());
    let bytes = r.sign(h.node.registry(), &id("domain:home"), &cap("domain.history_rule_set"), rule(30), h.node.now());
    let r = h.node.handle(&bytes);
    assert!(!r.is_ok() && r.summary().contains("E_INTENT_REQUIRED"), "an AI sends no commands: {}", r.summary());
    // (and the default policy forbids it the rules anyway, C11: chitala-policy's tests)
    assert!(!h.domain("person:guest", "domain.history_rule_set", rule(30)).is_ok(), "not a guest");
    let epoch = h.node.domain_state().epoch;
    assert_eq!(h.continuous_rule(30).result.unwrap()["version"], 1);
    assert_eq!(h.continuous_rule(45).result.unwrap()["version"], 2, "a new version");
    assert!(h.node.domain_state().epoch > epoch, "the epoch moved");
    let mut stop = rule(30);
    stop.insert("capability".into(), ParamValue::from("switch.turn_off"));
    stop.insert("resource".into(), ParamValue::from("resource:front-door"));
    stop.insert("capability".into(), ParamValue::from("lock.lock"));
    let r = h.domain("person:alice", "domain.history_rule_set", stop);
    assert!(!r.is_ok() && r.summary().contains("safe state"), "{}", r.summary());
    h.ran(&[(60, Some(false)), (50, Some(true))]);
    assert!(refused(&h.turn_on(), "LIMIT_EXCEEDED"));
    let remove = payload([("resource", ParamValue::from(FAN_R)), ("rule_id", ParamValue::from("pump-continuous"))]);
    assert!(h.domain("person:alice", "domain.history_rule_remove", remove).is_ok());
    assert!(h.turn_on().is_ok(), "no rule, nothing added");
}

/// What an evaluator answers.
type Answer = Box<dyn Fn(&EvalRequest) -> Result<Vec<SignedConstraint>, String> + Send + Sync>;

/// An evaluator that answers what the test says.
struct Fake(Answer);

impl HistoryEvaluator for Fake {
    fn evaluate(&self, req: &EvalRequest) -> Result<Vec<SignedConstraint>, String> {
        (self.0)(req)
    }
}

/// What is tried against the records: no answer, a forged one, one from
/// another evaluator, from a quarantined evaluator, or one replayed from an
/// earlier request. Each is EVALUATOR_UNAVAILABLE: fail closed, for the
/// governed action only.
#[test]
fn records_that_cannot_be_trusted_fail_closed() {
    let real = |h: &Home| {
        let ev = Evaluator::new(id(EVALUATOR), "test", h.keys[EVALUATOR].clone());
        LogEvaluator::new(ev, Arc::clone(&h.storage), h.path.clone())
    };
    let setup = || {
        let mut h = home();
        h.ran(&[(60, Some(false)), (10, Some(true))]);
        assert!(h.continuous_rule(30).is_ok());
        assert!(h.turn_on().is_ok(), "the real evaluator passes it through");
        h
    };
    // down
    let mut h = setup();
    h.node.set_history_evaluator(id(EVALUATOR), Arc::new(Fake(Box::new(|_| Err("timed out".into())))));
    assert!(refused(&h.turn_on(), "EVALUATOR_UNAVAILABLE"));
    assert!(h.req("person:alice", FAN, "switch.turn_off", Payload::new()).is_ok(), "only the governed action");
    // forged: the right name, another key
    let mut h = setup();
    let forged = Evaluator::new(id(EVALUATOR), "test", h.keys["service:impostor"].clone());
    h.node.set_history_evaluator(
        id(EVALUATOR),
        Arc::new(LogEvaluator::new(forged, Arc::clone(&h.storage), h.path.clone())),
    );
    assert!(refused(&h.turn_on(), "signature"));
    // another evaluator, signing as itself
    let mut h = setup();
    let other = Evaluator::new(id("service:impostor"), "test", h.keys["service:impostor"].clone());
    h.node.set_history_evaluator(
        id(EVALUATOR),
        Arc::new(LogEvaluator::new(other, Arc::clone(&h.storage), h.path.clone())),
    );
    assert!(refused(&h.turn_on(), "not the authorized evaluator"));
    // the authorized evaluator, quarantined
    let mut h = setup();
    let pl = payload([("principal", ParamValue::from(EVALUATOR)), ("state", ParamValue::from("quarantined"))]);
    let r = h.domain("person:alice", "domain.set_principal_state", pl);
    assert!(r.is_ok(), "{}", r.summary());
    assert!(refused(&h.turn_on(), "EVALUATOR_UNAVAILABLE"));
    // replayed: the answer to the first request, given again
    let mut h = setup();
    let first: Arc<Mutex<Option<Vec<SignedConstraint>>>> = Arc::default();
    let (inner, kept) = (real(&h), Arc::clone(&first));
    h.node.set_history_evaluator(
        id(EVALUATOR),
        Arc::new(Fake(Box::new(move |req| {
            let mut kept = kept.lock().unwrap();
            if kept.is_none() {
                *kept = Some(inner.evaluate(req)?);
            }
            Ok(kept.clone().unwrap())
        }))),
    );
    assert!(h.turn_on().is_ok(), "the first answer is its own");
    assert!(refused(&h.turn_on(), "another request"), "the same answer, replayed");
}

/// An AI's intent is checked the same way, and its decision record keeps
/// what SAFE-10 was given: the context digest and the signed records.
#[test]
fn an_ai_s_intent_is_held_to_the_same_history() {
    let mut h = home();
    h.ran(&[(60, Some(false)), (45, Some(true))]);
    assert!(h.continuous_rule(30).is_ok());
    let pl = payload([
        ("holder", ParamValue::from("ai:assistant")),
        ("target", ParamValue::from(FAN_R)),
        ("capability", ParamValue::from("switch.turn_on")),
        ("ttl_s", ParamValue::Int(600)),
    ]);
    let r = h.domain("person:alice", "domain.delegate", pl);
    let token = bytes_from_base64(r.result.unwrap()["token"].as_str().unwrap()).unwrap();
    let mut i = Intent::new(
        chitala_intent::new_intent_id(memory::test_entropy()),
        id("ai:assistant"),
        id("person:alice"),
        cap("switch.turn_on"),
        ResourceId::parse(FAN_R).unwrap(),
        h.node.now(),
        60_000,
    );
    i.authority = Some(token);
    let r = h.node.handle(&i.sign(&h.keys["ai:assistant"]));
    assert!(refused(&r, "LIMIT_EXCEEDED"), "{}", r.summary());
}
