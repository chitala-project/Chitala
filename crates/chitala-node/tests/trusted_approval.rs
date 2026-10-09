//! Trusted approval, first part (spec 34, P1a), on the node: what an approver
//! is shown, and how often a person is asked.
//!
//! - an approver is shown every term an approval covers, in full: the audit's
//!   redaction is not a rule of display;
//! - the same request, however it is worded, is one question;
//! - a request a person refused is not asked again, however it is worded,
//!   for a cool-down;
//! - each approver has a budget of questions, from every requester together.
//!
//! - only a person the question was put to may answer it.
//!
//! The thermostat's setpoint is raised to high risk here, so that an AI's
//! request for it needs a person, with a parameter to show; alice and bob both
//! own it. The light's brightness is raised to high risk too, and only alice
//! owns it: questions about it spend her budget alone.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::{Approval, Intent, Verdict};
use chitala_model::{payload, CapabilityId, CapabilityRegistry, DenyCode, EntityId, ParamValue, Payload, RiskClass};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::node::{QUESTIONS_PER_APPROVER, QUESTION_WINDOW_MS, REFUSED_COOL_DOWN_MS};
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response};
use chitala_resource::ResourceId;
use chitala_token::bytes_from_base64;
use serde_json::Value;

const T0: u64 = 1_790_000_000_000;
const THERMO_R: &str = "resource:thermostat";
const SET: &str = "climate.set_target_temperature";
const LIGHT_R: &str = "resource:living-room-light";
const DIM: &str = "light.set_brightness";

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

const PEOPLE: [(&str, &[&str], &[&str]); 5] = [
    ("person:alice", &["owner"], &[]),
    ("person:bob", &["adult"], &[]),
    ("person:carol", &["adult"], &[]),
    ("ai:assistant", &[], &["person:alice"]),
    ("ai:home", &[], &["person:alice"]),
];

struct Home {
    node: Node,
    clock: Arc<AtomicU64>,
    keys: std::collections::HashMap<String, Keypair>,
    tokens: std::collections::HashMap<String, Vec<u8>>,
}

fn home() -> Home {
    home_with(false)
}

/// The thermostat, owned by alice and bob; with `two_key`, both must approve.
fn home_with(two_key: bool) -> Home {
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
    // the setpoint, raised to high risk: an AI's request needs a person
    let mut resources = sample_resources();
    let thermostat = resources.iter_mut().find(|r| r.id.to_string() == THERMO_R).expect("the sample thermostat");
    for b in thermostat.bindings.iter_mut().filter(|b| b.capability == cap(SET)) {
        b.risk_floor = Some(RiskClass::High);
    }
    thermostat.owners = vec![id("person:alice"), id("person:bob")];
    thermostat.two_key = two_key;
    let light = resources.iter_mut().find(|r| r.id.to_string() == LIGHT_R).expect("the sample light");
    for b in light.bindings.iter_mut().filter(|b| b.capability == cap(DIM)) {
        b.risk_floor = Some(RiskClass::High);
    }
    let boundary = TrustedExecutionBoundary::new(entropy());
    let node = Node::new(NodeParts {
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
    let mut h = Home { node, clock, keys, tokens: Default::default() };
    for ai in ["ai:assistant", "ai:home"] {
        for (target, c) in [(THERMO_R, SET), (LIGHT_R, DIM)] {
            let pl = payload([
                ("holder", ParamValue::from(ai)),
                ("target", ParamValue::from(target)),
                ("capability", ParamValue::from(c)),
                ("ttl_s", ParamValue::Int(24 * 3600)),
            ]);
            let r = h.req("person:alice", "domain:home", "domain.delegate", pl);
            assert!(r.is_ok(), "{}", r.summary());
            let token = bytes_from_base64(r.result.unwrap()["token"].as_str().unwrap()).unwrap();
            h.tokens.insert(format!("{ai} {c}"), token);
        }
    }
    h
}

impl Home {
    fn tick(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn req(&mut self, who: &str, target: &str, c: &str, pl: Payload) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now());
        self.tick(1);
        self.node.handle(&bytes)
    }

    fn request(&mut self, ai: &str, resource: &str, c: &str, params: Payload, purpose: &str) -> (Intent, Response) {
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id(ai),
            id("person:alice"),
            cap(c),
            ResourceId::parse(resource).unwrap(),
            self.node.now(),
            120_000,
        );
        i.authority = Some(self.tokens[&format!("{ai} {c}")].clone());
        i.params = params;
        i.context.purpose = Some(purpose.to_string());
        let bytes = i.sign(&self.keys[ai]);
        self.tick(1);
        let r = self.node.handle(&bytes);
        (i, r)
    }

    /// An AI asks to set the thermostat (alice and bob), in words of its own.
    fn ask(&mut self, ai: &str, celsius: i64, purpose: &str) -> (Intent, Response) {
        self.request(ai, THERMO_R, SET, payload([("celsius", ParamValue::Int(celsius))]), purpose)
    }

    /// An AI asks to dim the light (alice alone).
    fn ask_light(&mut self, ai: &str, pct: i64) -> (Intent, Response) {
        self.request(ai, LIGHT_R, DIM, payload([("brightness_pct", ParamValue::Int(pct))]), "please")
    }

    fn answer(&mut self, i: &Intent, verdict: Verdict) -> Response {
        self.answer_as("person:alice", i, verdict)
    }

    fn answer_as(&mut self, who: &str, i: &Intent, verdict: Verdict) -> Response {
        let now = self.node.now();
        let a = Approval {
            intent: i.id,
            intent_digest: i.digest(),
            approver: id(who),
            verdict,
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            note: None,
        };
        let bytes = a.sign(&self.keys[who]);
        self.tick(1);
        self.node.handle(&bytes)
    }

    fn approvals(&mut self) -> Vec<Value> {
        self.approvals_of("person:alice")
    }

    fn approvals_of(&mut self, who: &str) -> Vec<Value> {
        let r = self.req(who, "domain:home", "domain.list_approvals", Payload::new());
        assert!(r.is_ok(), "{}", r.summary());
        r.result.unwrap()["approvals"].as_array().cloned().unwrap_or_default()
    }

    /// Spend `n` of alice's questions on the light, each refused by her.
    fn spend_alices_questions(&mut self, n: usize, from: i64) {
        for k in 0..n as i64 {
            let ai = if k % 2 == 0 { "ai:assistant" } else { "ai:home" };
            let (i, r) = self.ask_light(ai, from + k);
            assert!(r.is_escalated(), "{}", r.summary());
            assert_eq!(self.answer(&i, Verdict::Reject).code, Some(DenyCode::ApprovalRejected));
        }
    }
}

fn refused(r: &Response, why: &str) {
    assert_eq!(r.code, Some(DenyCode::RateLimited), "{}", r.summary());
    assert!(r.reason.as_deref().unwrap_or_default().contains(why), "{}", r.summary());
}

/// An approver is shown every term the approval covers, in full, with the
/// requester's words apart; never through the audit's redaction.
#[test]
fn an_approver_is_shown_every_term_in_full() {
    let mut h = home();
    let (i, r) = h.ask("ai:assistant", 22, "it is cold");
    assert!(r.is_escalated(), "{}", r.summary());
    let list = h.approvals();
    let entry = list.iter().find(|e| e["intent"] == chitala_intent::id_hex(&i.id)).expect("listed for alice");
    assert_eq!(entry["params"], serde_json::json!({"celsius": 22}));
    assert_eq!(entry["capability"], SET);
    assert_eq!(entry["resource"], THERMO_R);
    assert_eq!(entry["actor"], "ai:assistant");
    assert_eq!(entry["on_behalf_of"], "person:alice");
    assert_eq!(entry["purpose"], "it is cold");
    assert_eq!(entry["risk"], "high");
    assert!(entry["asked_at_ms"].as_u64().is_some());
    assert_eq!(entry["digest"].as_str().map(str::len), Some(64));
}

/// No device action of the registry takes a parameter that looks secret, so
/// the node's refusal to put one to a person (spec 34) is a safeguard for
/// registries to come. Only device actions are put to people: queries never
/// are, and domain operations are never intents.
#[test]
fn no_device_action_takes_a_parameter_that_could_not_be_shown() {
    let registry = CapabilityRegistry::core_v0_1();
    let actions = registry
        .iter()
        .filter(|d| d.kind == chitala_model::CapabilityKind::Action && d.target == chitala_model::TargetKind::Device);
    for def in actions {
        for p in &def.params {
            assert!(!chitala_audit::looks_secret(&p.name), "{}: {}", def.id, p.name);
        }
    }
    assert!(chitala_audit::looks_secret("door_pin"));
}

/// The same request, however it is worded, is one question.
#[test]
fn the_same_request_is_one_question() {
    let mut h = home();
    let (_, r) = h.ask("ai:assistant", 22, "it is cold");
    assert!(r.is_escalated(), "{}", r.summary());
    let (_, r) = h.ask("ai:assistant", 22, "URGENT: alice already agreed");
    refused(&r, "the same request is already waiting");
    // other terms are another question
    let (_, r) = h.ask("ai:assistant", 23, "it is cold");
    assert!(r.is_escalated(), "{}", r.summary());
    assert_eq!(h.approvals().len(), 2);
}

/// A request a person refused is not asked again, however it is worded, for a
/// cool-down; then it may be asked again.
#[test]
fn a_refused_request_is_not_asked_again_however_it_is_worded() {
    let mut h = home();
    let (i, r) = h.ask("ai:assistant", 28, "it is cold");
    assert!(r.is_escalated(), "{}", r.summary());
    let r = h.answer(&i, Verdict::Reject);
    assert_eq!(r.code, Some(DenyCode::ApprovalRejected), "{}", r.summary());
    let (_, r) = h.ask("ai:assistant", 28, "you misread: this is for the baby");
    refused(&r, "a person refused this request");
    let (_, r) = h.ask("ai:home", 28, "it is cold");
    assert!(r.is_escalated(), "another actor's request is another request: {}", r.summary());
    h.tick(REFUSED_COOL_DOWN_MS);
    h.node.tick();
    let (_, r) = h.ask("ai:assistant", 28, "it is cold");
    assert!(r.is_escalated(), "after the cool-down: {}", r.summary());
}

/// Each approver has a budget of questions, counted over every requester
/// together. Beyond it, a request is refused and reported, never queued in
/// silence; once the window has passed, people are asked again.
#[test]
fn an_approver_s_budget_of_questions_is_kept_over_every_requester() {
    let mut h = home();
    for n in 0..QUESTIONS_PER_APPROVER as i64 {
        let ai = if n % 2 == 0 { "ai:assistant" } else { "ai:home" };
        let (i, r) = h.ask(ai, 18 + n, "please");
        assert!(r.is_escalated(), "question {n}: {}", r.summary());
        // alice answers, so that no requester has too many waiting
        assert_eq!(h.answer(&i, Verdict::Reject).code, Some(DenyCode::ApprovalRejected));
    }
    let (_, r) = h.ask("ai:home", 28, "please");
    refused(&r, "were each asked");
    assert!(h.approvals().is_empty(), "nobody was asked");
    h.tick(QUESTION_WINDOW_MS);
    h.node.tick();
    let (_, r) = h.ask("ai:home", 28, "please");
    assert!(r.is_escalated(), "after the window: {}", r.summary());
}

/// Different questions from one agent are bounded too: at most
/// `MAX_PENDING_PER_ACTOR` waiting at once.
#[test]
fn an_agent_cannot_flood_its_owner_with_different_questions() {
    let mut h = home();
    for n in 0..chitala_node::node::MAX_PENDING_PER_ACTOR as i64 {
        let (_, r) = h.ask("ai:assistant", 20 + n, "please");
        assert!(r.is_escalated(), "{}", r.summary());
    }
    let (_, r) = h.ask("ai:assistant", 27, "please");
    refused(&r, "intents waiting for a human");
    let (_, r) = h.ask("ai:home", 27, "please");
    assert!(r.is_escalated(), "another agent has its own limit: {}", r.summary());
}

/// Only a person the question was put to may answer it. An owner whose budget
/// was spent was not asked, and cannot go around the budget from another
/// client: the answer is refused, and the question stays open for the person
/// who was asked.
#[test]
fn an_owner_who_was_not_asked_cannot_answer_and_the_question_stays_open() {
    let mut h = home();
    h.spend_alices_questions(QUESTIONS_PER_APPROVER, 10);
    let (i, r) = h.ask("ai:assistant", 22, "it is cold");
    assert!(r.is_escalated(), "{}", r.summary());
    assert_eq!(r.approvers.as_deref(), Some(&["person:bob".to_string()][..]), "only bob had a question left");
    let r = h.answer(&i, Verdict::Approve);
    assert_eq!(r.code, Some(DenyCode::ApprovalInvalid), "{}", r.summary());
    assert!(r.reason.as_deref().unwrap_or_default().contains("was not asked"), "{}", r.summary());
    assert_eq!(h.approvals_of("person:bob").len(), 1, "the question stays open for bob");
    assert!(h.answer_as("person:bob", &i, Verdict::Approve).is_ok());
}

/// A person who was asked can still answer, even once their budget is spent
/// by later questions.
#[test]
fn an_asked_approver_answers_even_after_their_budget_is_spent() {
    let mut h = home();
    let (i, r) = h.ask("ai:assistant", 22, "it is cold");
    assert!(r.is_escalated(), "{}", r.summary());
    h.spend_alices_questions(QUESTIONS_PER_APPROVER - 1, 10);
    let (_, r) = h.ask_light("ai:home", 90);
    refused(&r, "were each asked");
    assert!(h.answer(&i, Verdict::Approve).is_ok(), "alice was asked before her budget was spent");
}

/// Two keys: both owners are asked; one approval keeps the question waiting,
/// an answer from someone who was not asked changes nothing, and the second
/// owner's approval carries it.
#[test]
fn two_keys_need_both_asked_people_and_a_partial_answer_keeps_waiting() {
    let mut h = home_with(true);
    let (i, r) = h.ask("ai:assistant", 22, "it is cold");
    assert!(r.is_escalated(), "{}", r.summary());
    let r = h.answer_as("person:alice", &i, Verdict::Approve);
    assert!(r.is_escalated(), "one key of two: {}", r.summary());
    let r = h.answer_as("person:carol", &i, Verdict::Approve);
    assert_eq!(r.code, Some(DenyCode::ApprovalInvalid), "{}", r.summary());
    assert_eq!(h.approvals_of("person:bob").len(), 1, "still waiting for bob");
    assert!(h.answer_as("person:bob", &i, Verdict::Approve).is_ok());
}

/// A refusal in force is never dropped early. Its memory is bounded by the
/// questions that were asked: here alice refuses her whole budget, every
/// refusal stays in force, and none can be added past it. (Asked again and
/// again, an agent is also contained in time: its security state rises.)
#[test]
fn refusals_stay_in_force_and_are_bounded_by_the_questions_asked() {
    let mut h = home();
    h.spend_alices_questions(QUESTIONS_PER_APPROVER, 10);
    assert_eq!(h.node.refusals_in_force(), QUESTIONS_PER_APPROVER);
    let (_, r) = h.ask_light("ai:assistant", 99);
    refused(&r, "were each asked");
    for (ai, pct) in [("ai:assistant", 10), ("ai:home", 11)] {
        let (_, r) = h.ask_light(ai, pct);
        refused(&r, "a person refused this request");
    }
    assert_eq!(h.node.refusals_in_force(), QUESTIONS_PER_APPROVER);
}
