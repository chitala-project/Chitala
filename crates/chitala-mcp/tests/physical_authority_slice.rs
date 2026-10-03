//! Physical Authority Slice v0.1 — end to end.
//!
//! ```text
//! MCP tool call ─▶ Intent ─▶ Authority ─▶ Safety ─▶ Approval ─▶ Capability ─▶ simulated door
//! (broker)        (signed)   (engine)     (rules)    (human)     (node-signed    (adapter, mock
//!                                                                 order)          lock + door)
//! ```
//!
//! | # | case | required |
//! |---|------|----------|
//! | 1 | Owner AI → turn on the light | ALLOW |
//! | 2 | Guest AI → turn on a delegated light | ALLOW |
//! | 3 | Child AI → open the door without permission | DENY |
//! | 4 | Owner AI → open the door (high risk) | ESCALATE → human approval → ALLOW |
//! | 5 | AI A → asks AI B to open the door to dodge policy | DENY |
//!
//! Invariant 1 is checked throughout: the AIs only ever send intents, and the
//! door moves only when the node's trusted boundary minted an order after
//! Authority, Safety and — for the door — a human.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_audit::{verify_lines, AuditLog, Signer};
use chitala_bus::Filter;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::{parse_id_hex, Approval, Intent, Verdict};
use chitala_mcp::{Agent, Broker, Request, TokenSource};
use chitala_model::{payload, CapabilityId, EntityId, EventKind, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response};
use chitala_resource::ResourceId;
use serde_json::{json, Value};

const T0: u64 = 1_790_000_000_000;
const LIGHT: &str = "resource:living-room-light";
const DOOR: &str = "resource:front-door";
const DOOR_DEVICE: &str = "device:front-door";
const LIGHT_DEVICE: &str = "device:living-room-light";

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn key(s: &str) -> Keypair {
    Keypair::from_seed(&test_seed(s))
}

type Shared = Arc<Mutex<Node>>;

struct Home {
    node: Shared,
    clock: Arc<AtomicU64>,
    /// Every token each AI holds.
    tokens: HashMap<&'static str, Vec<Vec<u8>>>,
}

fn home() -> Home {
    let mut mock = MockAdapter::new();
    let devices = sample_devices();
    for d in &devices {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).unwrap());
    }
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let node_clock: chitala_node::Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let principals = [
        ("person:alice", vec!["owner"]),
        ("person:guest", vec!["guest"]),
        ("person:child", vec!["child"]),
        ("ai:assistant", vec![]),
        ("ai:guest-assistant", vec![]),
        ("ai:kid-assistant", vec![]),
    ]
    .into_iter()
    .map(|(who, roles)| (id(who), key(who).public_key(), roles.into_iter().map(String::from).collect()))
    .collect();
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: key("service:node"),
        authority_key: key("domain:home/authority"),
        principals,
        agency: vec![
            (id("ai:assistant"), vec![id("person:alice")]),
            (id("ai:guest-assistant"), vec![id("person:guest")]),
            (id("ai:kid-assistant"), vec![id("person:child")]),
        ],
        devices,
        resources: sample_resources(),
        safety: Default::default(),
        executor: chitala_node::executor::in_process(
            &key("service:node").public_key(),
            vec![Box::new(mock)],
            node_clock.clone(),
        ),
        policy: chitala_node::PolicySource::Default,
        audit: AuditLog::in_memory(Some(Signer { id: id("service:node"), key: key("service:node") })),
        state: chitala_node::DomainState::default(),
        state_file: None,
        containment: ContainmentConfig::default(),
        monitor: MonitorConfig::default(),
        entropy: std::sync::Arc::new(chitala_platform::memory::test_entropy()),
        clock: node_clock,
        clock_watch: None,
    })
    .unwrap();
    let mut h = Home { node: Arc::new(Mutex::new(node)), clock, tokens: HashMap::new() };
    // the owner delegates; nobody else holds anything
    h.grant("ai:assistant", LIGHT, "light.turn_on");
    h.grant("ai:assistant", DOOR, "lock.unlock");
    h.grant("ai:guest-assistant", LIGHT, "light.turn_on");
    h.grant("ai:kid-assistant", "resource:bedroom", "switch.turn_on");
    h
}

impl Home {
    fn now(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// A person's own signed request (CSME) — humans keep their direct path.
    fn person(&self, who: &str, target: &str, cap: &str, pl: Payload) -> Response {
        let r = Requester::new(
            id(who),
            key(who),
            id("service:cli"),
            std::sync::Arc::new(chitala_platform::memory::test_entropy()),
        );
        let now = self.now();
        let mut n = self.node.lock().unwrap();
        let bytes = r.sign(n.registry(), &id(target), &CapabilityId::parse(cap).unwrap(), pl, now);
        n.handle(&bytes)
    }

    fn grant(&mut self, holder: &'static str, target: &str, cap: &str) {
        let pl = payload([
            ("holder", ParamValue::from(holder)),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(cap)),
            ("ttl_s", ParamValue::Int(3600)),
        ]);
        let r = self.person("person:alice", "domain:home", "domain.delegate", pl);
        assert!(r.is_ok(), "delegation to {holder}: {}", r.summary());
        let b64 = r.result.unwrap()["token"].as_str().unwrap().to_string();
        let bytes = chitala_token::bytes_from_base64(&b64).unwrap();
        self.tokens.entry(holder).or_default().push(bytes);
    }

    fn broker(&self, ai: &'static str, serves: &str) -> Broker<Shared> {
        let pk = self.node.lock().unwrap().authority_public_key();
        let clock = Arc::clone(&self.clock);
        let tokens = self.tokens.get(ai).cloned().map(TokenSource::Many).unwrap_or(TokenSource::None);
        Broker::new(
            Arc::clone(&self.node),
            id("domain:home"),
            Agent::new(id(ai), key(ai), id(serves)),
            tokens,
            &pk,
            Box::new(move || clock.fetch_add(1, Ordering::SeqCst) + 1),
        )
    }

    /// A human answers an escalation: lists what waits for them (as the node
    /// shows it, with the digest), signs an answer for exactly that intent.
    fn answer(&self, who: &str, intent: &str, verdict: Verdict) -> Response {
        let list = self.person(who, "domain:home", "domain.list_approvals", Payload::new());
        assert!(list.is_ok(), "{}", list.summary());
        let entries = list.result.unwrap()["approvals"].as_array().unwrap().clone();
        let entry = entries
            .iter()
            .find(|e| e["intent"] == intent)
            .unwrap_or_else(|| panic!("{intent} is not waiting for {who}: {entries:?}"));
        let digest: [u8; 32] = hex::decode(entry["digest"].as_str().unwrap()).unwrap().try_into().unwrap();
        let now = self.now();
        let a = Approval {
            intent: parse_id_hex(intent).unwrap(),
            intent_digest: digest,
            approver: id(who),
            verdict,
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            note: Some("answered in the test".into()),
        };
        self.node.lock().unwrap().handle(&a.sign(&key(who)))
    }

    fn reported(&self, device: &str, field: &str) -> Option<ParamValue> {
        self.node.lock().unwrap().twins().get(&id(device)).and_then(|t| t.reported.get(field).cloned())
    }

    fn door_locked(&self) -> bool {
        self.reported(DOOR_DEVICE, "locked") == Some(ParamValue::Bool(true))
    }

    fn audit(&self) -> Vec<Value> {
        let n = self.node.lock().unwrap();
        let lines = n.audit().lines();
        verify_lines(lines.iter().map(String::as_str), &HashMap::new()).expect("audit chain verifies");
        lines.iter().map(|l| serde_json::from_str(l).unwrap()).collect()
    }
}

fn call(b: &mut Broker<Shared>, resource: &str, action: &str, purpose: &str) -> Value {
    b.request(&Request {
        resource: resource.into(),
        action: action.into(),
        params: Default::default(),
        purpose: Some(purpose.into()),
        max_risk: None,
    })["structuredContent"]
        .clone()
}

fn decision(v: &Value) -> (&str, Option<&str>) {
    (v["decision"].as_str().unwrap_or("?"), v["code"].as_str())
}

// ───────────────────────────── the five cases ─────────────────────────────

#[test]
fn case1_owner_ai_turns_on_the_light() {
    let h = home();
    let mut ai = h.broker("ai:assistant", "person:alice");
    let r = call(&mut ai, LIGHT, "light.turn_on", "it is getting dark");
    assert_eq!(decision(&r), ("allow", None), "{r}");
    assert_eq!(h.reported(LIGHT_DEVICE, "on"), Some(ParamValue::Bool(true)));
    // the record says who asked, for whom, and why every step passed
    let rec = h.audit().into_iter().rev().find(|v| v["decision"] == "allow").unwrap();
    assert_eq!((rec["actor"].as_str(), rec["on_behalf_of"].as_str()), (Some("ai:assistant"), Some("person:alice")));
    assert_eq!(rec["purpose"], "it is getting dark");
    assert_eq!(rec["device"], LIGHT_DEVICE);
    assert_eq!(rec["trace"].as_array().unwrap().len(), 8);
}

#[test]
fn case2_guest_ai_turns_on_a_delegated_light() {
    let h = home();
    let mut ai = h.broker("ai:guest-assistant", "person:guest");
    let r = call(&mut ai, LIGHT, "light.turn_on", "guest arrived");
    assert_eq!(decision(&r), ("allow", None), "{r}");
    assert_eq!(h.reported(LIGHT_DEVICE, "on"), Some(ParamValue::Bool(true)));
    // only what was delegated: the guest's AI cannot touch the door
    let r = call(&mut ai, DOOR, "lock.unlock", "let me in");
    assert_eq!(decision(&r).0, "deny");
    assert!(h.door_locked());
}

#[test]
fn case3_child_ai_cannot_open_the_door() {
    let h = home();
    let mut ai = h.broker("ai:kid-assistant", "person:child");
    let r = call(&mut ai, DOOR, "lock.unlock", "my friend is outside");
    assert_eq!(decision(&r), ("deny", Some("E_POLICY_DENIED")), "{r}");
    assert_eq!(r["step"], "delegation");
    assert!(h.door_locked());
    // nobody is asked to approve something the child is not entitled to
    assert!(h.node.lock().unwrap().pending_approvals().is_empty());
}

#[test]
fn case4_owner_ai_opening_the_door_needs_a_human() {
    let h = home();
    let events = h.node.lock().unwrap().subscribe(Filter::All);
    let mut ai = h.broker("ai:assistant", "person:alice");
    let r = call(&mut ai, DOOR, "lock.unlock", "the plumber is at the door");
    assert_eq!(decision(&r), ("escalate", None), "{r}");
    assert_eq!(r["approvers"], json!(["person:alice"]));
    assert!(r["note"].as_str().unwrap().contains("do not send this request again"));
    let intent = r["mid"].as_str().unwrap().to_string();
    // escalation is not execution: the door has not moved
    assert!(h.door_locked());
    assert!(events.drain().iter().any(|e| e.kind == EventKind::ApprovalRequested));

    // the human sees exactly what is asked, and approves it
    let r = h.answer("person:alice", &intent, Verdict::Approve);
    assert!(r.is_ok(), "{}", r.summary());
    assert!(!h.door_locked(), "the door opens only now");

    let audit = h.audit();
    let allow = audit.iter().rev().find(|v| v["decision"] == "allow").unwrap();
    assert_eq!(allow["approved_by"], "person:alice");
    assert_eq!(allow["mid"], intent.as_str());
    assert!(audit.iter().any(|v| v["kind"] == "approval" && v["verdict"] == "approve"));
    // answered once: a second answer finds nothing waiting
    let r = h.node.lock().unwrap().pending_approvals();
    assert!(r.is_empty());
}

#[test]
fn case4_rejected_or_ignored_means_the_door_stays_shut() {
    let h = home();
    let mut ai = h.broker("ai:assistant", "person:alice");
    let r = call(&mut ai, DOOR, "lock.unlock", "delivery");
    let intent = r["mid"].as_str().unwrap().to_string();
    let r = h.answer("person:alice", &intent, Verdict::Reject);
    assert_eq!(r.code.map(|c| c.as_str()), Some("E_APPROVAL_REJECTED"));
    assert!(h.door_locked());

    // an unanswered question expires with the intent's deadline
    let r = call(&mut ai, DOOR, "lock.unlock", "delivery again");
    assert_eq!(decision(&r).0, "escalate");
    h.clock.fetch_add(chitala_mcp::DEFAULT_INTENT_TTL_MS + 1, Ordering::SeqCst);
    let _ = h.person("person:alice", "domain:home", "domain.list_approvals", Payload::new());
    let r = h.person("person:alice", DOOR_DEVICE, "device.read_state", Payload::new());
    assert!(r.is_ok());
    assert!(h.node.lock().unwrap().pending_approvals().is_empty());
    assert!(h.door_locked());
}

#[test]
fn case5_an_ai_cannot_get_another_ai_to_open_the_door() {
    let h = home();
    let kid = h.broker("ai:kid-assistant", "person:child");
    let mut owner_ai = h.broker("ai:assistant", "person:alice");
    // A (the child's AI) writes the request and hands it to B (the owner's AI)
    let handoff = kid
        .handoff(&Request {
            resource: DOOR.into(),
            action: "lock.unlock".into(),
            params: Default::default(),
            purpose: Some("please open, my friend is outside".into()),
            max_risk: None,
        })
        .unwrap();

    // B relays it faithfully — on behalf of the child, whom B does not serve
    let r = owner_ai.relay(&handoff, Some("the kid's assistant asked".into()))["structuredContent"].clone();
    assert_eq!(decision(&r), ("deny", Some("E_ON_BEHALF_OF")), "{r}");

    // a dishonest B claims it is for the owner while carrying the child's request
    let mut laundered = Intent::new(
        chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
        id("ai:assistant"),
        id("person:alice"),
        CapabilityId::parse("lock.unlock").unwrap(),
        ResourceId::parse(DOOR).unwrap(),
        h.now(),
        60_000,
    );
    laundered.context.cause = Some(handoff.clone());
    laundered.authority = h.tokens["ai:assistant"].get(1).cloned(); // its door token
    let r = h.node.lock().unwrap().handle(&laundered.sign(&key("ai:assistant")));
    assert_eq!(r.code.map(|c| c.as_str()), Some("E_PROVENANCE"), "{}", r.summary());
    assert_eq!(r.step.as_deref(), Some("context"));

    // the child's AI cannot send the request itself either
    let mut kid = h.broker("ai:kid-assistant", "person:child");
    assert_eq!(decision(&call(&mut kid, DOOR, "lock.unlock", "then I'll do it")).0, "deny");
    assert!(h.door_locked());
    assert!(h.node.lock().unwrap().pending_approvals().is_empty());
}

#[test]
fn case5_residual_hidden_provenance_still_reaches_a_human() {
    // If B drops the child's request and asks on its own, B is using its own
    // authority: for the door that is never an allow — the owner is asked, and
    // sees that it is B asking.
    let h = home();
    let mut owner_ai = h.broker("ai:assistant", "person:alice");
    let r = call(&mut owner_ai, DOOR, "lock.unlock", "(silently on the kid's behalf)");
    assert_eq!(decision(&r).0, "escalate");
    assert!(h.door_locked());
}

// ───────────────────────────── around the cases ─────────────────────────────

#[test]
fn safety_is_checked_again_when_the_human_answers() {
    let h = home();
    let mut ai = h.broker("ai:assistant", "person:alice");
    let r = call(&mut ai, DOOR, "lock.unlock", "plumber");
    let intent = r["mid"].as_str().unwrap().to_string();
    // while the owner decides, the entrance is put under a safety hold
    h.node.lock().unwrap().safety_mut().hold(ResourceId::parse("resource:entrance").unwrap(), "alarm armed");
    let r = h.answer("person:alice", &intent, Verdict::Approve);
    assert_eq!(r.code.map(|c| c.as_str()), Some("E_SAFETY"), "{}", r.summary());
    assert_eq!(r.stage.as_deref(), Some("safety"));
    assert!(h.door_locked(), "an approval cannot override safety");
    // and nobody is asked to approve what safety refuses anyway
    let r = call(&mut ai, DOOR, "lock.unlock", "plumber, again");
    assert_eq!(decision(&r), ("deny", Some("E_SAFETY")));
    assert!(h.node.lock().unwrap().pending_approvals().is_empty());
}

#[test]
fn only_an_owner_can_answer_and_bogus_answers_do_not_cancel() {
    let h = home();
    let mut ai = h.broker("ai:assistant", "person:alice");
    let r = call(&mut ai, DOOR, "lock.unlock", "plumber");
    let intent = r["mid"].as_str().unwrap().to_string();
    // the guest sees nothing to approve and cannot answer anyway
    let list = h.person("person:guest", "domain:home", "domain.list_approvals", Payload::new());
    assert_eq!(list.code.map(|c| c.as_str()), Some("E_POLICY_DENIED"));
    let now = h.now();
    let forged = Approval {
        intent: parse_id_hex(&intent).unwrap(),
        intent_digest: [0; 32],
        approver: id("person:guest"),
        verdict: Verdict::Approve,
        issued_at_ms: now,
        expires_at_ms: now + 60_000,
        note: None,
    };
    let r = h.node.lock().unwrap().handle(&forged.sign(&key("person:guest")));
    assert_eq!(r.code.map(|c| c.as_str()), Some("E_APPROVAL_INVALID"));
    assert!(h.door_locked());
    // the question is still open for the owner
    assert_eq!(h.node.lock().unwrap().pending_approvals(), vec![intent.clone()]);
    // AIs never see the approval queue, with or without a token
    for token in [None, h.tokens["ai:assistant"].first().cloned()] {
        let r = Requester::new(
            id("ai:assistant"),
            key("ai:assistant"),
            id("service:mcp-broker"),
            std::sync::Arc::new(chitala_platform::memory::test_entropy()),
        )
        .with_token(token);
        let now = h.now();
        let mut n = h.node.lock().unwrap();
        let bytes = r.sign(
            n.registry(),
            &id("domain:home"),
            &CapabilityId::parse("domain.list_approvals").unwrap(),
            Payload::new(),
            now,
        );
        assert!(!n.handle(&bytes).is_allow());
    }
    assert!(h.answer("person:alice", &intent, Verdict::Approve).is_ok());
    assert!(!h.door_locked());
}

#[test]
fn an_agent_cannot_flood_its_owner_with_questions() {
    let h = home();
    let mut ai = h.broker("ai:assistant", "person:alice");
    for i in 0..3 {
        assert_eq!(decision(&call(&mut ai, DOOR, "lock.unlock", &format!("ask #{i}"))).0, "escalate");
    }
    let r = call(&mut ai, DOOR, "lock.unlock", "ask #4");
    assert_eq!(decision(&r), ("deny", Some("E_RATE_LIMITED")));
}

#[test]
fn physical_authority_slice_v0_1() {
    // the milestone table, in one run
    let h = home();
    let mut owner = h.broker("ai:assistant", "person:alice");
    let mut guest = h.broker("ai:guest-assistant", "person:guest");
    let mut child = h.broker("ai:kid-assistant", "person:child");
    let kid = h.broker("ai:kid-assistant", "person:child");

    let c1 = call(&mut owner, LIGHT, "light.turn_on", "case 1");
    let c2 = call(&mut guest, LIGHT, "light.turn_on", "case 2");
    let c3 = call(&mut child, DOOR, "lock.unlock", "case 3");
    let c4 = call(&mut owner, DOOR, "lock.unlock", "case 4");
    let handoff = kid
        .handoff(&Request {
            resource: DOOR.into(),
            action: "lock.unlock".into(),
            params: Default::default(),
            purpose: Some("case 5".into()),
            max_risk: None,
        })
        .unwrap();
    let c5 = owner.relay(&handoff, None)["structuredContent"].clone();

    assert_eq!(decision(&c1).0, "allow");
    assert_eq!(decision(&c2).0, "allow");
    assert_eq!(decision(&c3).0, "deny");
    assert_eq!(decision(&c4).0, "escalate");
    assert_eq!(decision(&c5).0, "deny");
    assert!(h.door_locked());
    let approved = h.answer("person:alice", c4["mid"].as_str().unwrap(), Verdict::Approve);
    assert!(approved.is_ok(), "{}", approved.summary());
    assert!(!h.door_locked());

    // Invariant 1, from the evidence: every allowed physical action on the
    // intent path names the AI, the person it served, and — for the door — the human
    let audit = h.audit();
    let allows: Vec<&Value> = audit.iter().filter(|v| v["decision"] == "allow" && v["path"] == "intent").collect();
    assert_eq!(allows.len(), 3);
    for a in &allows {
        assert!(a["actor"].as_str().unwrap().starts_with("ai:"));
        assert!(a["on_behalf_of"].as_str().unwrap().starts_with("person:"));
        assert_eq!(a["safety"], "cleared");
    }
    let door = allows.iter().find(|a| a["resource"] == DOOR).unwrap();
    assert_eq!(door["approved_by"], "person:alice");
    assert_eq!(door["risk"], "high");
}
