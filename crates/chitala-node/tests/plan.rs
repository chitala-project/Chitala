//! Plans end to end (v0.2 step 10, spec 23): several actions one after the
//! other, each judged in full when it runs and started only once the one
//! before has verifiably taken effect. A plan creates no authority.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::Simulation;
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::{parse_id_hex, Approval, Intent, PlanStep, Verdict};
use chitala_model::{payload, CapabilityId, DenyCode, EntityId, ExecCode, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response, Step};
use chitala_resource::ResourceId;
use chitala_token::bytes_from_base64;
use serde_json::Value;

const T0: u64 = 1_790_000_000_000;
const LIGHT_R: &str = "resource:living-room-light";
const THERMO: &str = "device:thermostat";
const THERMO_R: &str = "resource:thermostat";
const DOOR: &str = "device:front-door";
const DOOR_R: &str = "resource:front-door";
const SET: &str = "climate.set_target_temperature";

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
    ("person:bob", &["adult"], &[]),
    ("ai:assistant", &[], &["person:alice"]),
    ("ai:helper", &[], &["person:alice"]),
];

struct Home {
    node: Node,
    clock: Arc<AtomicU64>,
    keys: HashMap<String, Keypair>,
}

fn home() -> Home {
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let node_clock: chitala_node::Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let mut keys = HashMap::new();
    let mut principals = Vec::new();
    let mut agency = Vec::new();
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
    let node = Node::new(NodeParts {
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
    Home { node, clock, keys }
}

/// One step of a plan: an action on a resource, its parameters and its token.
type S<'a> = (&'a str, &'a str, Payload, Option<&'a [u8]>);

impl Home {
    fn advance(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn later(&mut self, ms: u64) {
        self.advance(ms);
        self.node.tick();
    }

    fn req(&mut self, who: &str, target: &str, c: &str, pl: Payload) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy());
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now());
        self.advance(1);
        self.node.handle(&bytes)
    }

    fn domain_op(&mut self, who: &str, c: &str, pl: Payload) -> Response {
        self.req(who, "domain:home", c, pl)
    }

    /// alice delegates `c` on `target` to `holder`; returns the token and its revocation id.
    fn delegate(&mut self, holder: &str, target: &str, c: &str) -> (Vec<u8>, String) {
        let pl = payload([
            ("holder", ParamValue::from(holder)),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(c)),
            ("ttl_s", ParamValue::Int(3600)),
        ]);
        let r = self.domain_op("person:alice", "domain.delegate", pl);
        assert!(r.is_ok(), "{}", r.summary());
        let res = r.result.unwrap();
        (bytes_from_base64(res["token"].as_str().unwrap()).unwrap(), res["revocation_id"].as_str().unwrap().into())
    }

    /// The tokens ai:assistant needs for the evening plan.
    fn tokens(&mut self) -> HashMap<&'static str, Vec<u8>> {
        let mut t = HashMap::new();
        t.insert("lock.lock", self.delegate("ai:assistant", DOOR_R, "lock.lock").0);
        t.insert("lock.unlock", self.delegate("ai:assistant", DOOR_R, "lock.unlock").0);
        t.insert(SET, self.delegate("ai:assistant", THERMO_R, SET).0);
        t.insert("light.turn_on", self.delegate("ai:assistant", LIGHT_R, "light.turn_on").0);
        t
    }

    /// A plan of `actor` for alice: the first step is the intent itself.
    fn plan(&self, actor: &str, steps: &[S<'_>]) -> Intent {
        let (first, rest) = steps.split_first().unwrap();
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id(actor),
            id("person:alice"),
            cap(first.0),
            ResourceId::parse(first.1).unwrap(),
            self.node.now(),
            120_000,
        );
        i.params = first.2.clone();
        i.authority = first.3.map(<[u8]>::to_vec);
        i.then = rest
            .iter()
            .map(|(c, r, p, t)| {
                let mut s = PlanStep::new(cap(c), ResourceId::parse(r).unwrap(), p.clone());
                s.authority = t.map(<[u8]>::to_vec);
                s
            })
            .collect();
        i
    }

    fn submit(&mut self, i: &Intent) -> Response {
        let bytes = i.sign(&self.keys[&i.actor.to_string()]);
        self.advance(1);
        self.node.handle(&bytes)
    }

    /// `who` answers the escalated step `mid`, as `list_approvals` shows it.
    fn answer(&mut self, who: &str, mid: &str, verdict: Verdict) -> Response {
        let list = self.domain_op(who, "domain.list_approvals", Payload::new()).result.unwrap();
        let entry = list["approvals"].as_array().unwrap().iter().find(|a| a["intent"] == mid).cloned().unwrap();
        let digest: [u8; 32] = hex::decode(entry["digest"].as_str().unwrap()).unwrap().try_into().unwrap();
        let now = self.node.now();
        let a = Approval {
            intent: parse_id_hex(mid).unwrap(),
            intent_digest: digest,
            approver: id(who),
            verdict,
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            note: None,
        };
        let bytes = a.sign(&self.keys[who]);
        self.advance(1);
        self.node.handle(&bytes)
    }

    fn reported(&self, device: &str, field: &str) -> Option<ParamValue> {
        self.node.twins().get(&id(device)).and_then(|t| t.reported.get(field).cloned())
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
}

fn plan_of(r: &Response) -> Value {
    r.result.as_ref().map(|v| v["plan"].clone()).unwrap_or(Value::Null)
}

fn statuses(plan: &Value) -> Vec<String> {
    plan["steps"].as_array().unwrap().iter().map(|s| s["status"].as_str().unwrap().to_string()).collect()
}

fn none() -> Payload {
    Payload::new()
}

#[test]
fn a_plan_runs_its_steps_in_order_each_verified_before_the_next() {
    let mut h = home();
    let t = h.tokens();
    let plan = h.plan(
        "ai:assistant",
        &[
            ("lock.lock", DOOR_R, none(), Some(&t["lock.lock"])),
            (SET, THERMO_R, payload([("celsius", 21i64)]), Some(&t[SET])),
            ("light.turn_on", LIGHT_R, none(), Some(&t["light.turn_on"])),
        ],
    );
    let r = h.submit(&plan);
    assert!(r.is_ok(), "{}", r.summary());
    let p = plan_of(&r);
    assert_eq!(p["status"], "done", "{p}");
    assert_eq!(statuses(&p), ["done", "done", "done"]);
    for s in p["steps"].as_array().unwrap() {
        assert_eq!(s["outcome"]["status"], "verified", "{s}");
    }
    assert_eq!(h.reported(THERMO, "target_celsius"), Some(ParamValue::Int(21)));
    assert_eq!(h.reported("device:living-room-light", "on"), Some(ParamValue::Bool(true)));

    // every step is a decision of its own, with its own id, judged when it ran
    let mids: Vec<&str> = p["steps"].as_array().unwrap().iter().map(|s| s["mid"].as_str().unwrap()).collect();
    let decisions: Vec<Value> =
        h.records("decision").into_iter().filter(|d| mids.contains(&d["mid"].as_str().unwrap_or(""))).collect();
    assert_eq!(decisions.len(), 3);
    assert!(decisions.iter().all(|d| d["decision"] == "allow" && d["context"]["kind"] == "intent"));
    assert_eq!(decisions[0]["capability"], "lock.lock");
    assert_eq!(decisions[2]["capability"], "light.turn_on");
    // the plan itself is accepted once, and ends done
    let events: Vec<String> = h.records("plan").iter().map(|p| p["event"].as_str().unwrap().to_string()).collect();
    assert_eq!(events, ["accepted", "step_done", "step_done", "done"]);
    let accepted = &h.records("plan")[0];
    assert_eq!(accepted["steps"].as_array().unwrap().len(), 3, "the accepted record lists every step");
    assert_eq!(accepted["actor"], "ai:assistant");
}

#[test]
fn a_plan_is_refused_whole_when_any_step_would_be() {
    let mut h = home();
    let t = h.tokens();
    // the third step names no token, and the plan's own (the thermostat's) does
    // not cover the fan: nothing moves, not even the first step
    let plan = h.plan(
        "ai:assistant",
        &[
            (SET, THERMO_R, payload([("celsius", 21i64)]), Some(&t[SET])),
            ("light.turn_on", LIGHT_R, none(), Some(&t["light.turn_on"])),
            ("switch.turn_on", "resource:fan", none(), None),
        ],
    );
    let r = h.submit(&plan);
    assert_eq!(r.code, Some(DenyCode::TokenDenied), "{}", r.summary());
    assert!(r.reason.as_deref().unwrap().contains("plan step 3 of 3"), "{:?}", r.reason);
    assert_eq!(h.reported(THERMO, "target_celsius"), Some(ParamValue::Int(24)));
    assert!(h.records("execution").iter().all(|e| e["order"].is_null()), "no order was minted");

    // Safety is part of the precheck too: 29 °C is outside this thermostat's envelope
    let plan = h.plan(
        "ai:assistant",
        &[
            ("light.turn_on", LIGHT_R, none(), Some(&t["light.turn_on"])),
            (SET, THERMO_R, payload([("celsius", 29i64)]), Some(&t[SET])),
        ],
    );
    let r = h.submit(&plan);
    assert_eq!(r.code, Some(DenyCode::Safety), "{}", r.summary());
    assert!(r.reason.as_deref().unwrap().contains("plan step 2 of 2"), "{:?}", r.reason);
    assert_eq!(h.reported("device:living-room-light", "on"), Some(ParamValue::Bool(false)));
    assert!(h.records("execution").iter().all(|e| e["order"].is_null()), "no order was minted");
}

#[test]
fn a_step_that_needs_a_person_pauses_the_plan_and_asks_for_that_step_alone() {
    let mut h = home();
    let t = h.tokens();
    let plan = h.plan(
        "ai:assistant",
        &[
            (SET, THERMO_R, payload([("celsius", 21i64)]), Some(&t[SET])),
            ("lock.unlock", DOOR_R, none(), Some(&t["lock.unlock"])),
            ("light.turn_on", LIGHT_R, none(), Some(&t["light.turn_on"])),
        ],
    );
    let r = h.submit(&plan);
    assert!(r.is_escalated(), "{}", r.summary());
    let p = plan_of(&r);
    assert_eq!(p["status"], "waiting_approval");
    assert_eq!(statuses(&p), ["done", "waiting_approval", "planned"]);
    let step2 = p["steps"][1]["mid"].as_str().unwrap().to_string();
    assert_eq!(r.mid.as_deref(), Some(step2.as_str()), "the question is about step 2, not the plan");
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));

    // an approval of the whole plan answers nothing
    let now = h.node.now();
    let whole = Approval {
        intent: plan.id,
        intent_digest: plan.digest(),
        approver: id("person:alice"),
        verdict: Verdict::Approve,
        issued_at_ms: now,
        expires_at_ms: now + 60_000,
        note: None,
    };
    let bytes = whole.sign(&h.keys["person:alice"]);
    let r = h.node.handle(&bytes);
    assert_eq!(r.code, Some(DenyCode::ApprovalInvalid), "{}", r.summary());

    // the owner approves step 2; it runs, and step 3 follows in the same request
    let r = h.answer("person:alice", &step2, Verdict::Approve);
    assert!(r.is_ok(), "{}", r.summary());
    let p = plan_of(&r);
    assert_eq!(p["status"], "done", "{p}");
    assert_eq!(statuses(&p), ["done", "done", "done"]);
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(false)));
    assert_eq!(h.reported("device:living-room-light", "on"), Some(ParamValue::Bool(true)));
}

#[test]
fn a_rejected_or_unanswered_step_stops_the_plan() {
    for answer in [Some(Verdict::Reject), None] {
        let mut h = home();
        let t = h.tokens();
        let plan = h.plan(
            "ai:assistant",
            &[
                ("lock.unlock", DOOR_R, none(), Some(&t["lock.unlock"])),
                ("light.turn_on", LIGHT_R, none(), Some(&t["light.turn_on"])),
            ],
        );
        let r = h.submit(&plan);
        assert!(r.is_escalated(), "{}", r.summary());
        let step1 = r.mid.clone().unwrap();
        let id = plan_of(&r)["id"].as_str().unwrap().to_string();
        match answer {
            Some(v) => {
                let r = h.answer("person:alice", &step1, v);
                assert_eq!(r.code, Some(DenyCode::ApprovalRejected), "{}", r.summary());
            }
            // no answer is no consent (C14): the deadline passes on a tick
            None => h.later(121_000),
        }
        let list = h.domain_op("person:alice", "domain.list_plans", none()).result.unwrap();
        let p = list["plans"].as_array().unwrap().iter().find(|p| p["id"] == id.as_str()).cloned().unwrap();
        assert_eq!(p["status"], "stopped", "{answer:?}: {p}");
        assert_eq!(statuses(&p), ["denied", "cancelled"], "{answer:?}");
        assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
        assert_eq!(h.reported("device:living-room-light", "on"), Some(ParamValue::Bool(false)));
    }
}

#[test]
fn a_step_waits_for_its_outcome_and_a_broken_promise_stops_the_plan() {
    let mut h = home();
    let t = h.tokens();
    // a slow thermostat: step 2 starts only once step 1 is verified, on a tick
    h.node.simulate(&id(THERMO), Simulation::Lag(2)).unwrap();
    let plan = h.plan(
        "ai:assistant",
        &[
            (SET, THERMO_R, payload([("celsius", 21i64)]), Some(&t[SET])),
            ("light.turn_on", LIGHT_R, none(), Some(&t["light.turn_on"])),
        ],
    );
    let r = h.submit(&plan);
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(statuses(&plan_of(&r)), ["running", "planned"]);
    assert_eq!(h.reported("device:living-room-light", "on"), Some(ParamValue::Bool(false)));
    h.later(1_000);
    assert_eq!(h.reported("device:living-room-light", "on"), Some(ParamValue::Bool(true)));
    let list = h.domain_op("person:alice", "domain.list_plans", none()).result.unwrap();
    assert_eq!(list["plans"][0]["status"], "done");

    // a stuck lock: its outcome diverges, the plan stops there
    assert!(h.req("person:alice", DOOR, "lock.unlock", none()).is_ok());
    h.node.simulate(&id(DOOR), Simulation::Stuck(true)).unwrap();
    let plan = h.plan(
        "ai:assistant",
        &[
            ("lock.lock", DOOR_R, none(), Some(&t["lock.lock"])),
            (SET, THERMO_R, payload([("celsius", 22i64)]), Some(&t[SET])),
        ],
    );
    let r = h.submit(&plan);
    assert_eq!(statuses(&plan_of(&r)), ["running", "planned"], "{}", r.summary());
    let id_ = plan_of(&r)["id"].as_str().unwrap().to_string();
    h.later(6_000);
    let list = h.domain_op("person:alice", "domain.list_plans", none()).result.unwrap();
    let p = list["plans"].as_array().unwrap().iter().find(|p| p["id"] == id_.as_str()).cloned().unwrap();
    assert_eq!(p["status"], "stopped", "{p}");
    assert_eq!(statuses(&p), ["failed", "cancelled"]);
    assert!(p["reason"].as_str().unwrap().contains("diverged"), "{p}");
    assert_eq!(h.reported(THERMO, "target_celsius"), Some(ParamValue::Int(21)), "step 2 never ran");
}

#[test]
fn a_plan_creates_no_authority_each_step_is_judged_when_it_runs() {
    let mut h = home();
    let t = h.tokens();
    let (light, light_rid) = h.delegate("ai:assistant", LIGHT_R, "light.turn_off");
    h.node.simulate(&id(THERMO), Simulation::Lag(2)).unwrap();
    let plan = h.plan(
        "ai:assistant",
        &[
            (SET, THERMO_R, payload([("celsius", 21i64)]), Some(&t[SET])),
            ("light.turn_off", LIGHT_R, none(), Some(&light)),
        ],
    );
    let r = h.submit(&plan);
    assert_eq!(statuses(&plan_of(&r)), ["running", "planned"], "{}", r.summary());
    // between the steps the owner revokes the token step 2 relies on
    let r = h.domain_op("person:alice", "domain.revoke_token", payload([("revocation_id", light_rid.as_str())]));
    assert!(r.is_ok(), "{}", r.summary());
    h.later(1_000);
    let list = h.domain_op("person:alice", "domain.list_plans", none()).result.unwrap();
    let p = &list["plans"][0];
    assert_eq!(p["status"], "stopped", "{p}");
    assert_eq!(statuses(p), ["done", "denied"]);
    assert_eq!(p["steps"][1]["code"], "E_TOKEN_REVOKED");
}

#[test]
fn a_person_cancels_a_plan_and_its_order_in_flight_is_stopped() {
    let mut h = home();
    let t = h.tokens();
    let plan = h.plan(
        "ai:assistant",
        &[
            (SET, THERMO_R, payload([("celsius", 21i64)]), Some(&t[SET])),
            ("light.turn_on", LIGHT_R, none(), Some(&t["light.turn_on"])),
        ],
    );
    let bytes = plan.sign(&h.keys["ai:assistant"]);
    h.advance(1);
    // step 1's order is minted, but not sent yet
    let Step::Device(mut pending) = h.node.begin(&bytes) else { panic!("step 1 is a device action") };
    let id_ = chitala_intent::id_hex(&plan.id);
    // only the person it acts for, an owner or an admin cancels it: not bob, not an AI
    let cancel = payload([("plan", id_.as_str())]);
    let r = h.domain_op("person:bob", "domain.plan_cancel", cancel.clone());
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::NotPermitted), "{}", r.summary());
    assert!(!h.domain_op("ai:assistant", "domain.plan_cancel", cancel.clone()).is_allow());
    let r = h.domain_op("person:alice", "domain.plan_cancel", cancel.clone());
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(r.result.as_ref().unwrap()["cancelled"], true);
    // the order in flight is stopped by the authority fence
    let outcome = pending.run();
    assert!(matches!(&outcome, Err(chitala_adapters::AdapterError::Rejected(m)) if m.contains("cancelled")));
    let r = h.node.finish(pending, outcome);
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::OrderRejected));
    h.later(2_000);
    assert_eq!(h.reported(THERMO, "target_celsius"), Some(ParamValue::Int(24)));
    assert_eq!(h.reported("device:living-room-light", "on"), Some(ParamValue::Bool(false)));
    let list = h.domain_op("person:alice", "domain.list_plans", none()).result.unwrap();
    assert_eq!(list["plans"][0]["status"], "cancelled");
    assert_eq!(statuses(&list["plans"][0]), ["cancelled", "cancelled"]);
    // bob sees no plan of alice's
    let list = h.domain_op("person:bob", "domain.list_plans", none()).result.unwrap();
    assert!(list["plans"].as_array().unwrap().is_empty());
}

#[test]
fn an_agent_runs_at_most_two_plans_at_once() {
    let mut h = home();
    let t = h.tokens();
    let (fan, _) = h.delegate("ai:assistant", "resource:fan", "switch.turn_on");
    for device in [THERMO, "device:living-room-light", "device:fan-plug"] {
        h.node.simulate(&id(device), Simulation::Lag(5)).unwrap();
    }
    let long = |h: &Home, c: &str, r: &str, p: Payload, tok: &[u8]| {
        h.plan("ai:assistant", &[(c, r, p, Some(tok)), ("lock.lock", DOOR_R, none(), Some(&t["lock.lock"]))])
    };
    let a = long(&h, SET, THERMO_R, payload([("celsius", 21i64)]), &t[SET]);
    assert!(h.submit(&a).is_ok());
    let b = long(&h, "light.turn_on", LIGHT_R, none(), &t["light.turn_on"]);
    assert!(h.submit(&b).is_ok());
    let c = long(&h, "switch.turn_on", "resource:fan", none(), &fan);
    let r = h.submit(&c);
    assert_eq!(r.code, Some(DenyCode::PlanDenied), "{}", r.summary());
}
