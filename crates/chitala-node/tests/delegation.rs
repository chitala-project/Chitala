//! Delegation, revocation and two-key approval, end to end (v0.2 step 3,
//! spec 05 and spec 16): the whole chain is the intersection of its links;
//! tokens are bound to a key, a person and a window, are non-transferable by
//! default, and die immediately — one by one, by floor, or in flight; a
//! two-key resource needs two different people.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::{Approval, Intent, Verdict};
use chitala_model::{payload, CapabilityId, DenyCode, EntityId, ExecCode, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response, Step};
use chitala_resource::{Resource, ResourceId};
use chitala_token::bytes_from_base64;
use serde_json::Value;

const T0: u64 = 1_790_000_000_000;
const LIGHT: &str = "device:living-room-light";
const LIGHT_R: &str = "resource:living-room-light";
const DOOR: &str = "device:front-door";
const DOOR_R: &str = "resource:front-door";

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
fn entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

/// Principals: (id, roles, the persons it serves).
const PEOPLE: [(&str, &[&str], &[&str]); 9] = [
    ("person:alice", &["owner"], &[]),
    ("person:bob", &["adult"], &[]),
    ("person:guest", &["guest"], &[]),
    ("ai:assistant", &[], &["person:alice"]),
    ("ai:home", &[], &["person:alice"]),
    ("ai:security", &[], &["person:alice"]),
    ("ai:family", &[], &["person:alice", "person:bob"]),
    ("ai:guest-assistant", &[], &["person:guest"]),
    ("ai:intruder", &[], &["person:alice"]),
];

struct Home {
    node: Node,
    clock: Arc<AtomicU64>,
    /// The key each principal signs with (a re-enrolled one has a new key).
    keys: std::collections::HashMap<String, Keypair>,
}

fn home_with(resources: Vec<Resource>, rekey: Option<&str>) -> Home {
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let node_clock: chitala_node::Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let mut keys = std::collections::HashMap::new();
    let mut principals = Vec::new();
    let mut agency = Vec::new();
    for (who, roles, serves) in PEOPLE {
        let seed = if rekey == Some(who) { format!("{who}/re-enrolled") } else { who.to_string() };
        let k = Keypair::from_seed(&test_seed(&seed));
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

fn home() -> Home {
    home_with(sample_resources(), None)
}

/// The front door needs two keys; alice and bob both own it.
fn two_key_home() -> Home {
    let mut resources = sample_resources();
    let door = resources.iter_mut().find(|r| r.id.as_entity() == &id(DOOR_R)).unwrap();
    door.two_key = true;
    door.owners = vec![id("person:alice"), id("person:bob")];
    home_with(resources, None)
}

impl Home {
    fn tick(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn req(&mut self, who: &str, target: &str, c: &str, pl: Payload, token: Option<&[u8]>) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:test"), entropy())
            .with_token(token.map(<[u8]>::to_vec));
        let bytes = r.sign(self.node.registry(), &id(target), &cap(c), pl, self.node.now());
        self.tick(1);
        self.node.handle(&bytes)
    }

    fn domain_op(&mut self, who: &str, c: &str, pl: Payload) -> Response {
        self.req(who, "domain:home", c, pl, None)
    }

    /// `who` delegates; returns the token bytes, or the failed response.
    fn delegate(
        &mut self,
        who: &str,
        holder: &str,
        target: &str,
        c: &str,
        extra: &[(&str, ParamValue)],
    ) -> Result<(Vec<u8>, String, Value), Box<Response>> {
        let mut pl = payload([
            ("holder", ParamValue::from(holder)),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(c)),
            ("ttl_s", ParamValue::Int(3600)),
        ]);
        for (k, v) in extra {
            pl.insert(k.to_string(), v.clone());
        }
        let r = self.domain_op(who, "domain.delegate", pl);
        if !r.is_ok() {
            return Err(Box::new(r));
        }
        let res = r.result.unwrap();
        let bytes = bytes_from_base64(res["token"].as_str().unwrap()).unwrap();
        Ok((bytes, res["revocation_id"].as_str().unwrap().to_string(), res))
    }

    fn intent(&self, actor: &str, for_: &str, resource: &str, c: &str, token: Option<&[u8]>) -> Intent {
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id(actor),
            id(for_),
            cap(c),
            ResourceId::parse(resource).unwrap(),
            self.node.now(),
            120_000,
        );
        i.authority = token.map(<[u8]>::to_vec);
        i
    }

    fn sign(&self, i: &Intent) -> Vec<u8> {
        i.sign(&self.keys[&i.actor.to_string()])
    }

    fn submit(&mut self, i: &Intent) -> Response {
        let bytes = self.sign(i);
        self.tick(1);
        self.node.handle(&bytes)
    }

    fn answer(&mut self, who: &str, i: &Intent, verdict: Verdict) -> Response {
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

    fn reported(&self, device: &str, field: &str) -> Option<ParamValue> {
        self.node.twins().get(&id(device)).and_then(|t| t.reported.get(field).cloned())
    }
}

fn deny(r: &Response) -> (DenyCode, String) {
    assert!(!r.is_allow(), "expected deny, got {}", r.summary());
    (r.code.unwrap(), r.reason.clone().unwrap_or_default())
}

// ───────────────────────── the chain is the intersection ─────────────────────────

/// Human → Personal AI → Home AI → Security Agent: each agent holds its own
/// right from the human; the chain can do only what every link can do, for the
/// person they all act for. (Agents never hand rights on — C11 — so the chain
/// is a chain of signed relays, spec 15.)
#[test]
fn the_whole_chain_is_the_intersection_of_its_links() {
    let mut h = home();
    let (personal, personal_rid, _) =
        h.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", &[]).unwrap();
    let (home_ai, _, _) = h.delegate("person:alice", "ai:home", LIGHT_R, "light.turn_on", &[]).unwrap();
    let (security, _, _) = h.delegate("person:alice", "ai:security", LIGHT_R, "light.turn_on", &[]).unwrap();
    let (home_fan_only, _, _) = h.delegate("person:alice", "ai:home", "resource:fan", "switch.turn_on", &[]).unwrap();

    // personal AI asks the home AI, which asks the security agent, which acts
    let chain = |h: &Home, home_token: &[u8]| {
        let first = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&personal));
        let mut second = h.intent("ai:home", "person:alice", LIGHT_R, "light.turn_on", Some(home_token));
        second.context.cause = Some(h.sign(&first));
        let mut third = h.intent("ai:security", "person:alice", LIGHT_R, "light.turn_on", Some(&security));
        third.context.cause = Some(h.sign(&second));
        third
    };
    let i = chain(&h, &home_ai);
    let r = h.submit(&i);
    assert!(r.is_ok(), "every link holds the right: {}", r.summary());
    assert_eq!(h.reported(LIGHT, "on"), Some(ParamValue::Bool(true)));

    // one link without the right: the chain has nothing, whatever the others hold
    let i = chain(&h, &home_fan_only);
    let (code, why) = deny(&h.submit(&i));
    assert_eq!(code, DenyCode::TokenDenied);
    assert!(why.contains("ai:home"), "{why}");

    // the root link's right revoked: the chain dies with it
    let r = h.domain_op("person:alice", "domain.revoke_token", payload([("revocation_id", personal_rid.as_str())]));
    assert!(r.is_ok());
    let i = chain(&h, &home_ai);
    assert_eq!(deny(&h.submit(&i)).0, DenyCode::TokenRevoked);
}

// ───────────────────────── tokens are bound ─────────────────────────

#[test]
fn a_token_is_bound_to_its_holders_key() {
    // alice's agent gets a right…
    let mut before = home();
    let (token, _, _) = before.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", &[]).unwrap();
    // …then the agent is re-enrolled with a new key (lost or compromised device)
    let mut after = home_with(sample_resources(), Some("ai:assistant"));
    let i = after.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&token));
    let (code, why) = deny(&after.submit(&i));
    assert_eq!(code, DenyCode::TokenDenied);
    assert!(why.contains("proof of possession"), "{why}");
    // a fresh grant to the new key works
    let (fresh, _, _) = after.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", &[]).unwrap();
    let i = after.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&fresh));
    assert!(after.submit(&i).is_ok());
    // a stolen token is useless to anyone else, even an agent of the same person
    let i = after.intent("ai:intruder", "person:alice", LIGHT_R, "light.turn_on", Some(&fresh));
    assert_eq!(deny(&after.submit(&i)).0, DenyCode::TokenDenied);
}

#[test]
fn an_agents_token_acts_only_for_the_person_it_is_for() {
    let mut h = home();
    // a family agent serves alice and bob; alice's grant is for alice
    let (t, _, res) = h.delegate("person:alice", "ai:family", LIGHT_R, "light.turn_on", &[]).unwrap();
    assert_eq!(res["for"], serde_json::json!(["person:alice"]));
    let for_bob = h.intent("ai:family", "person:bob", LIGHT_R, "light.turn_on", Some(&t));
    let (code, why) = deny(&h.submit(&for_bob));
    assert_eq!(code, DenyCode::TokenDenied);
    assert!(why.contains("acts only for person:alice"), "{why}");
    let for_alice = h.intent("ai:family", "person:alice", LIGHT_R, "light.turn_on", Some(&t));
    assert!(h.submit(&for_alice).is_ok());
    // the owner lets the guest's agent switch on the light — for the guest
    let (_, _, res) = h.delegate("person:alice", "ai:guest-assistant", LIGHT_R, "light.turn_on", &[]).unwrap();
    assert_eq!(res["for"], serde_json::json!(["person:guest"]));
    // naming someone the agent does not serve is refused
    let err = h
        .delegate(
            "person:alice",
            "ai:assistant",
            LIGHT_R,
            "light.turn_on",
            &[("for_person", ParamValue::from("person:bob"))],
        )
        .unwrap_err();
    assert_eq!(err.error.unwrap().code, ExecCode::DelegationDenied);
}

#[test]
fn a_token_has_a_window() {
    let mut h = home();
    let (t, _, res) = h
        .delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", &[("start_s", ParamValue::Int(60))])
        .unwrap();
    assert!(res["not_before_ms"].as_u64().unwrap() > h.node.now());
    let i = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&t));
    let (code, why) = deny(&h.submit(&i));
    assert_eq!(code, DenyCode::TokenDenied);
    assert!(why.contains("not valid yet"), "{why}");
    h.tick(60_000);
    let i = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&t));
    assert!(h.submit(&i).is_ok());
}

// ───────────────────────── revocation is immediate ─────────────────────────

/// Begin an intent with `token` up to the point where its order is minted.
fn in_flight(h: &mut Home, token: &[u8]) -> chitala_node::PendingDevice {
    let i = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(token));
    let bytes = h.sign(&i);
    h.tick(1);
    match h.node.begin(&bytes) {
        Step::Device(p) => p,
        Step::Done(r) => panic!("expected a device step, got {}", r.summary()),
    }
}

#[test]
fn a_revocation_stops_an_order_in_flight_but_an_unrelated_change_does_not() {
    let mut h = home();
    let (t, rid, _) = h.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", &[]).unwrap();

    // an unrelated delegation while the order is in flight: it goes through
    let mut p = in_flight(&mut h, &t);
    h.delegate("person:alice", "person:bob", LIGHT_R, "light.turn_off", &[]).unwrap();
    let outcome = p.run();
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(h.node.finish(p, outcome).is_ok());

    // the agent is quarantined while its order is in flight: it is not sent
    let mut p = in_flight(&mut h, &t);
    let r = h.domain_op(
        "person:alice",
        "domain.set_principal_state",
        payload([("principal", "ai:assistant"), ("state", "QUARANTINED")]),
    );
    assert!(r.is_ok(), "{}", r.summary());
    let outcome = p.run();
    assert!(outcome.as_ref().is_err_and(|e| e.to_string().contains("ai:assistant is now QUARANTINED")), "{outcome:?}");
    let r = h.node.finish(p, outcome);
    assert_eq!(r.error.unwrap().code, ExecCode::OrderRejected);
    for (to, state) in [("RECOVERY", "RECOVERY"), ("RE_ATTEST", "RE_ATTEST"), ("TRUSTED", "TRUSTED")] {
        let r = h.domain_op(
            "person:alice",
            "domain.set_principal_state",
            payload([("principal", "ai:assistant"), ("state", to)]),
        );
        assert!(r.is_ok(), "{state}: {}", r.summary());
    }

    // its token is revoked while its order is in flight: it is not sent
    let mut p = in_flight(&mut h, &t);
    assert!(h.domain_op("person:alice", "domain.revoke_token", payload([("revocation_id", rid.as_str())])).is_ok());
    let outcome = p.run();
    assert!(outcome.as_ref().is_err_and(|e| e.to_string().contains("the token was revoked")), "{outcome:?}");
    assert_eq!(h.node.finish(p, outcome).error.unwrap().code, ExecCode::OrderRejected);
}

/// A domain-wide revocation (`domain.revoke_all`, the panic button) and an
/// order in flight, on both sides of the authority fence (spec 19):
/// - before the fence, the order still needs its authority checked: it is
///   not sent;
/// - after the fence, the order was already sent and carried out. The
///   revocation does not undo it; it refuses everything that comes after.
#[test]
fn a_domain_wide_revocation_and_an_order_in_flight_on_both_sides_of_the_fence() {
    let mut h = home();
    // before the fence: revoked between the decision and the send
    let (t, _, _) = h.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", &[]).unwrap();
    let mut p = in_flight(&mut h, &t);
    assert!(h.domain_op("person:alice", "domain.revoke_all", Payload::new()).is_ok());
    let outcome = p.run();
    assert!(
        outcome.as_ref().is_err_and(|e| e.to_string().contains("every token issued before it was revoked")),
        "{outcome:?}"
    );
    assert_eq!(h.node.finish(p, outcome).error.unwrap().code, ExecCode::OrderRejected);
    assert_ne!(h.reported(LIGHT, "on"), Some(ParamValue::Bool(true)), "nothing reached the light");

    // after the fence: sent and carried out, then revoked
    let (t, _, _) = h.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", &[]).unwrap();
    let mut p = in_flight(&mut h, &t);
    let outcome = p.run();
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(h.domain_op("person:alice", "domain.revoke_all", Payload::new()).is_ok());
    let r = h.node.finish(p, outcome);
    assert!(r.is_ok(), "a revocation does not undo an order already carried out: {}", r.summary());
    assert_eq!(h.reported(LIGHT, "on"), Some(ParamValue::Bool(true)));
    let i = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&t));
    assert_eq!(deny(&h.submit(&i)).0, DenyCode::TokenRevoked);
}

#[test]
fn revocation_floors_cut_everything_issued_before() {
    let mut h = home();
    let (ai_token, _, _) = h.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", &[]).unwrap();
    let (bob_token, _, _) = h.delegate("person:alice", "person:bob", DOOR, "lock.unlock", &[]).unwrap();

    // the agent's phone is lost: everything it holds dies at once, by floor
    let r = h.domain_op("person:alice", "domain.revoke_all", payload([("principal", "ai:assistant")]));
    assert!(r.is_ok(), "{}", r.summary());
    let i = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&ai_token));
    let (code, why) = deny(&h.submit(&i));
    assert_eq!(code, DenyCode::TokenRevoked);
    assert!(why.contains("every token of ai:assistant"), "{why}");
    // bob's token is untouched, and a new grant to the agent works
    assert!(h.req("person:bob", DOOR, "lock.unlock", Payload::new(), Some(&bob_token)).is_ok());
    let (fresh, _, _) = h.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", &[]).unwrap();
    let i = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&fresh));
    assert!(h.submit(&i).is_ok());

    // bob may cut his own tokens, not alice's
    let r = h.domain_op("person:bob", "domain.revoke_all", payload([("principal", "person:alice")]));
    assert_eq!(r.error.unwrap().code, ExecCode::NotPermitted);
    // the panic button: every token of the domain
    assert!(h.domain_op("person:alice", "domain.revoke_all", Payload::new()).is_ok());
    let (code, _) = deny(&h.req("person:bob", DOOR, "lock.lock", Payload::new(), Some(&bob_token)));
    assert_eq!(code, DenyCode::TokenRevoked);
    let i = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&fresh));
    assert_eq!(deny(&h.submit(&i)).0, DenyCode::TokenRevoked);
    // the audit log records every floor
    let floors = h
        .node
        .audit()
        .lines()
        .iter()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|v| v["op"] == "revoke_all")
        .count();
    assert_eq!(floors, 2);
}

// ───────────────────────── two keys ─────────────────────────

#[test]
fn a_two_key_door_needs_two_different_people() {
    let mut h = two_key_home();
    let (t, _, _) = h.delegate("person:alice", "ai:assistant", DOOR_R, "lock.unlock", &[]).unwrap();
    let i = h.intent("ai:assistant", "person:alice", DOOR_R, "lock.unlock", Some(&t));
    let r = h.submit(&i);
    assert!(r.is_escalated(), "{}", r.summary());
    assert!(r.reason.as_deref().unwrap().contains("two people"), "{:?}", r.reason);

    // the first key turns: still locked, still waiting — for bob now
    let r = h.answer("person:alice", &i, Verdict::Approve);
    assert!(r.is_escalated(), "{}", r.summary());
    assert_eq!(r.approvers.as_deref(), Some(&["person:bob".to_string()][..]));
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
    // the same key cannot turn twice: a second answer of alice is a replay
    let r = h.answer("person:alice", &i, Verdict::Approve);
    assert_eq!(deny(&r).0, DenyCode::Replay);
    let waiting = h.req("person:bob", "domain:home", "domain.list_approvals", Payload::new(), None);
    let entry = &waiting.result.unwrap()["approvals"][0];
    assert_eq!(
        (entry["quorum"].as_u64(), entry["approved_by"].clone()),
        (Some(2), serde_json::json!(["person:alice"]))
    );

    // the second key: the door opens
    let r = h.answer("person:bob", &i, Verdict::Approve);
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(false)));
    let decision = h
        .node
        .audit()
        .lines()
        .iter()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .rfind(|v| v["kind"] == "decision" && v["decision"] == "allow")
        .unwrap();
    assert_eq!(decision["approved_by"], serde_json::json!(["person:alice", "person:bob"]));
    assert_eq!(decision["context"]["approved_by"], serde_json::json!(["person:alice", "person:bob"]));
}

#[test]
fn either_key_can_refuse() {
    let mut h = two_key_home();
    let (t, _, _) = h.delegate("person:alice", "ai:assistant", DOOR_R, "lock.unlock", &[]).unwrap();
    let i = h.intent("ai:assistant", "person:alice", DOOR_R, "lock.unlock", Some(&t));
    assert!(h.submit(&i).is_escalated());
    assert!(h.answer("person:alice", &i, Verdict::Approve).is_escalated());
    assert_eq!(deny(&h.answer("person:bob", &i, Verdict::Reject)).0, DenyCode::ApprovalRejected);
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
}

#[test]
fn one_person_alone_never_turns_two_keys() {
    let mut h = two_key_home();
    // a direct command cannot be approved by anyone: it is refused
    let (code, why) = deny(&h.req("person:alice", DOOR, "lock.unlock", Payload::new(), None));
    assert_eq!(code, DenyCode::TwoKeyRequired);
    assert!(why.contains("second person"), "{why}");
    // the owner's own intent is one key; bob is the other
    let mut own = h.intent("person:alice", "person:alice", DOOR_R, "lock.unlock", None);
    own.authority = None;
    let r = h.submit(&own);
    assert!(r.is_escalated(), "{}", r.summary());
    assert_eq!(r.approvers.as_deref(), Some(&["person:bob".to_string()][..]));
    // alice cannot be her own second key: her signature on this intent is spent
    let r = h.answer("person:alice", &own, Verdict::Approve);
    assert_eq!(deny(&r).0, DenyCode::Replay);
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
    assert!(h.answer("person:bob", &own, Verdict::Approve).is_ok());
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(false)));
    // low-risk actions on a two-key resource stay one-key
    assert!(h.req("person:alice", DOOR, "lock.lock", Payload::new(), None).is_ok());
}

/// C11: an agent never places or lifts safety holds. A hold stops every action
/// below it, protective ones included (a door under hold cannot be locked), so
/// it is a protection in itself. The owner cannot hand either right to an
/// agent, and a person who may hold or release is unaffected.
#[test]
fn an_agent_is_never_given_safety_holds() {
    let mut h = home();
    for c in ["domain.safety_hold", "domain.safety_release"] {
        let err = h.delegate("person:alice", "ai:assistant", "domain:home", c, &[]).unwrap_err();
        let e = err.error.unwrap();
        assert_eq!(e.code, ExecCode::DelegationDenied, "{c}: {}", e.message);
    }
    let hold = payload([("resource", ParamValue::from(DOOR_R)), ("reason", ParamValue::from("alarm armed"))]);
    assert!(h.domain_op("person:alice", "domain.safety_hold", hold).is_ok());
    assert!(h.domain_op("person:alice", "domain.safety_release", payload([("resource", DOOR_R)])).is_ok());
}
