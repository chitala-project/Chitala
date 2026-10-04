//! Execution leases end to end (v0.2 step 8, spec 21): one authority decision,
//! and for a high-risk action one owner's approval of exact terms, covers a
//! bounded series of uses. Every use is judged again, cleared by Safety and
//! executed as its own single-use order; it is counted before the order exists.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_audit::AuditLog;
use chitala_boundary::TrustedExecutionBoundary;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::{Approval, Intent, LeaseClause, LeaseTerms, Verdict};
use chitala_model::{payload, CapabilityId, DenyCode, EntityId, ExecCode, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{Node, NodeParts, Requester, Response, Step};
use chitala_resource::ResourceId;
use chitala_token::bytes_from_base64;
use serde_json::Value;

const T0: u64 = 1_790_000_000_000;
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

const PEOPLE: [(&str, &[&str], &[&str]); 5] = [
    ("person:alice", &["owner"], &[]),
    ("person:bob", &["adult"], &[]),
    ("ai:assistant", &[], &["person:alice"]),
    ("ai:home", &[], &["person:alice"]),
    ("ai:family", &[], &["person:alice", "person:bob"]),
];

struct Home {
    node: Node,
    clock: Arc<AtomicU64>,
    keys: std::collections::HashMap<String, Keypair>,
}

fn home() -> Home {
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let node_clock: chitala_node::Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let mut keys = std::collections::HashMap::new();
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

    fn intent(&self, actor: &str, resource: &str, c: &str, token: Option<&[u8]>, params: Payload) -> Intent {
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id(actor),
            id("person:alice"),
            cap(c),
            ResourceId::parse(resource).unwrap(),
            self.node.now(),
            120_000,
        );
        i.authority = token.map(<[u8]>::to_vec);
        i.params = params;
        i
    }

    fn ask(&self, actor: &str, resource: &str, c: &str, token: &[u8], terms: Terms<'_>) -> Intent {
        let (max_uses, duration_ms, envelope) = terms;
        let mut i = self.intent(actor, resource, c, Some(token), Payload::new());
        i.lease = Some(LeaseClause::Request(LeaseTerms {
            max_uses,
            duration_ms,
            envelope: envelope.iter().map(|(n, r)| (n.to_string(), *r)).collect(),
        }));
        i
    }

    fn use_(&self, actor: &str, resource: &str, c: &str, token: &[u8], lease: [u8; 16], params: Payload) -> Intent {
        let mut i = self.intent(actor, resource, c, Some(token), params);
        i.lease = Some(LeaseClause::Use(lease));
        i
    }

    fn submit(&mut self, i: &Intent) -> Response {
        let bytes = i.sign(&self.keys[&i.actor.to_string()]);
        self.tick(1);
        self.node.handle(&bytes)
    }

    fn approve(&mut self, who: &str, i: &Intent) -> Response {
        let now = self.node.now();
        let a = Approval {
            intent: i.id,
            intent_digest: i.digest(),
            approver: id(who),
            verdict: Verdict::Approve,
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

    fn records(&self, kind: &str) -> Vec<Value> {
        self.node
            .audit()
            .lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| v["kind"] == kind)
            .collect()
    }

    /// A thermostat lease for ai:assistant: `uses` uses, 20–24 °C, an hour.
    fn thermostat_lease(&mut self, uses: u32) -> (Vec<u8>, [u8; 16]) {
        let (token, _) = self.delegate("ai:assistant", THERMO_R, SET);
        let ask = self.ask("ai:assistant", THERMO_R, SET, &token, (uses, 3_600_000, &[("celsius", (20, 24))]));
        let r = self.submit(&ask);
        assert!(r.is_ok(), "{}", r.summary());
        (token, lease_id(&r))
    }
}

/// Lease terms in a test: uses, duration (ms), envelope.
type Terms<'a> = (u32, u64, &'a [(&'a str, (i64, i64))]);

fn lease_id(r: &Response) -> [u8; 16] {
    let hex_id = r.result.as_ref().unwrap()["lease"]["id"].as_str().unwrap();
    hex::decode(hex_id).unwrap().try_into().unwrap()
}

fn deny(r: &Response) -> (DenyCode, String) {
    assert!(!r.is_allow(), "expected deny, got {}", r.summary());
    (r.code.unwrap(), r.reason.clone().unwrap_or_default())
}

fn celsius(c: i64) -> Payload {
    payload([("celsius", ParamValue::Int(c))])
}

#[test]
fn an_agent_uses_a_lease_up_to_its_limit_and_each_use_is_an_order() {
    let mut h = home();
    let (token, lease) = h.thermostat_lease(3);
    // the request itself changed nothing
    assert_eq!(h.reported(THERMO, "target_celsius"), Some(ParamValue::Int(24)));
    for (n, c) in [(1, 21), (2, 22), (3, 23)] {
        let r = h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(c)));
        assert!(r.is_ok(), "use {n}: {}", r.summary());
        assert_eq!(h.reported(THERMO, "target_celsius"), Some(ParamValue::Int(c)));
    }
    let (code, why) = deny(&h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(22))));
    assert_eq!(code, DenyCode::LeaseExhausted, "{why}");
    // every use is its own decision record, counted against the lease
    let uses: Vec<(u64, u64)> = h
        .records("decision")
        .iter()
        .filter_map(|r| Some((r["lease"]["use"].as_u64()?, r["lease"]["of"].as_u64()?)))
        .collect();
    assert_eq!(uses, [(1, 3), (2, 3), (3, 3)]);
}

#[test]
fn a_use_must_be_what_the_lease_covers() {
    let mut h = home();
    let (token, lease) = h.thermostat_lease(5);
    // outside the envelope, an extra parameter: refused, not counted
    for pl in [celsius(26), payload([("celsius", ParamValue::Int(21)), ("fan", ParamValue::Int(1))])] {
        let (code, why) = deny(&h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, pl)));
        assert_eq!(code, DenyCode::LeaseEnvelope, "{why}");
    }
    // another agent that knows the lease id, with its own valid token
    let (other, _) = h.delegate("ai:home", THERMO_R, SET);
    let (code, _) = deny(&h.submit(&h.use_("ai:home", THERMO_R, SET, &other, lease, celsius(21))));
    assert_eq!(code, DenyCode::LeaseMismatch);
    // the same agent, another token for the same right
    let (second, _) = h.delegate("ai:assistant", THERMO_R, SET);
    let (code, why) = deny(&h.submit(&h.use_("ai:assistant", THERMO_R, SET, &second, lease, celsius(21))));
    assert_eq!(code, DenyCode::LeaseMismatch, "{why}");
    // no token at all: Authority runs again and refuses
    let mut bare = h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(21));
    bare.authority = None;
    assert_eq!(deny(&h.submit(&bare)).0, DenyCode::TokenMissing);
    // a lease nobody granted
    assert_eq!(
        deny(&h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, [3; 16], celsius(21)))).0,
        DenyCode::LeaseUnknown
    );
    // none of the refusals spent a use: all five are left
    for c in [20, 21, 22, 23, 24] {
        assert!(h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(c))).is_ok());
    }
}

#[test]
fn a_high_risk_lease_is_approved_once_for_exactly_its_terms() {
    let mut h = home();
    let (token, _) = h.delegate("ai:assistant", DOOR_R, "lock.unlock");
    // more than the high-risk limits is refused before anyone is asked
    let greedy = h.ask("ai:assistant", DOOR_R, "lock.unlock", &token, (4, 600_000, &[]));
    assert_eq!(deny(&h.submit(&greedy)).0, DenyCode::LeaseDenied);
    // two uses within half an hour: the owner is asked, and sees the terms
    let ask = h.ask("ai:assistant", DOOR_R, "lock.unlock", &token, (2, 1_800_000, &[]));
    let r = h.submit(&ask);
    assert!(r.is_escalated(), "{}", r.summary());
    let waiting = h.domain_op("person:alice", "domain.list_approvals", Payload::new());
    let item = &waiting.result.unwrap()["approvals"][0];
    assert_eq!(item["lease"]["max_uses"], 2);
    assert_eq!(item["lease"]["duration_ms"], 1_800_000);
    let r = h.approve("person:alice", &ask);
    assert!(r.is_ok(), "{}", r.summary());
    let lease = lease_id(&r);
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
    // two unlocks without asking again; the third is beyond the terms
    for n in 1..=2 {
        let r = h.submit(&h.use_("ai:assistant", DOOR_R, "lock.unlock", &token, lease, Payload::new()));
        assert!(r.is_ok(), "use {n}: {}", r.summary());
        assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(false)));
        assert!(h.req("person:alice", DOOR, "lock.lock", Payload::new()).is_ok());
    }
    let r = h.submit(&h.use_("ai:assistant", DOOR_R, "lock.unlock", &token, lease, Payload::new()));
    assert_eq!(deny(&r).0, DenyCode::LeaseExhausted);
    assert_eq!(h.reported(DOOR, "locked"), Some(ParamValue::Bool(true)));
}

#[test]
fn a_lease_ends_by_revocation_of_itself_its_token_its_agent_or_time() {
    let mut h = home();
    // revoked by the person it acts for
    let (token, lease) = h.thermostat_lease(5);
    let r = h.domain_op("person:alice", "domain.lease_revoke", payload([("lease_id", hex::encode(lease))]));
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(
        deny(&h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(21)))).0,
        DenyCode::LeaseRevoked
    );
    // its token revoked
    let (token, rid) = h.delegate("ai:assistant", THERMO_R, SET);
    let ask = h.ask("ai:assistant", THERMO_R, SET, &token, (5, 3_600_000, &[("celsius", (20, 24))]));
    let lease = lease_id(&h.submit(&ask));
    assert!(h.domain_op("person:alice", "domain.revoke_token", payload([("revocation_id", rid.as_str())])).is_ok());
    assert_eq!(
        deny(&h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(21)))).0,
        DenyCode::TokenRevoked
    );
    // time
    let (token, _) = h.delegate("ai:assistant", THERMO_R, SET);
    let ask = h.ask("ai:assistant", THERMO_R, SET, &token, (5, 60_000, &[("celsius", (20, 24))]));
    let lease = lease_id(&h.submit(&ask));
    h.tick(60_001);
    assert_eq!(
        deny(&h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(21)))).0,
        DenyCode::LeaseExpired
    );
    // its agent quarantined
    let (token, lease) = h.thermostat_lease(5);
    let q = payload([("principal", "ai:assistant"), ("state", "QUARANTINED")]);
    assert!(h.domain_op("person:alice", "domain.set_principal_state", q).is_ok());
    assert!(!h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(21))).is_allow());
}

#[test]
fn a_lease_revoked_while_its_order_is_in_flight_stops_the_order() {
    let mut h = home();
    let (token, lease) = h.thermostat_lease(3);
    let use_ = h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(21));
    let bytes = use_.sign(&h.keys["ai:assistant"]);
    h.tick(1);
    let mut pending = match h.node.begin(&bytes) {
        Step::Device(p) => p,
        Step::Done(r) => panic!("expected a device step, got {}", r.summary()),
    };
    assert!(h.domain_op("person:alice", "domain.lease_revoke", payload([("lease_id", hex::encode(lease))])).is_ok());
    let outcome = pending.run();
    assert!(outcome.as_ref().is_err_and(|e| e.to_string().contains("was revoked")), "{outcome:?}");
    assert_eq!(h.node.finish(pending, outcome).error.unwrap().code, ExecCode::OrderRejected);
    assert_eq!(h.reported(THERMO, "target_celsius"), Some(ParamValue::Int(24)));
}

#[test]
fn a_hold_refuses_a_use_without_spending_it() {
    let mut h = home();
    let (token, lease) = h.thermostat_lease(1);
    let hold = payload([("resource", ParamValue::from(THERMO_R)), ("reason", ParamValue::from("maintenance"))]);
    assert!(h.domain_op("person:alice", "domain.safety_hold", hold).is_ok());
    let (code, why) = deny(&h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(21))));
    assert_eq!(code, DenyCode::Safety, "{why}");
    assert!(h.domain_op("person:alice", "domain.safety_release", payload([("resource", THERMO_R)])).is_ok());
    // the single use is still there
    assert!(h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(21))).is_ok());
}

#[test]
fn a_replayed_use_is_refused_and_not_counted() {
    let mut h = home();
    let (token, lease) = h.thermostat_lease(2);
    let bytes = h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(21)).sign(&h.keys["ai:assistant"]);
    assert!(h.node.handle(&bytes).is_ok());
    assert_eq!(deny(&h.node.handle(&bytes)).0, DenyCode::Replay);
    assert!(h.submit(&h.use_("ai:assistant", THERMO_R, SET, &token, lease, celsius(22))).is_ok());
}

#[test]
fn who_may_see_and_end_a_lease() {
    let mut h = home();
    let (_, lease) = h.thermostat_lease(2);
    let end = payload([("lease_id", hex::encode(lease))]);
    // an adult it does not act for may not end it, nor see it
    let r = h.domain_op("person:bob", "domain.lease_revoke", end.clone());
    assert_eq!(r.error.unwrap().code, ExecCode::NotPermitted);
    let seen = h.domain_op("person:bob", "domain.list_leases", Payload::new());
    assert_eq!(seen.result.unwrap()["leases"].as_array().unwrap().len(), 0);
    // the owner sees it
    let seen = h.domain_op("person:alice", "domain.list_leases", Payload::new());
    assert_eq!(seen.result.unwrap()["leases"][0]["id"], hex::encode(lease));
    // an agent sends no commands at all, so it cannot end or list leases (C11 as a backstop)
    let r = h.req("ai:assistant", "domain:home", "domain.lease_revoke", end);
    assert_eq!(deny(&r).0, DenyCode::IntentRequired);
}

#[test]
fn an_agent_holds_a_bounded_number_of_leases() {
    let mut h = home();
    let (token, _) = h.delegate("ai:assistant", THERMO_R, SET);
    for _ in 0..chitala_node::node::MAX_LEASES_PER_ACTOR {
        let ask = h.ask("ai:assistant", THERMO_R, SET, &token, (1, 3_600_000, &[("celsius", (20, 24))]));
        assert!(h.submit(&ask).is_ok());
    }
    let ask = h.ask("ai:assistant", THERMO_R, SET, &token, (1, 3_600_000, &[("celsius", (20, 24))]));
    assert_eq!(deny(&h.submit(&ask)).0, DenyCode::LeaseDenied);
}
