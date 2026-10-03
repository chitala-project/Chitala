//! The five cases of the Physical Authority Slice v0.1 at engine level, plus
//! the attacks around them, with real signatures and real capability tokens.
//! The end-to-end versions live in `crates/chitala-node/tests/physical_authority_slice.rs`.

use super::*;
use chitala_identity::{key_id_of, test_seed, KeyId, Keypair, PublicKey};
use chitala_intent::{open_signed, Approval, SignedApproval, Verdict as Answer};
use chitala_model::{payload, CapabilityId, SecurityClass, SecurityState};
use chitala_resource::{Boundary, CapabilityBinding, Resource, ResourceKind, StateRef};
use chitala_token::{Grant as TokenGrant, Right, TokenAuthority};

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn rid(s: &str) -> ResourceId {
    ResourceId::new(s).unwrap()
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
fn key(s: &str) -> Keypair {
    Keypair::from_seed(&test_seed(s))
}

const NOW: u64 = 1_800_000_000_000;

fn res(local: &str, kind: ResourceKind, parent: Option<&str>, device: Option<(&str, &[&str])>) -> Resource {
    Resource {
        id: rid(local),
        kind,
        name: local.into(),
        parent: parent.map(rid),
        owners: vec![],
        boundary: Boundary::Interior,
        zone: None,
        bindings: device
            .map(|(d, caps)| {
                caps.iter().map(|c| CapabilityBinding { capability: cap(c), device: id(d), risk_floor: None }).collect()
            })
            .unwrap_or_default(),
        state: device.map(|(d, _)| StateRef { device: id(d), max_age_ms: 120_000 }),
        envelope: vec![],
    }
}

struct Fixture {
    identities: IdentityRegistry,
    registry: CapabilityRegistry,
    resources: ResourceGraph,
    policy: PolicyEngine,
    authority: TokenAuthority,
    tokens: TokenVerifier,
    revocations: RevocationList,
    now: u64,
}

fn fixture_with(mutate: impl FnOnce(&mut Vec<Resource>)) -> Fixture {
    let mut identities = IdentityRegistry::new();
    for (p, roles) in [
        ("person:alice", &["owner"][..]),
        ("person:bob", &["adult"][..]),
        ("person:guest", &["guest"][..]),
        ("person:child", &["child"][..]),
        ("ai:assistant", &[][..]),
        ("ai:helper", &[][..]),
        ("ai:guest-assistant", &[][..]),
        ("ai:kid-assistant", &[][..]),
    ] {
        identities.enroll(id(p), key(p).public_key(), roles).unwrap();
    }
    identities.set_serves(&id("ai:assistant"), &[id("person:alice")]).unwrap();
    identities.set_serves(&id("ai:helper"), &[id("person:alice")]).unwrap();
    identities.set_serves(&id("ai:guest-assistant"), &[id("person:guest")]).unwrap();
    identities.set_serves(&id("ai:kid-assistant"), &[id("person:child")]).unwrap();

    let mut home = res("home", ResourceKind::Site, None, None);
    home.owners = vec![id("person:alice")];
    let mut door = res(
        "front-door",
        ResourceKind::Door,
        Some("entrance"),
        Some(("device:front-door", &["lock.lock", "lock.unlock"])),
    );
    door.boundary = Boundary::Perimeter;
    let mut rs = vec![
        home,
        res("living-room", ResourceKind::Space, Some("home"), None),
        res("entrance", ResourceKind::Space, Some("home"), None),
        res(
            "living-room-light",
            ResourceKind::Light,
            Some("living-room"),
            Some(("device:living-room-light", &["light.turn_on", "light.turn_off", "light.set_brightness"])),
        ),
        door,
    ];
    mutate(&mut rs);
    let registry = CapabilityRegistry::core_v0_1();
    let resources = ResourceGraph::new(rs, &registry).unwrap();
    let policy = PolicyEngine::with_default_policies(&registry).unwrap();
    let authority = TokenAuthority::new(&key("domain:home/authority"));
    let tokens = authority.verifier();
    Fixture { identities, registry, resources, policy, authority, tokens, revocations: RevocationList::new(), now: NOW }
}

fn fixture() -> Fixture {
    fixture_with(|_| {})
}

fn devices(d: &EntityId) -> Option<DeviceAttrs> {
    let sc = match d.local() {
        "front-door" => SecurityClass::Sc3,
        "living-room-light" => SecurityClass::Sc2,
        "legacy-plug" => SecurityClass::Sc0,
        _ => return None,
    };
    Some(DeviceAttrs { security_class: sc, room: None, state: SecurityState::Trusted })
}

fn intent(actor: &str, for_: &str, action: &str, resource: &str) -> Intent {
    let mut i = Intent::new(id(actor), id(for_), cap(action), rid(resource), NOW - 1_000, 120_000);
    i.context.purpose = Some("test".into());
    i
}

impl Fixture {
    /// A token issued by `issuer` to `holder` for `rights` (resource local id, capability).
    fn token(&self, holder: &str, rights: &[(&str, &str)]) -> Vec<u8> {
        let grant = TokenGrant {
            holder: id(holder),
            issuer: id("person:alice"),
            rights: rights.iter().map(|(r, c)| Right::new(rid(r).as_entity().clone(), cap(c))).collect(),
            not_after_ms: NOW + 3_600_000,
        };
        self.authority.issue(&grant, NOW - 10_000).unwrap().bytes
    }

    fn keys(&self) -> impl Fn(&KeyId) -> Option<(EntityId, PublicKey)> + '_ {
        |k: &KeyId| self.identities.principals().find(|p| &p.key_id == k).map(|p| (p.id.clone(), p.public_key))
    }

    fn sign(&self, i: &Intent) -> Vec<u8> {
        i.sign(&key(&i.actor.to_string()))
    }

    fn decide_bytes(&self, bytes: &[u8], approval: Option<&Approval>) -> AuthorityDecision {
        let keys = self.keys();
        let verified = open_signed(bytes, &keys).unwrap();
        let approval = approval.map(|a| {
            let b = a.sign(&key(&a.approver.to_string()));
            let signer = a.approver.clone();
            SignedApproval::parse(&b).unwrap().open(&signer, &key(&signer.to_string()).public_key()).unwrap()
        });
        let world = AuthorityWorld {
            identities: &self.identities,
            registry: &self.registry,
            resources: &self.resources,
            policy: &self.policy,
            tokens: &self.tokens,
            revocations: &self.revocations,
            devices: &devices,
            now_ms: self.now,
        };
        decide(&world, &verified, approval.as_ref())
    }

    fn decide(&self, i: &Intent, approval: Option<&Approval>) -> AuthorityDecision {
        self.decide_bytes(&self.sign(i), approval)
    }

    /// `outer` relays `cause` (already signed).
    fn relay(&self, outer: &Intent, cause: &Intent) -> AuthorityDecision {
        let mut o = outer.clone();
        o.context.cause = Some(self.sign(cause));
        self.decide(&o, None)
    }
}

fn with_token(mut i: Intent, t: Vec<u8>) -> Intent {
    i.authority = Some(t);
    i
}

fn denied(d: &AuthorityDecision) -> (Step, DenyCode) {
    let x = d.denial().unwrap_or_else(|| panic!("expected deny, got {} {:?}", d.label(), d.trace));
    (x.step, x.code)
}

fn approval(i: &Intent, by: &str, verdict: Answer) -> Approval {
    Approval {
        intent: i.id,
        intent_digest: i.digest(),
        approver: id(by),
        verdict,
        issued_at_ms: NOW - 500,
        expires_at_ms: NOW + 60_000,
        note: None,
    }
}

// ───────────────────────── the five slice cases ─────────────────────────

#[test]
fn case1_owner_ai_turns_on_the_light() {
    let f = fixture();
    let t = f.token("ai:assistant", &[("living-room-light", "light.turn_on")]);
    let i = with_token(intent("ai:assistant", "person:alice", "light.turn_on", "living-room-light"), t);
    let d = f.decide(&i, None);
    let Verdict::Allow(g) = &d.verdict else { panic!("{:?}", d.trace) };
    assert_eq!(g.device(), &id("device:living-room-light"));
    assert_eq!(g.risk(), RiskClass::Low);
    assert_eq!(g.tokens().len(), 1);
    assert!(g.approved_by().is_none());
    // every question was asked and answered, in order
    assert_eq!(d.trace.iter().map(|s| s.step).collect::<Vec<_>>(), Step::ORDER);
    assert!(d.trace.iter().all(|s| s.passed));
}

#[test]
fn case2_guest_ai_turns_on_a_delegated_light() {
    let f = fixture();
    // a right on the room covers the light in it
    let t = f.token("ai:guest-assistant", &[("living-room", "light.turn_on")]);
    let i = intent("ai:guest-assistant", "person:guest", "light.turn_on", "living-room-light");
    assert!(matches!(f.decide(&with_token(i.clone(), t), None).verdict, Verdict::Allow(_)));
    // …but the same guest AI without the delegation has nothing
    assert_eq!(denied(&f.decide(&i, None)), (Step::Delegation, DenyCode::TokenMissing));
    let other_room = f.token("ai:guest-assistant", &[("entrance", "light.turn_on")]);
    assert_eq!(denied(&f.decide(&with_token(i.clone(), other_room), None)), (Step::Delegation, DenyCode::TokenDenied));
    // a token bound to another holder is useless
    let stolen = f.token("ai:assistant", &[("living-room-light", "light.turn_on")]);
    assert_eq!(denied(&f.decide(&with_token(i, stolen), None)), (Step::Delegation, DenyCode::TokenDenied));
}

#[test]
fn case3_child_ai_cannot_open_the_door() {
    let f = fixture();
    // even with a token that (wrongly) covers the door: the child is not entitled
    let t = f.token("ai:kid-assistant", &[("front-door", "lock.unlock")]);
    let i = with_token(intent("ai:kid-assistant", "person:child", "lock.unlock", "front-door"), t);
    let d = f.decide(&i, None);
    assert_eq!(denied(&d), (Step::Delegation, DenyCode::PolicyDenied));
    assert!(d.denial().unwrap().policy_reasons.iter().any(|r| r.starts_with("child-no-high-risk")));
    assert_eq!(d.risk, Some(RiskClass::High));
}

#[test]
fn case4_owner_ai_opening_the_door_escalates_to_a_human() {
    let f = fixture();
    let t = f.token("ai:assistant", &[("front-door", "lock.unlock")]);
    let i = with_token(intent("ai:assistant", "person:alice", "lock.unlock", "front-door"), t);
    let d = f.decide(&i, None);
    let Verdict::Escalate(e) = &d.verdict else { panic!("{} {:?}", d.label(), d.trace) };
    assert_eq!(e.approvers, [id("person:alice")]);
    assert_eq!(e.digest, i.digest());
    assert!(e.reasons.iter().any(|r| r.starts_with("C11")));
    assert!(e.reasons.iter().any(|r| r.contains("constitution")));

    // the owner approves → allow, with the approver on the grant
    let ok = approval(&i, "person:alice", Answer::Approve);
    let Verdict::Allow(g) = f.decide(&i, Some(&ok)).verdict else { panic!() };
    assert_eq!(g.approved_by(), Some(&id("person:alice")));
    assert_eq!(g.policy_reasons(), ["token-grant"], "the grant names what permitted it");
    // the owner rejects → deny
    let no = approval(&i, "person:alice", Answer::Reject);
    assert_eq!(denied(&f.decide(&i, Some(&no))), (Step::Approval, DenyCode::ApprovalRejected));
}

#[test]
fn case5_ai_cannot_launder_authority_through_another_ai() {
    let f = fixture();
    let owner_ai = f.token("ai:assistant", &[("front-door", "lock.unlock")]);
    // A (the child's AI) asks B (the owner's AI) to open the door
    let a = intent("ai:kid-assistant", "person:child", "lock.unlock", "front-door");
    let mut b = with_token(intent("ai:assistant", "person:alice", "lock.unlock", "front-door"), owner_ai.clone());
    b.requested_at_ms = a.requested_at_ms + 10;
    // B relays it on behalf of the owner → laundering
    assert_eq!(denied(&f.relay(&b, &a)), (Step::Context, DenyCode::Provenance));
    // B relays it honestly on behalf of the child → B does not act for the child
    let mut b2 = b.clone();
    b2.on_behalf_of = id("person:child");
    assert_eq!(denied(&f.relay(&b2, &a)), (Step::OnBehalfOf, DenyCode::OnBehalfOf));
    // inside one household a relay still intersects: the helper holds no door
    // right, and the owner's assistant cannot lend it one
    let h = with_token(
        intent("ai:helper", "person:alice", "lock.unlock", "front-door"),
        f.token("ai:helper", &[("living-room-light", "light.turn_on")]),
    );
    let mut b3 = b.clone();
    b3.requested_at_ms = h.requested_at_ms + 10;
    assert_eq!(denied(&f.relay(&b3, &h)), (Step::Delegation, DenyCode::TokenDenied));
    // and a relay that changes the request is refused
    let mut b4 = b3.clone();
    b4.action = cap("lock.lock");
    assert_eq!(denied(&f.relay(&b4, &h)), (Step::Context, DenyCode::Provenance));
}

#[test]
fn case5_residual_stripped_provenance_still_needs_a_human() {
    // If B hides that A asked, B acts on its own authority: for the door that
    // is never an allow — the owner is asked and sees B's request.
    let f = fixture();
    let t = f.token("ai:assistant", &[("front-door", "lock.unlock")]);
    let b = with_token(intent("ai:assistant", "person:alice", "lock.unlock", "front-door"), t);
    assert!(matches!(f.decide(&b, None).verdict, Verdict::Escalate(_)));
}

// ───────────────────────── the questions, one by one ─────────────────────────

#[test]
fn who_and_on_behalf_of() {
    let mut f = fixture();
    let t = f.token("ai:assistant", &[("home", "light.turn_on"), ("front-door", "lock.unlock")]);
    let i = with_token(intent("ai:assistant", "person:bob", "light.turn_on", "living-room-light"), t.clone());
    assert_eq!(denied(&f.decide(&i, None)), (Step::OnBehalfOf, DenyCode::OnBehalfOf));
    let i = with_token(intent("ai:assistant", "person:nobody", "light.turn_on", "living-room-light"), t.clone());
    assert_eq!(denied(&f.decide(&i, None)), (Step::OnBehalfOf, DenyCode::OnBehalfOf));
    let i = with_token(intent("ai:assistant", "person:alice", "light.turn_on", "living-room-light"), t.clone());
    f.identities.set_state(&id("ai:assistant"), SecurityState::Quarantined).unwrap();
    assert_eq!(denied(&f.decide(&i, None)), (Step::Who, DenyCode::PrincipalState));
    f.identities.set_state(&id("ai:assistant"), SecurityState::Restricted).unwrap();
    // RESTRICTED keeps low-risk actions only
    assert!(matches!(f.decide(&i, None).verdict, Verdict::Allow(_)));
    let door = with_token(intent("ai:assistant", "person:alice", "lock.unlock", "front-door"), t);
    assert_eq!(denied(&f.decide(&door, None)), (Step::Risk, DenyCode::PrincipalState));
    // the represented human's own state matters too
    f.identities.set_state(&id("person:alice"), SecurityState::Quarantined).unwrap();
    assert_eq!(denied(&f.decide(&i, None)), (Step::OnBehalfOf, DenyCode::OnBehalfOf));
}

#[test]
fn what_and_object() {
    let f = fixture();
    let t = f.token("ai:assistant", &[("home", "light.set_brightness")]);
    let mut i = with_token(intent("ai:assistant", "person:alice", "light.set_brightness", "living-room-light"), t);
    i.params = payload([("brightness_pct", 140i64)]);
    assert_eq!(denied(&f.decide(&i, None)), (Step::What, DenyCode::SafetyEnvelope));
    i.params = payload([("brightness_pct", "max")]);
    assert_eq!(denied(&f.decide(&i, None)), (Step::What, DenyCode::PayloadInvalid));
    let i = intent("ai:assistant", "person:alice", "domain.revoke_token", "living-room-light");
    assert_eq!(denied(&f.decide(&i, None)), (Step::What, DenyCode::UnsupportedByTarget));
    let i = intent("ai:assistant", "person:alice", "x-acme.fan.spin", "living-room-light");
    assert_eq!(denied(&f.decide(&i, None)), (Step::What, DenyCode::UnknownCapability));
    let i = intent("ai:assistant", "person:alice", "light.turn_on", "garage");
    assert_eq!(denied(&f.decide(&i, None)), (Step::Object, DenyCode::UnknownResource));
    let i = intent("ai:assistant", "person:alice", "lock.unlock", "living-room-light");
    assert_eq!(denied(&f.decide(&i, None)), (Step::Object, DenyCode::UnsupportedByTarget));
    let i = intent("ai:assistant", "person:alice", "light.turn_on", "living-room");
    assert_eq!(denied(&f.decide(&i, None)), (Step::Object, DenyCode::UnsupportedByTarget));
}

#[test]
fn context_deadline_and_loops() {
    let mut f = fixture();
    let t = |f: &Fixture, who: &str| f.token(who, &[("living-room-light", "light.turn_on")]);
    let i =
        with_token(intent("ai:assistant", "person:alice", "light.turn_on", "living-room-light"), t(&f, "ai:assistant"));
    f.now = i.constraints.deadline_ms;
    assert_eq!(denied(&f.decide(&i, None)), (Step::Context, DenyCode::Expired));
    let f = fixture();
    let a =
        with_token(intent("ai:assistant", "person:alice", "light.turn_on", "living-room-light"), t(&f, "ai:assistant"));
    let b = with_token(intent("ai:helper", "person:alice", "light.turn_on", "living-room-light"), t(&f, "ai:helper"));
    // A relays B relays A
    let mut b_relays_a = b.clone();
    b_relays_a.context.cause = Some(f.sign(&a));
    let mut outer = a.clone();
    outer.id = [9; 16];
    outer.requested_at_ms += 2;
    b_relays_a.requested_at_ms += 1;
    outer.context.cause = Some(f.sign(&b_relays_a));
    assert_eq!(denied(&f.decide(&outer, None)), (Step::Context, DenyCode::Provenance));
    // a faithful relay inside one household where everyone holds the right is fine
    let mut outer = a.clone();
    outer.requested_at_ms = b.requested_at_ms + 1;
    let d = f.relay(&outer, &b);
    let Verdict::Allow(g) = &d.verdict else { panic!("{:?}", d.trace) };
    assert_eq!(g.relayed_from(), [id("ai:helper")]);
    assert_eq!(g.tokens().len(), 2);
}

#[test]
fn revoked_and_foreign_tokens() {
    let mut f = fixture();
    let t = f.token("ai:assistant", &[("living-room-light", "light.turn_on")]);
    let i = with_token(intent("ai:assistant", "person:alice", "light.turn_on", "living-room-light"), t.clone());
    let v = f.tokens.verify(&t).unwrap();
    f.revocations.revoke(&v.revocation_id);
    assert_eq!(denied(&f.decide(&i, None)), (Step::Delegation, DenyCode::TokenRevoked));
    let foreign = TokenAuthority::new(&key("domain:elsewhere/authority"));
    let grant = TokenGrant {
        holder: id("ai:assistant"),
        issuer: id("person:alice"),
        rights: vec![Right::new(rid("living-room-light").as_entity().clone(), cap("light.turn_on"))],
        not_after_ms: NOW + 60_000,
    };
    let forged = foreign.issue(&grant, NOW).unwrap().bytes;
    let i = with_token(intent("ai:assistant", "person:alice", "light.turn_on", "living-room-light"), forged);
    assert_eq!(denied(&f.decide(&i, None)), (Step::Delegation, DenyCode::TokenInvalid));
}

#[test]
fn risk_floor_and_requester_limits() {
    // the owner raised the light to `medium` at this resource: the guest is no
    // longer entitled, the owner's AI still is
    let f = fixture_with(|rs| {
        let light = rs.iter_mut().find(|r| r.id.local() == "living-room-light").unwrap();
        light.bindings[0].risk_floor = Some(RiskClass::Medium);
    });
    let g = with_token(
        intent("ai:guest-assistant", "person:guest", "light.turn_on", "living-room-light"),
        f.token("ai:guest-assistant", &[("living-room-light", "light.turn_on")]),
    );
    let d = f.decide(&g, None);
    assert_eq!(denied(&d), (Step::Delegation, DenyCode::PolicyDenied));
    assert_eq!(d.risk, Some(RiskClass::Medium));
    let mut o = with_token(
        intent("ai:assistant", "person:alice", "light.turn_on", "living-room-light"),
        f.token("ai:assistant", &[("living-room-light", "light.turn_on")]),
    );
    assert!(matches!(f.decide(&o, None).verdict, Verdict::Allow(_)));
    o.constraints.max_risk = Some(RiskClass::Low);
    assert_eq!(denied(&f.decide(&o, None)), (Step::Risk, DenyCode::Constraint));
}

#[test]
fn critical_floor_needs_the_owner_even_for_a_person() {
    let f = fixture_with(|rs| {
        let door = rs.iter_mut().find(|r| r.id.local() == "front-door").unwrap();
        door.bindings[1].risk_floor = Some(RiskClass::Critical);
    });
    // the owner acting in person is the human decision
    let own = intent("person:alice", "person:alice", "lock.unlock", "front-door");
    assert!(matches!(f.decide(&own, None).verdict, Verdict::Allow(_)));
    // the owner's AI is escalated
    let ai = with_token(
        intent("ai:assistant", "person:alice", "lock.unlock", "front-door"),
        f.token("ai:assistant", &[("front-door", "lock.unlock")]),
    );
    assert!(matches!(f.decide(&ai, None).verdict, Verdict::Escalate(_)));
}

#[test]
fn persons_act_in_person() {
    let f = fixture();
    let own = intent("person:alice", "person:alice", "lock.unlock", "front-door");
    let d = f.decide(&own, None);
    let Verdict::Allow(g) = &d.verdict else { panic!("{:?}", d.trace) };
    assert!(g.tokens().is_empty() && g.approved_by().is_none());
    let bob = intent("person:bob", "person:bob", "lock.unlock", "front-door");
    assert_eq!(denied(&f.decide(&bob, None)), (Step::Delegation, DenyCode::PolicyDenied));
    let bob = intent("person:bob", "person:bob", "light.turn_on", "living-room-light");
    assert!(matches!(f.decide(&bob, None).verdict, Verdict::Allow(_)));
}

#[test]
fn approvals_must_come_from_an_owner_for_this_exact_intent() {
    let mut f = fixture();
    let t = f.token("ai:assistant", &[("front-door", "lock.unlock")]);
    let i = with_token(intent("ai:assistant", "person:alice", "lock.unlock", "front-door"), t);
    // an adult who does not own the door
    let bob = approval(&i, "person:bob", Answer::Approve);
    assert_eq!(denied(&f.decide(&i, Some(&bob))), (Step::Approval, DenyCode::ApprovalInvalid));
    // an approval for another intent (or a modified one)
    let mut other = i.clone();
    other.params = payload([("x", 1i64)]);
    let wrong = approval(&other, "person:alice", Answer::Approve);
    assert_eq!(denied(&f.decide(&i, Some(&wrong))), (Step::Approval, DenyCode::ApprovalInvalid));
    // expired, or issued before the request
    let mut late = approval(&i, "person:alice", Answer::Approve);
    late.expires_at_ms = NOW;
    assert_eq!(denied(&f.decide(&i, Some(&late))), (Step::Approval, DenyCode::ApprovalInvalid));
    let mut early = approval(&i, "person:alice", Answer::Approve);
    early.issued_at_ms = i.requested_at_ms - 60_000;
    assert_eq!(denied(&f.decide(&i, Some(&early))), (Step::Approval, DenyCode::ApprovalInvalid));
    // no escalation wanted
    let mut quiet = i.clone();
    quiet.constraints.no_escalation = true;
    assert_eq!(denied(&f.decide(&quiet, None)), (Step::Approval, DenyCode::Constraint));
    // an AI never exceeds the ceiling of the human it represents
    f.identities.set_state(&id("person:alice"), SecurityState::Restricted).unwrap();
    assert_eq!(denied(&f.decide(&i, None)), (Step::Risk, DenyCode::PrincipalState));
}

#[test]
fn escalation_needs_an_owner_who_can_still_decide() {
    // the door belongs to bob; alice (household owner role) asks through her AI
    let mut f = fixture_with(|rs| {
        let door = rs.iter_mut().find(|r| r.id.local() == "front-door").unwrap();
        door.owners = vec![id("person:bob")];
    });
    let t = f.token("ai:assistant", &[("front-door", "lock.unlock")]);
    let i = with_token(intent("ai:assistant", "person:alice", "lock.unlock", "front-door"), t);
    let Verdict::Escalate(e) = f.decide(&i, None).verdict else { panic!() };
    assert_eq!(e.approvers, [id("person:bob")]);
    // a contained owner cannot approve high-risk actions: nobody left to ask
    f.identities.set_state(&id("person:bob"), SecurityState::Restricted).unwrap();
    assert_eq!(denied(&f.decide(&i, None)), (Step::Approval, DenyCode::PolicyDenied));
    let late = approval(&i, "person:bob", Answer::Approve);
    assert_eq!(denied(&f.decide(&i, Some(&late))), (Step::Approval, DenyCode::ApprovalInvalid));
}

#[test]
fn sc0_bound_devices_take_no_high_risk_actions() {
    let f = fixture_with(|rs| {
        let door = rs.iter_mut().find(|r| r.id.local() == "front-door").unwrap();
        door.bindings[1].device = id("device:legacy-plug");
    });
    let own = intent("person:alice", "person:alice", "lock.unlock", "front-door");
    let d = f.decide(&own, None);
    assert_eq!(denied(&d), (Step::Delegation, DenyCode::PolicyDenied));
    assert!(d.denial().unwrap().policy_reasons.contains(&"SC0-no-high-risk-resource".to_string()));
}

#[test]
fn resource_hierarchy_reaches_cedar() {
    // a policy written against a room applies to everything in it
    let registry = CapabilityRegistry::core_v0_1();
    let src = format!(
        "{}\n@id(\"bob-living-room\")\npermit (principal == Chitala::Person::\"person:bob\", action, resource in Chitala::Resource::\"resource:living-room\");\n@id(\"no-bob-entrance\")\nforbid (principal == Chitala::Person::\"person:bob\", action, resource in Chitala::Resource::\"resource:entrance\");",
        crate::DEFAULT_POLICIES
    );
    let mut f = fixture();
    f.policy = PolicyEngine::new(&registry, &src).unwrap();
    let mut b = intent("person:bob", "person:bob", "light.set_brightness", "living-room-light");
    b.params = payload([("brightness_pct", 50i64)]);
    let d = f.decide(&b, None);
    let Verdict::Allow(g) = &d.verdict else { panic!("{:?}", d.trace) };
    assert!(g.policy_reasons().contains(&"bob-living-room".to_string()));
    let lock = intent("person:bob", "person:bob", "lock.lock", "front-door");
    let d = f.decide(&lock, None);
    assert!(d.denial().unwrap().policy_reasons.contains(&"no-bob-entrance".to_string()));
}

#[test]
fn key_ids_match_identity() {
    // sanity for the fixture's key lookup
    let f = fixture();
    let k = key("ai:assistant");
    assert_eq!(f.keys()(&key_id_of(&k.public_key())).unwrap().0, id("ai:assistant"));
}
