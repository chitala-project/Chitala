//! The boundary with real proofs: grants from the Authority Engine, clearances
//! from Safety. The end-to-end attacks live in
//! `crates/chitala-node/tests/execution_boundary.rs`.

use super::*;
use chitala_identity::{test_seed, IdentityRegistry, KeyId};
use chitala_intent::{new_intent_id, open_signed, Intent};
use chitala_model::{payload, CapabilityRegistry, ParamValue, RiskClass, SecurityClass, SecurityState};
use chitala_policy::authority::{authorize_recovery, decide, AuthorityWorld, RecoveryRequest, Verdict};
use chitala_policy::{DeviceAttrs, PolicyEngine};
use chitala_resource::{
    Boundary, CapabilityBinding, Resource, ResourceGraph, ResourceId, ResourceKind, SafeState, StateRef,
};
use chitala_safety::{Observation, Proposed, Safety};
use chitala_token::{RevocationList, TokenAuthority};

const NOW: u64 = 1_800_000_000_000;

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn rid(s: &str) -> ResourceId {
    ResourceId::new(s).unwrap()
}
fn key(s: &str) -> Keypair {
    Keypair::from_seed(&test_seed(s))
}
fn entropy() -> Arc<dyn Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

fn res(local: &str, kind: ResourceKind, parent: Option<&str>, device: Option<(&str, &[&str])>) -> Resource {
    Resource {
        id: rid(local),
        kind,
        name: local.into(),
        parent: parent.map(rid),
        owners: if parent.is_none() { vec![id("person:alice")] } else { vec![] },
        boundary: Boundary::Interior,
        zone: None,
        bindings: device
            .map(|(d, caps)| {
                caps.iter()
                    .map(|c| CapabilityBinding {
                        capability: CapabilityId::parse(c).unwrap(),
                        device: id(d),
                        risk_floor: None,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        state: device.map(|(d, _)| StateRef { device: id(d), max_age_ms: 120_000 }),
        envelope: vec![],
        two_key: false,
        safe_state: None,
        motion: None,
    }
}

/// An owner and her home: two lights, so two different grants can be compared.
struct Home {
    identities: IdentityRegistry,
    registry: CapabilityRegistry,
    resources: ResourceGraph,
    policy: PolicyEngine,
    tokens: chitala_token::TokenVerifier,
    safety: Safety,
}

fn devices(d: &EntityId) -> Option<DeviceAttrs> {
    d.local().ends_with("light").then_some(DeviceAttrs {
        security_class: SecurityClass::Sc2,
        room: None,
        state: SecurityState::Trusted,
    })
}

fn home() -> Home {
    let mut identities = IdentityRegistry::new();
    identities.enroll(id("person:alice"), key("person:alice").public_key(), &["owner"]).unwrap();
    let registry = CapabilityRegistry::core_v0_1();
    let caps: &[&str] = &["light.turn_on", "light.turn_off", "light.set_brightness"];
    let mut hall = res("hall-light", ResourceKind::Light, Some("home"), Some(("device:hall-light", caps)));
    hall.safe_state =
        Some(SafeState { capability: CapabilityId::parse("light.turn_off").unwrap(), params: Payload::new() });
    let resources = ResourceGraph::new(
        vec![
            res("home", ResourceKind::Site, None, None),
            hall,
            res("desk-light", ResourceKind::Light, Some("home"), Some(("device:desk-light", caps))),
        ],
        &registry,
    )
    .unwrap();
    let policy = PolicyEngine::with_default_policies(&registry).unwrap();
    let tokens = TokenAuthority::new(&key("domain:home/authority"), entropy()).verifier();
    Home { identities, registry, resources, policy, tokens, safety: Safety::default() }
}

impl Home {
    /// Alice asks for `action` on `resource`; the Authority Engine decides.
    fn grant(&self, resource: &str, action: &str, params: Payload) -> Grant {
        let mut i = Intent::new(
            new_intent_id(chitala_platform::memory::test_entropy()),
            id("person:alice"),
            id("person:alice"),
            CapabilityId::parse(action).unwrap(),
            rid(resource),
            NOW - 1_000,
            60_000,
        );
        i.params = params;
        let bytes = i.sign(&key("person:alice"));
        let keys =
            |k: &KeyId| self.identities.principals().find(|p| &p.key_id == k).map(|p| (p.id.clone(), p.public_key));
        let verified = open_signed(&bytes, &keys).unwrap();
        let world = AuthorityWorld {
            identities: &self.identities,
            registry: &self.registry,
            resources: &self.resources,
            policy: &self.policy,
            tokens: &self.tokens,
            revocations: &RevocationList::new(),
            devices: &devices,
            now_ms: NOW,
        };
        match decide(&world, &verified, &[]).verdict {
            Verdict::Allow(g) => *g,
            other => panic!("expected a grant, got {other:?}"),
        }
    }

    /// Safety clears exactly what the grant describes, for `subject`.
    fn clear_for(&mut self, g: &Grant, subject: &[u8; 16], now: u64) -> Clearance {
        let state = payload([("on", false)]);
        self.safety
            .clear(
                &self.resources,
                &Proposed {
                    subject,
                    resource: g.resource(),
                    capability: g.def(),
                    params: g.params(),
                    risk: RiskClass::Low,
                    device: g.device(),
                    device_state: SecurityState::Trusted,
                    observation: Some(Observation { age_ms: 1_000, state: &state }),
                    device_busy: false,
                    resource_busy: false,
                },
                now,
            )
            .unwrap()
    }

    fn clear(&mut self, g: &Grant, now: u64) -> Clearance {
        let subject = *g.intent();
        self.clear_for(g, &subject, now)
    }
}

fn ctx(domain: &EntityId) -> DecisionContext<'_> {
    DecisionContext { domain, policy_fingerprint: "fp", epoch: 7 }
}

const EXECUTOR: ExecutorSession = [42; 16];

#[test]
fn mints_a_signed_single_executor_order_bound_to_its_decision() {
    let mut h = home();
    let boundary = TrustedExecutionBoundary::new(entropy());
    let g = h.grant("hall-light", "light.set_brightness", payload([("brightness_pct", 40i64)]));
    let (subject, digest) = (*g.intent(), *g.digest());
    let c = h.clear(&g, NOW);
    let domain = id("domain:home");
    let context =
        Authority::Intent(Box::new(h.grant("hall-light", "light.turn_on", Payload::new()))).context(&ctx(&domain));
    let minted = boundary.mint(Authority::Intent(Box::new(g)), c, &ctx(&domain), 3, &EXECUTOR, NOW + 10).unwrap();

    let order = ExecOrder::open(minted.bytes(), &boundary.order_key()).unwrap();
    assert_eq!(order.executor, EXECUTOR);
    assert_eq!((order.subject, order.subject_digest), (subject, digest));
    assert_eq!(order.resource, id("resource:hall-light"));
    assert_eq!(order.device, id("device:hall-light"));
    assert_eq!(order.params.get("brightness_pct"), Some(&ParamValue::Int(40)));
    assert_eq!((order.epoch, order.evidence_seq), (7, 3));
    assert_eq!((order.cleared_at_ms, order.issued_at_ms), (NOW, NOW + 10));
    assert_eq!(order.expires_at_ms - order.issued_at_ms, ORDER_TTL_MS);
    assert_ne!(order.id, subject, "the order id is fresh, not the intent id");
    // the context digest covers the decision context (same actor, domain, epoch, policy)
    assert_eq!(context["kind"], "intent");
    assert_eq!(context["epoch"], 7);

    let e = minted.expectation();
    assert_eq!((e.order_id(), e.executor(), e.device()), (&order.id, &EXECUTOR, &order.device));
    assert_eq!(e.order_digest(), &message_digest(minted.bytes()));
    // the node's identity key is not the order key
    assert!(ExecOrder::open(minted.bytes(), &key("service:node").public_key()).is_err());
}

#[test]
fn a_clearance_of_one_intent_never_clears_another() {
    let mut h = home();
    let boundary = TrustedExecutionBoundary::new(entropy());
    let domain = id("domain:home");
    // two intents asking for the very same action
    let a = h.grant("hall-light", "light.turn_on", Payload::new());
    let b = h.grant("hall-light", "light.turn_on", Payload::new());
    let clearance_of_a = h.clear(&a, NOW);
    let err =
        boundary.mint(Authority::Intent(Box::new(b)), clearance_of_a, &ctx(&domain), 1, &EXECUTOR, NOW).unwrap_err();
    assert_eq!(err, BoundaryError::SubjectMismatch);
}

#[test]
fn a_clearance_must_describe_exactly_the_granted_action() {
    let mut h = home();
    let boundary = TrustedExecutionBoundary::new(entropy());
    let domain = id("domain:home");

    // other resource / device
    let g = h.grant("hall-light", "light.turn_on", Payload::new());
    let other = h.grant("desk-light", "light.turn_on", Payload::new());
    let c = h.clear_for(&other, g.intent(), NOW);
    assert_eq!(
        boundary.mint(Authority::Intent(Box::new(g)), c, &ctx(&domain), 1, &EXECUTOR, NOW).unwrap_err(),
        BoundaryError::Mismatch("device")
    );

    // other parameters (changed after the decision)
    let g = h.grant("hall-light", "light.set_brightness", payload([("brightness_pct", 10i64)]));
    let loud = h.grant("hall-light", "light.set_brightness", payload([("brightness_pct", 100i64)]));
    let c = h.clear_for(&loud, g.intent(), NOW);
    assert_eq!(
        boundary.mint(Authority::Intent(Box::new(g)), c, &ctx(&domain), 1, &EXECUTOR, NOW).unwrap_err(),
        BoundaryError::Mismatch("parameters")
    );

    // other capability
    let g = h.grant("hall-light", "light.turn_on", Payload::new());
    let off = h.grant("hall-light", "light.turn_off", Payload::new());
    let c = h.clear_for(&off, g.intent(), NOW);
    assert_eq!(
        boundary.mint(Authority::Intent(Box::new(g)), c, &ctx(&domain), 1, &EXECUTOR, NOW).unwrap_err(),
        BoundaryError::Mismatch("capability")
    );
}

#[test]
fn a_stale_or_future_clearance_is_refused() {
    let mut h = home();
    let boundary = TrustedExecutionBoundary::new(entropy());
    let domain = id("domain:home");
    let g = h.grant("hall-light", "light.turn_on", Payload::new());
    let c = h.clear(&g, NOW);
    assert_eq!(
        boundary
            .mint(Authority::Intent(Box::new(g)), c, &ctx(&domain), 1, &EXECUTOR, NOW + CLEARANCE_TTL_MS + 1)
            .unwrap_err(),
        BoundaryError::Stale
    );
    let g = h.grant("hall-light", "light.turn_on", Payload::new());
    let c = h.clear(&g, NOW + 5_000);
    assert_eq!(
        boundary.mint(Authority::Intent(Box::new(g)), c, &ctx(&domain), 1, &EXECUTOR, NOW).unwrap_err(),
        BoundaryError::Stale
    );
}

#[test]
fn every_boundary_has_its_own_key() {
    let a = TrustedExecutionBoundary::new(entropy());
    let b = TrustedExecutionBoundary::new(entropy());
    assert_ne!(a.order_key(), b.order_key(), "a restarted node invalidates every outstanding order");
    assert!(!format!("{a:?}").contains("key:"), "the order key is never printed");
}

fn receipt_for(boundary: &TrustedExecutionBoundary, m: &MintedOrder, state: &Payload) -> ExecutionReceipt {
    let order = ExecOrder::open(m.bytes(), &boundary.order_key()).unwrap();
    ExecutionReceipt::for_order(&order, m.bytes(), state, order.issued_at_ms + 5)
}

#[test]
fn receipts_must_answer_exactly_the_order() {
    let mut h = home();
    let boundary = TrustedExecutionBoundary::new(entropy());
    let domain = id("domain:home");
    let g = h.grant("hall-light", "light.turn_on", Payload::new());
    let c = h.clear(&g, NOW);
    let m = boundary.mint(Authority::Intent(Box::new(g)), c, &ctx(&domain), 1, &EXECUTOR, NOW).unwrap();
    let on = payload([("on", true)]);
    let good = receipt_for(&boundary, &m, &on);
    let e = m.expectation();
    assert_eq!(verify_receipt(e, Some(&good), &on), Ok(()));
    assert_eq!(verify_receipt(e, None, &on), Err(ReceiptError::Missing));

    let forged = |f: &dyn Fn(&mut ExecutionReceipt)| {
        let mut r = good.clone();
        f(&mut r);
        verify_receipt(e, Some(&r), &on)
    };
    assert_eq!(forged(&|r| r.order[0] ^= 1), Err(ReceiptError::Mismatch("order id")));
    assert_eq!(forged(&|r| r.order_digest[0] ^= 1), Err(ReceiptError::Mismatch("order bytes")));
    assert_eq!(forged(&|r| r.executor = [0; 16]), Err(ReceiptError::Mismatch("executor")));
    assert_eq!(forged(&|r| r.device = id("device:desk-light")), Err(ReceiptError::Mismatch("device")));
    assert_eq!(
        forged(&|r| r.capability = CapabilityId::parse("light.turn_off").unwrap()),
        Err(ReceiptError::Mismatch("capability"))
    );
    assert_eq!(forged(&|r| r.executed_at_ms = NOW + ORDER_TTL_MS + RECEIPT_SKEW_MS + 1), Err(ReceiptError::Time));
    // the receipt vouches for one state: a different reported state does not match it
    assert_eq!(verify_receipt(e, Some(&good), &payload([("on", false)])), Err(ReceiptError::State));
    // a genuine receipt of another order does not answer this one
    let g2 = h.grant("hall-light", "light.turn_on", Payload::new());
    let c2 = h.clear(&g2, NOW);
    let m2 = boundary.mint(Authority::Intent(Box::new(g2)), c2, &ctx(&domain), 2, &EXECUTOR, NOW).unwrap();
    assert!(verify_receipt(m2.expectation(), Some(&good), &on).is_err());
}

#[test]
fn a_safe_state_is_minted_from_the_engine_s_recovery_grant_only_for_its_resource() {
    let mut h = home();
    let boundary = TrustedExecutionBoundary::new(entropy());
    let domain = id("domain:home");
    let recovery = |h: &Home, resource: &str| {
        authorize_recovery(RecoveryRequest {
            graph: &h.resources,
            registry: &h.registry,
            resource: &rid(resource),
            actor: &id("service:node"),
            subject: [5; 16],
            trigger: 12,
            now_ms: NOW,
        })
    };
    assert!(recovery(&h, "desk-light").is_err(), "no safe state declared there");
    let r = recovery(&h, "hall-light").unwrap();
    let digest = *r.digest();
    // Safety clears it like any action, for its own subject
    let off = h.grant("hall-light", "light.turn_off", Payload::new());
    let c = h.clear_for(&off, &[5; 16], NOW);
    let authority = Authority::Recovery(Box::new(r));
    let context = authority.context(&ctx(&domain));
    assert_eq!(context["kind"], "recovery");
    assert_eq!(context["actor"], "service:node");
    assert_eq!(context["policy"], serde_json::json!(["safe-state:resource:hall-light", "trigger:12"]));
    let minted = boundary.mint(authority, c, &ctx(&domain), 13, &EXECUTOR, NOW).unwrap();
    let order = ExecOrder::open(minted.bytes(), &boundary.order_key()).unwrap();
    assert_eq!((order.subject, order.subject_digest), ([5; 16], digest));
    assert_eq!(order.actor, id("service:node"));
    assert_eq!(order.capability.as_str(), "light.turn_off");
    assert_eq!(order.context_digest, context_digest(&context));

    // the clearance of an intent does not clear the recovery, nor one for another resource
    let r = recovery(&h, "hall-light").unwrap();
    let c = h.clear(&off, NOW);
    assert_eq!(
        boundary.mint(Authority::Recovery(Box::new(r)), c, &ctx(&domain), 1, &EXECUTOR, NOW).unwrap_err(),
        BoundaryError::SubjectMismatch
    );
    let r = recovery(&h, "hall-light").unwrap();
    let desk_off = h.grant("desk-light", "light.turn_off", Payload::new());
    let c = h.clear_for(&desk_off, &[5; 16], NOW);
    assert_eq!(
        boundary.mint(Authority::Recovery(Box::new(r)), c, &ctx(&domain), 1, &EXECUTOR, NOW).unwrap_err(),
        BoundaryError::Mismatch("device")
    );
}
