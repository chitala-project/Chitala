//! Reference Monitor tests: one test per deny code plus the v17 milestone flows.

use super::*;
use chitala_identity::{test_seed, Keypair};
use chitala_model::{payload, ParamValue, RiskClass, SecurityClass};
use chitala_token::{Grant, Right, TokenAuthority};

const NOW: u64 = 1_790_000_000_000;

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}
fn key(label: &str) -> Keypair {
    Keypair::from_seed(&test_seed(label))
}

struct Devices(Vec<TargetInfo>);

impl Targets for Devices {
    fn target(&self, id: &EntityId) -> Option<TargetInfo> {
        self.0.iter().find(|t| &t.id == id).cloned()
    }
}

struct Fixture {
    identities: IdentityRegistry,
    registry: CapabilityRegistry,
    devices: Devices,
    authority: TokenAuthority,
    tokens: TokenVerifier,
    revocations: RevocationList,
    policy: PolicyEngine,
    monitor: Monitor,
    now: u64,
    counter: u8,
}

fn device(id_: &str, caps: &[&str], sc: SecurityClass) -> TargetInfo {
    TargetInfo {
        id: id(id_),
        kind: TargetKind::Device,
        capabilities: caps.iter().map(|c| cap(c)).collect(),
        device: Some(DeviceAttrs {
            security_class: sc,
            room: Some("living-room".into()),
            state: SecurityState::Trusted,
        }),
    }
}

impl Fixture {
    fn new() -> Self {
        let registry = CapabilityRegistry::core_v0_1();
        let mut identities = IdentityRegistry::new();
        for (who, roles) in [
            ("person:alice", &["owner"][..]),
            ("person:bob", &["adult"][..]),
            ("ai:assistant", &[][..]),
            ("ai:rogue", &[][..]),
        ] {
            identities.enroll(id(who), key(who).public_key(), roles).unwrap();
        }
        let domain_caps: Vec<CapabilityId> =
            registry.iter().filter(|d| d.target == TargetKind::Domain).map(|d| d.id.clone()).collect();
        let devices = Devices(vec![
            device(
                "device:light",
                &["device.read_state", "light.turn_on", "light.turn_off", "light.set_brightness"],
                SecurityClass::Sc2,
            ),
            device("device:door", &["device.read_state", "lock.lock", "lock.unlock"], SecurityClass::Sc2),
            TargetInfo { id: id("domain:home"), kind: TargetKind::Domain, capabilities: domain_caps, device: None },
        ]);
        let authority = TokenAuthority::new(&key("domain:home/authority"));
        let tokens = authority.verifier();
        let policy = PolicyEngine::with_default_policies(&registry).unwrap();
        Self {
            identities,
            registry,
            devices,
            authority,
            tokens,
            revocations: RevocationList::new(),
            policy,
            monitor: Monitor::new(MonitorConfig::default()),
            now: NOW,
            counter: 0,
        }
    }

    fn msg(&mut self, actor: &str, target: &str, capability: &str, pl: Payload) -> Csme {
        self.counter = self.counter.wrapping_add(1);
        let c = cap(capability);
        let (version, risk, kind) = self.registry.get(&c).map(|d| (d.version, d.risk, d.kind)).unwrap_or((
            1,
            RiskClass::Low,
            CapabilityKind::Action,
        ));
        Csme {
            message_id: [self.counter; 16],
            correlation_id: None,
            source: id("service:test"),
            destination: id(target),
            actor: id(actor),
            capability: c,
            capability_version: version,
            message_type: if kind == CapabilityKind::Query { MessageType::Query } else { MessageType::Command },
            issued_at_ms: self.now,
            expires_at_ms: self.now + 30_000,
            context_ref: None,
            authority: None,
            risk,
            payload: pl,
        }
    }

    fn check_bytes(&mut self, bytes: &[u8]) -> Decision {
        let world = World {
            identities: &self.identities,
            registry: &self.registry,
            targets: &self.devices,
            tokens: &self.tokens,
            revocations: &self.revocations,
            policy: &self.policy,
            now_ms: self.now,
        };
        self.monitor.check(&world, bytes)
    }

    fn check(&mut self, m: &Csme) -> Decision {
        let bytes = m.sign(&key(&m.actor.to_string()));
        self.check_bytes(&bytes)
    }

    fn token(&self, holder: &str, rights: &[(&str, &str)]) -> Vec<u8> {
        self.authority
            .issue(
                &Grant {
                    holder: id(holder),
                    issuer: id("person:alice"),
                    rights: rights.iter().map(|(t, c)| Right::new(id(t), cap(c))).collect(),
                    not_after_ms: NOW + 3_600_000,
                },
                NOW,
            )
            .unwrap()
            .bytes
    }
}

fn denied(d: &Decision) -> DenyCode {
    match d {
        Decision::Deny(x) => x.code,
        Decision::Allow(a) => panic!("expected a denial, got allow of {}", a.capability()),
    }
}

fn allowed(d: Decision) -> Authorized {
    match d {
        Decision::Allow(a) => *a,
        Decision::Deny(x) => panic!("expected allow, got {} at {}: {}", x.code, x.stage.as_str(), x.reason),
    }
}

// ───────────────────────── milestone 0.0.1 (v17 §4) ─────────────────────────

#[test]
fn owner_turns_on_light() {
    let mut f = Fixture::new();
    let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    let a = allowed(f.check(&m));
    assert_eq!(a.actor(), &id("person:alice"));
    assert_eq!(a.policy_reasons(), &["owner-all".to_string()]);
    assert!(a.token().is_none());
}

#[test]
fn unauthorized_ai_is_denied() {
    let mut f = Fixture::new();
    let m = f.msg("ai:assistant", "device:light", "light.turn_on", Payload::new());
    let d = f.check(&m);
    assert_eq!(denied(&d), DenyCode::TokenMissing);
    let Decision::Deny(d) = d else { unreachable!() };
    assert!(d.authenticated);
    assert_eq!(d.actor, Some(id("ai:assistant")));
    assert_eq!(d.stage, Stage::Authority);
}

#[test]
fn delegated_ai_can_turn_on_but_never_unlock() {
    let mut f = Fixture::new();
    let tok = f.token("ai:assistant", &[("device:light", "light.turn_on"), ("device:door", "lock.unlock")]);
    let mut m = f.msg("ai:assistant", "device:light", "light.turn_on", Payload::new());
    m.authority = Some(tok.clone());
    let a = allowed(f.check(&m));
    assert_eq!(a.policy_reasons(), &["token-grant".to_string()]);
    assert_eq!(a.token().unwrap().depth, 1);

    // even a token that names lock.unlock cannot beat the constitution
    let mut m = f.msg("ai:assistant", "device:door", "lock.unlock", Payload::new());
    m.authority = Some(tok);
    let d = f.check(&m);
    assert_eq!(denied(&d), DenyCode::PolicyDenied);
    let Decision::Deny(d) = d else { unreachable!() };
    assert_eq!(d.policy_reasons, vec!["C11-ai-no-high-risk".to_string()]);
}

// ───────────────────────────── envelope / identity ─────────────────────────────

#[test]
fn garbage_and_unknown_keys() {
    let mut f = Fixture::new();
    assert_eq!(denied(&f.check_bytes(b"hello")), DenyCode::Decode);
    let m = f.msg("person:mallory", "device:light", "light.turn_on", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::UnknownKey);
}

#[test]
fn forged_signature_is_not_attributed() {
    let mut f = Fixture::new();
    let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    let mut bytes = m.sign(&key("person:alice"));
    let last = bytes.len() - 1;
    bytes[last] ^= 0x55;
    let d = f.check_bytes(&bytes);
    assert_eq!(denied(&d), DenyCode::BadSignature);
    let Decision::Deny(d) = d else { unreachable!() };
    assert!(!d.authenticated);
    assert_eq!(d.actor, None);
}

#[test]
fn actor_must_be_signer() {
    let mut f = Fixture::new();
    let m = f.msg("person:alice", "device:door", "lock.unlock", Payload::new());
    // bob signs a message that claims to come from alice
    let bytes = m.sign(&key("person:bob"));
    assert_eq!(denied(&f.check_bytes(&bytes)), DenyCode::ActorKeyMismatch);
}

#[test]
fn security_state_gates_actions() {
    let mut f = Fixture::new();
    f.identities.set_state(&id("person:bob"), SecurityState::Quarantined).unwrap();
    let m = f.msg("person:bob", "device:light", "light.turn_on", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::PrincipalState);

    // RESTRICTED keeps low-risk actions only
    f.identities.set_state(&id("person:alice"), SecurityState::Restricted).unwrap();
    let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    allowed(f.check(&m));
    let m = f.msg("person:alice", "device:door", "lock.lock", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::PrincipalState);
}

#[test]
fn rate_limit_per_actor() {
    let mut f = Fixture::new();
    let limit = f.monitor.config().rate_limit;
    for _ in 0..limit {
        let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
        allowed(f.check(&m));
    }
    let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::RateLimited);
    // another actor is unaffected
    let m = f.msg("person:bob", "device:light", "light.turn_on", Payload::new());
    allowed(f.check(&m));
    // the window slides
    f.now += f.monitor.config().rate_window_ms;
    let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    allowed(f.check(&m));
}

// ───────────────────────────── freshness ─────────────────────────────

#[test]
fn freshness_and_replay() {
    let mut f = Fixture::new();
    let mut m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    m.message_type = MessageType::Event;
    assert_eq!(denied(&f.check(&m)), DenyCode::UnsupportedType);

    let mut m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    m.issued_at_ms = NOW + 10_000;
    m.expires_at_ms = NOW + 20_000;
    assert_eq!(denied(&f.check(&m)), DenyCode::NotYetValid);

    let mut m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    m.issued_at_ms = NOW - 40_000;
    m.expires_at_ms = NOW - 10_000;
    assert_eq!(denied(&f.check(&m)), DenyCode::Expired);

    let mut m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    m.expires_at_ms = NOW + 3_600_000;
    assert_eq!(denied(&f.check(&m)), DenyCode::LifetimeTooLong);

    let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    let bytes = m.sign(&key("person:alice"));
    allowed(f.check_bytes(&bytes));
    assert_eq!(denied(&f.check_bytes(&bytes)), DenyCode::Replay);
}

#[test]
fn requests_from_before_a_restart_are_refused() {
    let mut f = Fixture::new();
    let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    let bytes = m.sign(&key("person:alice"));
    // a fresh monitor (new process) started after the request was signed
    f.monitor = Monitor::new(MonitorConfig::default());
    f.monitor.reject_issued_before(NOW + 1);
    f.now = NOW + 1;
    assert_eq!(denied(&f.check_bytes(&bytes)), DenyCode::Replay);
    let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    allowed(f.check(&m));
}

#[test]
fn denied_request_cannot_be_replayed_after_a_grant() {
    let mut f = Fixture::new();
    // bob may not unlock; the signed request is consumed anyway
    let m = f.msg("person:bob", "device:door", "lock.unlock", Payload::new());
    let bytes = m.sign(&key("person:bob"));
    assert_eq!(denied(&f.check_bytes(&bytes)), DenyCode::PolicyDenied);
    f.identities = {
        let mut r = IdentityRegistry::new();
        r.enroll(id("person:bob"), key("person:bob").public_key(), &["owner"]).unwrap();
        r
    };
    assert_eq!(denied(&f.check_bytes(&bytes)), DenyCode::Replay);
}

// ───────────────────────────── capability ─────────────────────────────

#[test]
fn capability_checks() {
    let mut f = Fixture::new();
    let m = f.msg("person:alice", "device:toaster", "light.turn_on", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::UnknownTarget);

    let m = f.msg("person:alice", "device:light", "x-acme.light.disco", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::UnknownCapability);

    let mut m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    m.capability_version = 2;
    assert_eq!(denied(&f.check(&m)), DenyCode::CapabilityVersion);

    let m = f.msg("person:alice", "device:light", "lock.unlock", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::UnsupportedByTarget);

    // a domain capability sent to a device and vice versa
    let m = f.msg("person:alice", "device:light", "domain.list_devices", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::UnsupportedByTarget);
    let m = f.msg("person:alice", "domain:home", "light.turn_on", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::UnsupportedByTarget);

    let mut m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
    m.message_type = MessageType::Query;
    assert_eq!(denied(&f.check(&m)), DenyCode::KindMismatch);

    // understating risk to slip under a policy is caught
    let mut m = f.msg("person:alice", "device:door", "lock.unlock", Payload::new());
    m.risk = RiskClass::Low;
    assert_eq!(denied(&f.check(&m)), DenyCode::RiskMismatch);

    let m = f.msg("person:alice", "device:light", "light.set_brightness", payload([("brightness_pct", true)]));
    assert_eq!(denied(&f.check(&m)), DenyCode::PayloadInvalid);
    let m = f.msg("person:alice", "device:light", "light.set_brightness", payload([("brightness_pct", 140i64)]));
    assert_eq!(denied(&f.check(&m)), DenyCode::SafetyEnvelope);
    let m = f.msg(
        "person:alice",
        "device:light",
        "light.set_brightness",
        payload([("brightness_pct", ParamValue::Int(40)), ("extra", ParamValue::Int(1))]),
    );
    assert_eq!(denied(&f.check(&m)), DenyCode::PayloadInvalid);
}

// ───────────────────────────── authority ─────────────────────────────

#[test]
fn token_checks() {
    let mut f = Fixture::new();
    let mut m = f.msg("ai:assistant", "device:light", "light.turn_on", Payload::new());
    m.authority = Some(b"not a biscuit".to_vec());
    assert_eq!(denied(&f.check(&m)), DenyCode::TokenInvalid);

    // a token minted by another domain's authority
    let foreign = TokenAuthority::new(&key("domain:evil/authority"))
        .issue(
            &Grant {
                holder: id("ai:assistant"),
                issuer: id("person:eve"),
                rights: vec![Right::new(id("device:light"), cap("light.turn_on"))],
                not_after_ms: NOW + 60_000,
            },
            NOW,
        )
        .unwrap();
    let mut m = f.msg("ai:assistant", "device:light", "light.turn_on", Payload::new());
    m.authority = Some(foreign.bytes);
    assert_eq!(denied(&f.check(&m)), DenyCode::TokenInvalid);

    let tok = f.token("ai:assistant", &[("device:light", "light.turn_on")]);
    // wrong capability
    let mut m = f.msg("ai:assistant", "device:light", "light.turn_off", Payload::new());
    m.authority = Some(tok.clone());
    assert_eq!(denied(&f.check(&m)), DenyCode::TokenDenied);
    // stolen by another AI (holder-bound)
    let mut m = f.msg("ai:rogue", "device:light", "light.turn_on", Payload::new());
    m.authority = Some(tok.clone());
    assert_eq!(denied(&f.check(&m)), DenyCode::TokenDenied);
    // revoked
    let rid = f.tokens.verify(&tok).unwrap().revocation_id;
    f.revocations.revoke(&rid);
    let mut m = f.msg("ai:assistant", "device:light", "light.turn_on", Payload::new());
    m.authority = Some(tok);
    let d = f.check(&m);
    assert_eq!(denied(&d), DenyCode::TokenRevoked);
    let Decision::Deny(d) = d else { unreachable!() };
    assert_eq!(d.token_id, Some(rid));
}

#[test]
fn policy_checks() {
    let mut f = Fixture::new();
    // adult may not unlock
    let m = f.msg("person:bob", "device:door", "lock.unlock", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::PolicyDenied);
    // AI may never administer the domain, even with a token for it
    let tok = f.token("ai:assistant", &[("domain:home", "domain.set_principal_state")]);
    let mut m = f.msg(
        "ai:assistant",
        "domain:home",
        "domain.set_principal_state",
        payload([("principal", "ai:assistant"), ("state", "TRUSTED")]),
    );
    m.authority = Some(tok);
    let d = f.check(&m);
    assert_eq!(denied(&d), DenyCode::PolicyDenied);
    let Decision::Deny(d) = d else { unreachable!() };
    assert!(d.policy_reasons.contains(&"C11-ai-no-domain-admin".to_string()));
}

#[test]
fn evaluate_policy_for_delegation_checks() {
    let f = Fixture::new();
    let world = World {
        identities: &f.identities,
        registry: &f.registry,
        targets: &f.devices,
        tokens: &f.tokens,
        revocations: &f.revocations,
        policy: &f.policy,
        now_ms: NOW,
    };
    let bob = f.identities.get(&id("person:bob")).unwrap();
    let light = f.devices.target(&id("device:light")).unwrap();
    let door = f.devices.target(&id("device:door")).unwrap();
    let on = f.registry.get(&cap("light.turn_on")).unwrap();
    let unlock = f.registry.get(&cap("lock.unlock")).unwrap();
    assert!(evaluate_policy(&world, bob, &light, on, false).unwrap().allowed);
    assert!(!evaluate_policy(&world, bob, &door, unlock, false).unwrap().allowed);
}

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        /// Flipping any single bit of a valid signed request never yields an allow.
        #[test]
        fn bit_flips_never_allow(pos in any::<prop::sample::Index>(), bit in 0u8..8) {
            let mut f = Fixture::new();
            let m = f.msg("person:alice", "device:light", "light.turn_on", Payload::new());
            let mut bytes = m.sign(&key("person:alice"));
            let i = pos.index(bytes.len());
            bytes[i] ^= 1 << bit;
            prop_assert!(!f.check_bytes(&bytes).is_allow());
        }
    }
}
