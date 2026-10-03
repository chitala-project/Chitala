//! Reference Monitor tests: one test per deny code plus the v17 milestone flows.

use super::*;
use chitala_identity::{key_id_of, test_seed, Keypair};
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
    resources: chitala_resource::ResourceGraph,
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
            ("service:automation", &[][..]),
            ("service:rogue", &[][..]),
        ] {
            identities.enroll(id(who), key(who).public_key(), roles).unwrap();
        }
        identities.set_serves(&id("ai:assistant"), &[id("person:alice")]).unwrap();
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
        let authority = TokenAuthority::new(
            &key("domain:home/authority"),
            std::sync::Arc::new(chitala_platform::memory::test_entropy()),
        );
        let tokens = authority.verifier();
        let policy = PolicyEngine::with_default_policies(&registry).unwrap();
        Self {
            resources: chitala_resource::ResourceGraph::default(),
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
            resources: &self.resources,
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
                    holder_key: key_id_of(&key(holder).public_key()),
                    issuer: id("person:alice"),
                    rights: rights.iter().map(|(t, c)| Right::new(id(t), cap(c))).collect(),
                    not_before_ms: 0,
                    not_after_ms: NOW + 3_600_000,
                    redelegate: 0,
                    issued_epoch: 0,
                    for_persons: if holder.starts_with("ai:") { vec![id("person:alice")] } else { vec![] },
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
fn ai_commands_are_refused_intents_are_required() {
    // Invariant 1: an AI produces intents; it never sends a command, not even
    // with a token that names the right
    let mut f = Fixture::new();
    let tok = f.token("ai:assistant", &[("device:light", "light.turn_on"), ("device:door", "lock.unlock")]);
    for (target, capability) in [("device:light", "light.turn_on"), ("device:door", "lock.unlock")] {
        let mut m = f.msg("ai:assistant", target, capability, Payload::new());
        m.authority = Some(tok.clone());
        let d = f.check(&m);
        assert_eq!(denied(&d), DenyCode::IntentRequired);
        let Decision::Deny(d) = d else { unreachable!() };
        assert!(d.authenticated);
        assert_eq!(d.actor, Some(id("ai:assistant")));
        assert_eq!(d.stage, Stage::Identity);
    }
    // reading is not commanding: queries still go through the normal stages
    let m = f.msg("ai:assistant", "device:light", "device.read_state", Payload::new());
    assert_eq!(denied(&f.check(&m)), DenyCode::TokenMissing);
}

#[test]
fn unauthorized_service_is_denied() {
    let mut f = Fixture::new();
    let m = f.msg("service:automation", "device:light", "light.turn_on", Payload::new());
    let d = f.check(&m);
    assert_eq!(denied(&d), DenyCode::TokenMissing);
    let Decision::Deny(d) = d else { unreachable!() };
    assert!(d.authenticated);
    assert_eq!(d.stage, Stage::Authority);
}

#[test]
fn delegated_service_can_turn_on() {
    let mut f = Fixture::new();
    let tok = f.token("service:automation", &[("device:light", "light.turn_on")]);
    let mut m = f.msg("service:automation", "device:light", "light.turn_on", Payload::new());
    m.authority = Some(tok);
    let a = allowed(f.check(&m));
    assert_eq!(a.policy_reasons(), &["token-grant".to_string()]);
    assert_eq!(a.token().unwrap().depth, 1);
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
    let mut m = f.msg("service:automation", "device:light", "light.turn_on", Payload::new());
    m.authority = Some(b"not a biscuit".to_vec());
    assert_eq!(denied(&f.check(&m)), DenyCode::TokenInvalid);

    // a token minted by another domain's authority
    let foreign = TokenAuthority::new(
        &key("domain:evil/authority"),
        std::sync::Arc::new(chitala_platform::memory::test_entropy()),
    )
    .issue(
        &Grant {
            holder: id("service:automation"),
            holder_key: key_id_of(&key("service:automation").public_key()),
            issuer: id("person:eve"),
            rights: vec![Right::new(id("device:light"), cap("light.turn_on"))],
            not_before_ms: 0,
            not_after_ms: NOW + 60_000,
            redelegate: 0,
            issued_epoch: 0,
            for_persons: vec![],
        },
        NOW,
    )
    .unwrap();
    let mut m = f.msg("service:automation", "device:light", "light.turn_on", Payload::new());
    m.authority = Some(foreign.bytes);
    assert_eq!(denied(&f.check(&m)), DenyCode::TokenInvalid);

    let tok = f.token("service:automation", &[("device:light", "light.turn_on")]);
    // wrong capability
    let mut m = f.msg("service:automation", "device:light", "light.turn_off", Payload::new());
    m.authority = Some(tok.clone());
    assert_eq!(denied(&f.check(&m)), DenyCode::TokenDenied);
    // stolen by another principal (holder-bound)
    let mut m = f.msg("service:rogue", "device:light", "light.turn_on", Payload::new());
    m.authority = Some(tok.clone());
    assert_eq!(denied(&f.check(&m)), DenyCode::TokenDenied);
    // revoked
    let rid = f.tokens.verify(&tok).unwrap().revocation_id;
    f.revocations.revoke(&rid);
    let mut m = f.msg("service:automation", "device:light", "light.turn_on", Payload::new());
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
    // AI may never administer the domain, even with a token for it: refused as
    // a command before policy (and C11-ai-no-domain-admin stays as a backstop)
    let tok = f.token("ai:assistant", &[("domain:home", "domain.set_principal_state")]);
    let mut m = f.msg(
        "ai:assistant",
        "domain:home",
        "domain.set_principal_state",
        payload([("principal", "ai:assistant"), ("state", "TRUSTED")]),
    );
    m.authority = Some(tok);
    assert_eq!(denied(&f.check(&m)), DenyCode::IntentRequired);
}

#[test]
fn evaluate_policy_for_delegation_checks() {
    let f = Fixture::new();
    let world = World {
        identities: &f.identities,
        registry: &f.registry,
        targets: &f.devices,
        resources: &f.resources,
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

// ───────────────────────────── intents ─────────────────────────────

mod intents {
    use super::*;
    use chitala_intent::{Approval, Intent, Verdict as Answer};
    use chitala_policy::authority::Verdict;
    use chitala_resource::{Boundary, CapabilityBinding, Resource, ResourceGraph, ResourceId, ResourceKind, StateRef};

    fn rid(s: &str) -> ResourceId {
        ResourceId::new(s).unwrap()
    }

    fn fixture() -> Fixture {
        let mut f = Fixture::new();
        f.identities.set_serves(&id("ai:assistant"), &[id("person:alice")]).unwrap();
        let mut home = Resource {
            id: rid("home"),
            kind: ResourceKind::Site,
            name: "Home".into(),
            parent: None,
            owners: vec![id("person:alice")],
            boundary: Boundary::Interior,
            zone: None,
            bindings: vec![],
            state: None,
            envelope: vec![],
            two_key: false,
        };
        let mut light = home.clone();
        light.id = rid("light");
        light.kind = ResourceKind::Light;
        light.parent = Some(rid("home"));
        light.owners = vec![];
        light.bindings =
            vec![CapabilityBinding { capability: cap("light.turn_on"), device: id("device:light"), risk_floor: None }];
        light.state = Some(StateRef { device: id("device:light"), max_age_ms: 60_000 });
        home.name = "Home".into();
        f.resources = ResourceGraph::new(vec![home, light], &f.registry).unwrap();
        f
    }

    fn intent(f: &mut Fixture, actor: &str) -> Intent {
        f.counter = f.counter.wrapping_add(1);
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id(actor),
            id("person:alice"),
            cap("light.turn_on"),
            rid("light"),
            NOW,
            30_000,
        );
        i.id = [f.counter; 16];
        if actor.starts_with("ai:") {
            i.authority = Some(f.token(actor, &[("resource:light", "light.turn_on")]));
        }
        i
    }

    impl Fixture {
        fn world(&self) -> World<'_> {
            World {
                identities: &self.identities,
                registry: &self.registry,
                targets: &self.devices,
                resources: &self.resources,
                tokens: &self.tokens,
                revocations: &self.revocations,
                policy: &self.policy,
                now_ms: self.now,
            }
        }
        fn admit(&mut self, bytes: &[u8]) -> Result<VerifiedIntent, Box<Denial>> {
            let mut m = std::mem::replace(&mut self.monitor, Monitor::new(MonitorConfig::default()));
            let r = m.admit_intent(&self.world(), bytes);
            self.monitor = m;
            r
        }
        fn admit_answer(&mut self, bytes: &[u8]) -> Result<VerifiedApproval, Box<Denial>> {
            let mut m = std::mem::replace(&mut self.monitor, Monitor::new(MonitorConfig::default()));
            let r = m.admit_approval(&self.world(), bytes);
            self.monitor = m;
            r
        }
    }

    #[test]
    fn admitted_intents_reach_the_authority_engine() {
        let mut f = fixture();
        let i = intent(&mut f, "ai:assistant");
        let v = f.admit(&i.sign(&key("ai:assistant"))).unwrap();
        let d = decide_intent(&f.world(), &v, &[]);
        let Verdict::Allow(g) = d.verdict else { panic!("{:?}", d.trace) };
        assert_eq!(g.device(), &id("device:light"));
    }

    #[test]
    fn intent_admission_stages() {
        let mut f = fixture();
        let code = |r: Result<VerifiedIntent, Box<Denial>>| r.unwrap_err().code;
        // a CSME is not an intent
        let csme = f.msg("ai:assistant", "device:light", "light.turn_on", Payload::new()).sign(&key("ai:assistant"));
        assert_eq!(code(f.admit(&csme)), DenyCode::Decode);
        // unknown signer, wrong signer, tampered
        let i = intent(&mut f, "ai:assistant");
        assert_eq!(code(f.admit(&i.sign(&key("ai:stranger")))), DenyCode::UnknownKey);
        assert_eq!(code(f.admit(&i.sign(&key("ai:rogue-not-enrolled")))), DenyCode::UnknownKey);
        let d = f.admit(&i.sign(&key("person:alice"))).unwrap_err();
        assert_eq!((d.code, d.authenticated), (DenyCode::ActorKeyMismatch, true));
        let mut t = i.sign(&key("ai:assistant"));
        let n = t.len();
        t[n - 1] ^= 1;
        assert_eq!(code(f.admit(&t)), DenyCode::BadSignature);
        // single use
        let ok = i.sign(&key("ai:assistant"));
        assert!(f.admit(&ok).is_ok());
        assert_eq!(code(f.admit(&ok)), DenyCode::Replay);
        // freshness
        let mut late = intent(&mut f, "ai:assistant");
        late.requested_at_ms = NOW - 60_000;
        late.constraints.deadline_ms = NOW;
        assert_eq!(code(f.admit(&late.sign(&key("ai:assistant")))), DenyCode::Expired);
        let mut future = intent(&mut f, "ai:assistant");
        future.requested_at_ms = NOW + 60_000;
        future.constraints.deadline_ms = NOW + 90_000;
        assert_eq!(code(f.admit(&future.sign(&key("ai:assistant")))), DenyCode::NotYetValid);
        // signed before this node started
        f.monitor.reject_issued_before(NOW + 1);
        let old = intent(&mut f, "ai:assistant");
        assert_eq!(code(f.admit(&old.sign(&key("ai:assistant")))), DenyCode::Replay);
        f.monitor.reject_issued_before(0);
        // contained principals
        f.identities.set_state(&id("ai:assistant"), SecurityState::Quarantined).unwrap();
        let q = intent(&mut f, "ai:assistant");
        assert_eq!(code(f.admit(&q.sign(&key("ai:assistant")))), DenyCode::PrincipalState);
        // a forged cause is a provenance failure, attributed to the relaying actor
        f.identities.set_state(&id("ai:assistant"), SecurityState::Trusted).unwrap();
        let mut relay = intent(&mut f, "ai:assistant");
        relay.context.cause = Some(intent(&mut f, "service:automation").sign(&key("ai:assistant")));
        let d = f.admit(&relay.sign(&key("ai:assistant"))).unwrap_err();
        assert_eq!((d.code, d.actor), (DenyCode::Provenance, Some(id("ai:assistant"))));
    }

    #[test]
    fn approval_admission() {
        let mut f = fixture();
        let i = intent(&mut f, "ai:assistant");
        let a = Approval {
            intent: i.id,
            intent_digest: i.digest(),
            approver: id("person:alice"),
            verdict: Answer::Approve,
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
            note: None,
        };
        let bytes = a.sign(&key("person:alice"));
        assert_eq!(f.admit_answer(&bytes).unwrap().approval(), &a);
        assert_eq!(f.admit_answer(&bytes).unwrap_err().code, DenyCode::Replay);
        // an approval is not an intent and vice versa
        assert_eq!(f.admit(&bytes).unwrap_err().code, DenyCode::Decode);
        assert_eq!(f.admit_answer(&i.sign(&key("ai:assistant"))).unwrap_err().code, DenyCode::Decode);
        // signed by someone other than the named approver
        let mut b = a.clone();
        b.intent = [7; 16];
        assert_eq!(f.admit_answer(&b.sign(&key("person:bob"))).unwrap_err().code, DenyCode::ActorKeyMismatch);
    }
}
