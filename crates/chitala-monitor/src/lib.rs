//! Reference Monitor (spec `specs/08-reference-monitor.md`, Blueprint v8 §1, v17 §3).
//!
//! Every request — from a person, an AI, a service or a device — is a signed CSME
//! and passes the same five stages, in this order:
//!
//! 1. **Envelope**   COSE structure, algorithm, protected header.
//! 2. **Identity**   key id → principal, signature, *then* payload decoding, actor =
//!    signer, security state, per-actor rate limit.
//! 3. **Freshness**  message type, issued-at / expiry window, replay cache.
//! 4. **Capability** target, registry entry, version, kind, declared risk, payload
//!    schema and safety envelope, security-state risk ceiling.
//! 5. **Authority**  capability token (signature, revocation, holder-bound Datalog
//!    authorization) and the domain policy (Cedar + Security Constitution).
//!
//! **AI principals never send commands** (Invariant 1: AI produces Intent,
//! Chitala produces Authority, only the trusted execution boundary produces
//! physical Commands). A `command` CSME from an AI is refused with
//! `E_INTENT_REQUIRED`; AIs submit signed intents instead, which
//! [`Monitor::admit_intent`] authenticates (envelope, identity, freshness,
//! replay, relay chain) and [`decide_intent`] hands to the Authority Engine
//! (`chitala_policy::authority`). Human answers to escalations pass
//! [`Monitor::admit_approval`].
//!
//! The first failing check produces a [`Denial`] with a stable [`DenyCode`]. Success
//! produces an [`Authorized`] value. `Authorized` has no public constructor and is
//! neither `Clone` nor `Default`, so the only way for an adapter or the node to
//! obtain one is through [`Monitor::check`]: the type system makes the monitor
//! non-bypassable inside the Rust code base.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};

use chitala_csme::{Csme, SignedEnvelope, ID_LEN};
use chitala_identity::{IdentityRegistry, KeyId, Principal};
use chitala_intent::{OpenError, SignedApproval, SignedIntent, VerifiedApproval, VerifiedIntent};
use chitala_model::{
    CapabilityDef, CapabilityId, CapabilityKind, CapabilityRegistry, DenyCode, EntityId, EntityKind, MessageType,
    Payload, PayloadError, SecurityState, TargetKind,
};
use chitala_policy::authority::{self, AuthorityDecision, AuthorityWorld};
use chitala_policy::{
    DeviceAttrs, PolicyContext, PolicyDecision, PolicyEngine, PolicyError, PolicyRequest, PrincipalInfo, ResourceInfo,
};
use chitala_resource::ResourceGraph;
use chitala_token::{Presentation, RevocationList, TokenError, TokenRef, TokenVerifier};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorConfig {
    /// Maximum `exp - iat` of a request.
    pub max_lifetime_ms: u64,
    /// Tolerated clock skew for `iat` in the future.
    pub clock_skew_ms: u64,
    /// Authenticated requests per actor per window.
    pub rate_limit: u32,
    pub rate_window_ms: u64,
    /// Upper bound on remembered message ids.
    pub replay_capacity: usize,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            max_lifetime_ms: 60_000,
            clock_skew_ms: 5_000,
            rate_limit: 30,
            rate_window_ms: 10_000,
            replay_capacity: 100_000,
        }
    }
}

/// What the monitor needs to know about a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    pub id: EntityId,
    pub kind: TargetKind,
    pub capabilities: Vec<CapabilityId>,
    /// Present for device targets.
    pub device: Option<DeviceAttrs>,
}

/// Lookup of targets (devices and the domain itself). Implemented by the node.
pub trait Targets {
    fn target(&self, id: &EntityId) -> Option<TargetInfo>;
}

/// Read-only view of the domain for one decision.
pub struct World<'a> {
    pub identities: &'a IdentityRegistry,
    pub registry: &'a CapabilityRegistry,
    pub targets: &'a dyn Targets,
    pub resources: &'a ResourceGraph,
    pub tokens: &'a TokenVerifier,
    pub revocations: &'a RevocationList,
    pub policy: &'a PolicyEngine,
    pub now_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Envelope,
    Identity,
    Freshness,
    Capability,
    Authority,
    /// Refused by the safety layer after Authority (intent path).
    Safety,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Envelope => "envelope",
            Stage::Identity => "identity",
            Stage::Freshness => "freshness",
            Stage::Capability => "capability",
            Stage::Authority => "authority",
            Stage::Safety => "safety",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub code: DenyCode,
    pub stage: Stage,
    pub reason: String,
    /// `true` once the signature has been verified. Unauthenticated denials must
    /// not be attributed to the claimed actor (an attacker could forge them to get
    /// a victim quarantined).
    pub authenticated: bool,
    /// Set only when authenticated.
    pub actor: Option<EntityId>,
    pub message_id: Option<[u8; ID_LEN]>,
    pub target: Option<EntityId>,
    pub capability: Option<CapabilityId>,
    pub token_id: Option<String>,
    pub policy_reasons: Vec<String>,
}

/// Information about the token that contributed to an allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenUse {
    pub revocation_id: String,
    pub issuer: EntityId,
    pub depth: u8,
    pub expires_at_ms: u64,
    /// For re-checking revocation while the request executes (spec 19).
    pub reference: TokenRef,
}

/// Proof that the Reference Monitor allowed exactly this request.
#[derive(Debug)]
pub struct Authorized {
    envelope: Csme,
    /// SHA-256 of the signed request exactly as received.
    request_digest: [u8; 32],
    principal_kind: EntityKind,
    def: CapabilityDef,
    token: Option<TokenUse>,
    policy_reasons: Vec<String>,
    decided_at_ms: u64,
}

impl Authorized {
    pub fn envelope(&self) -> &Csme {
        &self.envelope
    }
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub fn actor(&self) -> &EntityId {
        &self.envelope.actor
    }
    pub fn actor_kind(&self) -> EntityKind {
        self.principal_kind
    }
    pub fn target(&self) -> &EntityId {
        &self.envelope.destination
    }
    pub fn capability(&self) -> &CapabilityId {
        &self.envelope.capability
    }
    pub fn def(&self) -> &CapabilityDef {
        &self.def
    }
    pub fn payload(&self) -> &Payload {
        &self.envelope.payload
    }
    pub fn token(&self) -> Option<&TokenUse> {
        self.token.as_ref()
    }
    pub fn policy_reasons(&self) -> &[String] {
        &self.policy_reasons
    }
    pub fn decided_at_ms(&self) -> u64 {
        self.decided_at_ms
    }
    pub fn message_id_hex(&self) -> String {
        hex::encode(self.envelope.message_id)
    }
}

#[derive(Debug)]
pub enum Decision {
    Allow(Box<Authorized>),
    Deny(Denial),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow(_))
    }
    pub fn deny_code(&self) -> Option<DenyCode> {
        match self {
            Decision::Deny(d) => Some(d.code),
            Decision::Allow(_) => None,
        }
    }
}

// ───────────────────────────── replay / rate state ─────────────────────────────

#[derive(Default)]
struct ReplayCache {
    seen: HashMap<(KeyId, [u8; ID_LEN]), u64>,
}

impl ReplayCache {
    fn prune(&mut self, now_ms: u64) {
        self.seen.retain(|_, until| *until > now_ms);
    }
}

#[derive(Default)]
struct RateLimiter {
    windows: HashMap<EntityId, VecDeque<u64>>,
}

impl RateLimiter {
    fn allow(&mut self, actor: &EntityId, now_ms: u64, limit: u32, window_ms: u64) -> bool {
        let w = self.windows.entry(actor.clone()).or_default();
        while matches!(w.front(), Some(t) if *t + window_ms <= now_ms) {
            w.pop_front();
        }
        if w.len() >= limit as usize {
            return false;
        }
        w.push_back(now_ms);
        true
    }
}

// ───────────────────────────── the monitor ─────────────────────────────

pub struct Monitor {
    cfg: MonitorConfig,
    replay: ReplayCache,
    rate: RateLimiter,
    /// Requests issued before this instant are refused: the replay cache does
    /// not survive a restart, so it cannot vouch for them.
    not_before_ms: u64,
}

/// Accumulates what is known so far, so every denial carries maximal context.
struct Trace {
    authenticated: bool,
    actor: Option<EntityId>,
    message_id: Option<[u8; ID_LEN]>,
    target: Option<EntityId>,
    capability: Option<CapabilityId>,
    token_id: Option<String>,
    policy_reasons: Vec<String>,
}

impl Trace {
    fn new() -> Self {
        Trace {
            authenticated: false,
            actor: None,
            message_id: None,
            target: None,
            capability: None,
            token_id: None,
            policy_reasons: Vec::new(),
        }
    }

    fn deny(&mut self, stage: Stage, code: DenyCode, reason: impl Into<String>) -> Decision {
        Decision::Deny(self.denial(stage, code, reason))
    }

    fn boxed(&mut self, stage: Stage, code: DenyCode, reason: impl Into<String>) -> Box<Denial> {
        Box::new(self.denial(stage, code, reason))
    }

    fn denial(&mut self, stage: Stage, code: DenyCode, reason: impl Into<String>) -> Denial {
        Denial {
            code,
            stage,
            reason: reason.into(),
            authenticated: self.authenticated,
            actor: if self.authenticated { self.actor.clone() } else { None },
            message_id: self.message_id,
            target: self.target.clone(),
            capability: self.capability.clone(),
            token_id: self.token_id.clone(),
            policy_reasons: std::mem::take(&mut self.policy_reasons),
        }
    }
}

impl Monitor {
    pub fn new(cfg: MonitorConfig) -> Self {
        Self { cfg, replay: ReplayCache::default(), rate: RateLimiter::default(), not_before_ms: 0 }
    }

    /// Refuse requests issued before `ms` — call with the start time of the
    /// process that owns this (in-memory) replay cache.
    pub fn reject_issued_before(&mut self, ms: u64) {
        self.not_before_ms = ms;
    }

    pub fn config(&self) -> &MonitorConfig {
        &self.cfg
    }

    /// Shared freshness and single-use rule for every signed message kind:
    /// not issued in the future, not expired, not issued before this monitor
    /// started, and never seen before (remembered until `expires + skew`).
    fn fresh(
        &mut self,
        key_id: KeyId,
        id: [u8; ID_LEN],
        issued_at_ms: u64,
        expires_at_ms: u64,
        now: u64,
    ) -> Result<(), (DenyCode, &'static str)> {
        if issued_at_ms > now.saturating_add(self.cfg.clock_skew_ms) {
            return Err((DenyCode::NotYetValid, "issued in the future"));
        }
        if expires_at_ms <= issued_at_ms || now >= expires_at_ms {
            return Err((DenyCode::Expired, "has expired"));
        }
        if issued_at_ms < self.not_before_ms {
            return Err((
                DenyCode::Replay,
                "issued before this node started; its replay cache cannot vouch for it — sign a new one",
            ));
        }
        let replay_key = (key_id, id);
        if self.replay.seen.contains_key(&replay_key) {
            return Err((DenyCode::Replay, "id already used"));
        }
        if self.replay.seen.len() >= self.cfg.replay_capacity {
            self.replay.prune(now);
            if self.replay.seen.len() >= self.cfg.replay_capacity {
                return Err((DenyCode::RateLimited, "replay cache is full"));
            }
        }
        self.replay.seen.insert(replay_key, expires_at_ms.saturating_add(self.cfg.clock_skew_ms));
        Ok(())
    }

    /// Authenticate an intent: envelope, signer, body, `actor == signer`, every
    /// relayed cause, security state, rate, freshness and single use. What it
    /// returns can only be decided by [`decide_intent`].
    pub fn admit_intent(&mut self, world: &World<'_>, bytes: &[u8]) -> Result<VerifiedIntent, Box<Denial>> {
        let mut t = Trace::new();
        let now = world.now_ms;
        let signed = SignedIntent::parse(bytes).map_err(|e| t.boxed(Stage::Envelope, e.code, e.reason))?;
        let Some(principal) = world.identities.by_key_id(signed.key_id()) else {
            return Err(t.boxed(Stage::Identity, DenyCode::UnknownKey, "key id is not enrolled in this domain"));
        };
        let keys = |k: &KeyId| world.identities.by_key_id(k).map(|p| (p.id.clone(), p.public_key));
        let verified = match signed.open(&principal.id, &principal.public_key, &keys) {
            Ok(v) => v,
            Err(OpenError::Signature(e)) => return Err(t.boxed(Stage::Identity, e.code, e.reason)),
            Err(e) => {
                t.authenticated = true;
                t.actor = Some(principal.id.clone());
                let code = match &e {
                    OpenError::Body(d) => d.code,
                    OpenError::SignerMismatch { .. } => DenyCode::ActorKeyMismatch,
                    OpenError::Cause(_) => DenyCode::Provenance,
                    OpenError::Signature(_) => unreachable!("handled above"),
                };
                return Err(t.boxed(Stage::Identity, code, e.to_string()));
            }
        };
        let intent = verified.intent();
        t.authenticated = true;
        t.actor = Some(principal.id.clone());
        t.message_id = Some(intent.id);
        t.target = Some(intent.resource.as_entity().clone());
        t.capability = Some(intent.action.clone());
        if !principal.state.may_act() {
            let why = format!("{} is {}", principal.id, principal.state);
            return Err(t.boxed(Stage::Identity, DenyCode::PrincipalState, why));
        }
        if !self.rate.allow(&principal.id, now, self.cfg.rate_limit, self.cfg.rate_window_ms) {
            let why = format!("more than {} requests in {} ms", self.cfg.rate_limit, self.cfg.rate_window_ms);
            return Err(t.boxed(Stage::Identity, DenyCode::RateLimited, why));
        }
        let c = &intent.constraints;
        if let Err((code, why)) = self.fresh(principal.key_id, intent.id, intent.requested_at_ms, c.deadline_ms, now) {
            return Err(t.boxed(Stage::Freshness, code, format!("intent {why}")));
        }
        Ok(verified)
    }

    /// Authenticate a human's answer to an escalated intent.
    pub fn admit_approval(&mut self, world: &World<'_>, bytes: &[u8]) -> Result<VerifiedApproval, Box<Denial>> {
        let mut t = Trace::new();
        let now = world.now_ms;
        let signed = SignedApproval::parse(bytes).map_err(|e| t.boxed(Stage::Envelope, e.code, e.reason))?;
        let Some(principal) = world.identities.by_key_id(signed.key_id()) else {
            return Err(t.boxed(Stage::Identity, DenyCode::UnknownKey, "key id is not enrolled in this domain"));
        };
        let approval = match signed.open(&principal.id, &principal.public_key) {
            Ok(a) => a,
            Err(OpenError::Signature(e)) => return Err(t.boxed(Stage::Identity, e.code, e.reason)),
            Err(e) => {
                t.authenticated = true;
                t.actor = Some(principal.id.clone());
                let code = match &e {
                    OpenError::Body(d) => d.code,
                    _ => DenyCode::ActorKeyMismatch,
                };
                return Err(t.boxed(Stage::Identity, code, e.to_string()));
            }
        };
        let a = approval.approval();
        t.authenticated = true;
        t.actor = Some(principal.id.clone());
        t.message_id = Some(a.intent);
        if !principal.state.may_act() {
            let why = format!("{} is {}", principal.id, principal.state);
            return Err(t.boxed(Stage::Identity, DenyCode::PrincipalState, why));
        }
        if !self.rate.allow(&principal.id, now, self.cfg.rate_limit, self.cfg.rate_window_ms) {
            let why = format!("more than {} requests in {} ms", self.cfg.rate_limit, self.cfg.rate_window_ms);
            return Err(t.boxed(Stage::Identity, DenyCode::RateLimited, why));
        }
        if let Err((code, why)) = self.fresh(principal.key_id, a.intent, a.issued_at_ms, a.expires_at_ms, now) {
            return Err(t.boxed(Stage::Freshness, code, format!("approval {why}")));
        }
        Ok(approval)
    }

    pub fn check(&mut self, world: &World<'_>, bytes: &[u8]) -> Decision {
        let mut t = Trace::new();
        let now = world.now_ms;

        // ── 1. envelope ──
        let env = match SignedEnvelope::parse(bytes) {
            Ok(e) => e,
            Err(e) => return t.deny(Stage::Envelope, e.code, e.reason),
        };

        // ── 2. identity ──
        let Some(principal) = world.identities.by_key_id(env.key_id()) else {
            return t.deny(Stage::Identity, DenyCode::UnknownKey, "key id is not enrolled in this domain");
        };
        if let Err(e) = env.verify(&principal.public_key) {
            return t.deny(Stage::Identity, e.code, e.reason);
        }
        t.authenticated = true;
        t.actor = Some(principal.id.clone());
        let msg = match Csme::from_cbor(env.payload()) {
            Ok(m) => m,
            Err(e) => return t.deny(Stage::Identity, e.code, e.reason),
        };
        t.message_id = Some(msg.message_id);
        t.target = Some(msg.destination.clone());
        t.capability = Some(msg.capability.clone());
        if msg.actor != principal.id {
            return t.deny(
                Stage::Identity,
                DenyCode::ActorKeyMismatch,
                format!("envelope claims actor {} but is signed by {}", msg.actor, principal.id),
            );
        }
        if !principal.state.may_act() {
            return t.deny(
                Stage::Identity,
                DenyCode::PrincipalState,
                format!("{} is {}", principal.id, principal.state),
            );
        }
        if !self.rate.allow(&principal.id, now, self.cfg.rate_limit, self.cfg.rate_window_ms) {
            return t.deny(
                Stage::Identity,
                DenyCode::RateLimited,
                format!("more than {} requests in {} ms", self.cfg.rate_limit, self.cfg.rate_window_ms),
            );
        }

        // Invariant 1: an AI produces intents, never commands
        if principal.id.kind() == EntityKind::Ai && msg.message_type == MessageType::Command {
            return t.deny(
                Stage::Identity,
                DenyCode::IntentRequired,
                "AI principals submit intents, not commands (application/chitala-intent)",
            );
        }

        // ── 3. freshness ──
        if !matches!(msg.message_type, MessageType::Command | MessageType::Query) {
            return t.deny(
                Stage::Freshness,
                DenyCode::UnsupportedType,
                format!("message type {} is not accepted by the v0.1 monitor", msg.message_type),
            );
        }
        if msg.issued_at_ms > now.saturating_add(self.cfg.clock_skew_ms) {
            return t.deny(Stage::Freshness, DenyCode::NotYetValid, "issued in the future");
        }
        if msg.expires_at_ms <= msg.issued_at_ms || now >= msg.expires_at_ms {
            return t.deny(Stage::Freshness, DenyCode::Expired, "request has expired");
        }
        if msg.expires_at_ms - msg.issued_at_ms > self.cfg.max_lifetime_ms {
            return t.deny(
                Stage::Freshness,
                DenyCode::LifetimeTooLong,
                format!("lifetime exceeds {} ms", self.cfg.max_lifetime_ms),
            );
        }
        // consumed even if a later stage denies: a signed request is single-use
        if let Err((code, why)) = self.fresh(principal.key_id, msg.message_id, msg.issued_at_ms, msg.expires_at_ms, now)
        {
            return t.deny(Stage::Freshness, code, format!("request {why}"));
        }

        // ── 4. capability ──
        let Some(target) = world.targets.target(&msg.destination) else {
            return t.deny(Stage::Capability, DenyCode::UnknownTarget, format!("unknown target {}", msg.destination));
        };
        let Some(def) = world.registry.get(&msg.capability) else {
            return t.deny(
                Stage::Capability,
                DenyCode::UnknownCapability,
                format!("{} is not in registry {}", msg.capability, world.registry.version()),
            );
        };
        if def.version != msg.capability_version {
            return t.deny(
                Stage::Capability,
                DenyCode::CapabilityVersion,
                format!("{} v{} requested, registry has v{}", def.id, msg.capability_version, def.version),
            );
        }
        if def.target != target.kind || !target.capabilities.contains(&def.id) {
            return t.deny(
                Stage::Capability,
                DenyCode::UnsupportedByTarget,
                format!("{} does not support {}", target.id, def.id),
            );
        }
        let kind_ok = matches!(
            (def.kind, msg.message_type),
            (CapabilityKind::Action, MessageType::Command) | (CapabilityKind::Query, MessageType::Query)
        );
        if !kind_ok {
            return t.deny(
                Stage::Capability,
                DenyCode::KindMismatch,
                format!("{} is a {:?} and cannot be sent as {}", def.id, def.kind, msg.message_type),
            );
        }
        if def.risk != msg.risk {
            return t.deny(
                Stage::Capability,
                DenyCode::RiskMismatch,
                format!("declared risk {} but {} is {}", msg.risk, def.id, def.risk),
            );
        }
        match principal.state.max_risk() {
            Some(max) if def.risk <= max => {}
            _ => {
                return t.deny(
                    Stage::Capability,
                    DenyCode::PrincipalState,
                    format!("{} is {} and may not perform {} actions", principal.id, principal.state, def.risk),
                )
            }
        }
        if let Err(e) = def.validate(&msg.payload) {
            return match e {
                PayloadError::Invalid(r) => t.deny(Stage::Capability, DenyCode::PayloadInvalid, r),
                PayloadError::OutOfRange(r) => t.deny(Stage::Capability, DenyCode::SafetyEnvelope, r),
            };
        }

        // ── 5. authority ──
        let mut token_use = None;
        match &msg.authority {
            Some(bytes) => {
                let token = match world.tokens.verify(bytes) {
                    Ok(tok) => tok,
                    Err(e) => return t.deny(Stage::Authority, DenyCode::TokenInvalid, e.to_string()),
                };
                t.token_id = Some(token.revocation_id.clone());
                if let Some(why) = world.revocations.revoked_because(&token) {
                    return t.deny(Stage::Authority, DenyCode::TokenRevoked, format!("{}: {why}", TokenError::Revoked));
                }
                // whom the request is made for: a person acts for themselves; an
                // agent for a person it serves whom its token names
                let represented = if principal.id.kind() == EntityKind::Person {
                    Some(principal.id.clone())
                } else {
                    token.for_persons.iter().find(|p| principal.acts_for(p)).cloned()
                };
                let presented = Presentation {
                    actor: &principal.id,
                    key_id: env.key_id(),
                    on_behalf_of: represented.as_ref(),
                    target: &msg.destination,
                    capability: &msg.capability,
                    now_ms: now,
                };
                if let Err(e) = token.authorize(&presented) {
                    return t.deny(Stage::Authority, DenyCode::TokenDenied, e.to_string());
                }
                token_use = Some(TokenUse {
                    revocation_id: token.revocation_id.clone(),
                    issuer: token.issuer.clone(),
                    depth: token.depth,
                    expires_at_ms: token.expires_at_ms,
                    reference: token.reference(),
                });
            }
            None if principal.id.kind() != EntityKind::Person => {
                return t.deny(
                    Stage::Authority,
                    DenyCode::TokenMissing,
                    format!(
                        "{} principals have no ambient authority; a capability token is required",
                        principal.id.kind()
                    ),
                );
            }
            None => {}
        }
        let decision = match evaluate_policy(world, principal, &target, def, token_use.is_some()) {
            Ok(d) => d,
            Err(e) => return t.deny(Stage::Authority, DenyCode::PolicyError, e.to_string()),
        };
        if !decision.allowed {
            t.policy_reasons = decision.reasons;
            let why = if t.policy_reasons.is_empty() {
                "no policy permits this request".to_string()
            } else {
                format!("forbidden by {}", t.policy_reasons.join(", "))
            };
            return t.deny(Stage::Authority, DenyCode::PolicyDenied, why);
        }

        Decision::Allow(Box::new(Authorized {
            request_digest: chitala_csme::order::message_digest(bytes),
            principal_kind: principal.id.kind(),
            def: def.clone(),
            token: token_use,
            policy_reasons: decision.reasons,
            decided_at_ms: now,
            envelope: msg,
        }))
    }
}

/// Evaluate the domain policy for `principal` performing `def` on `target`.
/// Used by [`Monitor::check`] and by the node to decide whether a principal holds
/// a right *ambiently* (without a token) before it may delegate it.
pub fn evaluate_policy(
    world: &World<'_>,
    principal: &Principal,
    target: &TargetInfo,
    def: &CapabilityDef,
    token_granted: bool,
) -> Result<PolicyDecision, PolicyError> {
    let principal_device = if principal.id.kind() == EntityKind::Device {
        world.targets.target(&principal.id).and_then(|t| t.device)
    } else {
        None
    };
    let resource = match (&target.kind, &target.device) {
        (TargetKind::Device, Some(attrs)) => ResourceInfo::Device { id: &target.id, attrs },
        (TargetKind::Device, None) => {
            return Err(PolicyError::Evaluation(format!("device {} has no attributes", target.id)))
        }
        (TargetKind::Domain, _) => ResourceInfo::Domain { id: &target.id },
    };
    world.policy.evaluate(&PolicyRequest {
        principal: PrincipalInfo {
            id: &principal.id,
            roles: &principal.roles,
            state: principal.state,
            device: principal_device.as_ref(),
        },
        capability: &def.id,
        resource,
        context: PolicyContext { token_granted, human_approved: false, risk: def.risk },
    })
}

/// Hand an admitted intent (and the people's answers so far) to the Authority
/// Engine. The result is the only source of an Authority grant.
pub fn decide_intent(world: &World<'_>, intent: &VerifiedIntent, approvals: &[&VerifiedApproval]) -> AuthorityDecision {
    let devices = |id: &EntityId| world.targets.target(id).and_then(|t| t.device);
    let aw = AuthorityWorld {
        identities: world.identities,
        registry: world.registry,
        resources: world.resources,
        policy: world.policy,
        tokens: world.tokens,
        revocations: world.revocations,
        devices: &devices,
        now_ms: world.now_ms,
    };
    authority::decide(&aw, intent, approvals)
}

/// [`decide_intent`] for one use of an execution lease (spec 21): the whole
/// chain again, with the lease's approval in place of new answers.
pub fn decide_lease_use(
    world: &World<'_>,
    intent: &VerifiedIntent,
    lease: authority::LeaseBacking<'_>,
) -> AuthorityDecision {
    let devices = |id: &EntityId| world.targets.target(id).and_then(|t| t.device);
    let aw = AuthorityWorld {
        identities: world.identities,
        registry: world.registry,
        resources: world.resources,
        policy: world.policy,
        tokens: world.tokens,
        revocations: world.revocations,
        devices: &devices,
        now_ms: world.now_ms,
    };
    authority::decide_lease_use(&aw, intent, lease)
}

/// Security state a device target has when it is also an enrolled principal.
pub fn device_state(identities: &IdentityRegistry, id: &EntityId) -> SecurityState {
    identities.get(id).map(|p| p.state).unwrap_or(SecurityState::Trusted)
}

#[cfg(test)]
mod tests;
