//! Authority Engine (spec `specs/16-authority-engine.md`).
//!
//! > AI produces Intent. **Chitala produces Authority.** Only the trusted
//! > execution boundary produces physical Commands.
//!
//! For one authenticated intent — and every intent it relays — the engine walks
//! a fixed chain of questions and records the answer to each:
//!
//! ```text
//! WHO → ON_BEHALF_OF → WHAT → OBJECT → CONTEXT → DELEGATION → RISK → APPROVAL → ALLOW | DENY | ESCALATE
//! ```
//!
//! | step | question |
//! |------|----------|
//! | WHO | Is every actor of the chain enrolled and allowed to act (security state)? |
//! | ON_BEHALF_OF | Is the represented principal an enrolled person, and does the actor act for them (agency declared at enrollment)? |
//! | WHAT | Is the action a registered device capability with valid parameters? |
//! | OBJECT | Does the resource exist and bind the action to a known device? |
//! | CONTEXT | Is the intent still current; is every relay faithful (same request, same represented person)? |
//! | DELEGATION | Is the represented person entitled; does each non-human actor hold a token covering the request; does policy permit the actor at all? |
//! | RISK | Effective risk = max(registry risk, binding floor); within every actor's state ceiling and every requester's own limit? |
//! | APPROVAL | Does policy, the constitution or a two-key resource require people to agree? If so, have enough different owners of the resource answered (quorum)? |
//!
//! The first failing step decides `DENY`. A missing human answer where one is
//! required decides `ESCALATE` (with the eligible approvers). Otherwise the
//! result is an [`Grant`], which has no public constructor: the only way to
//! obtain one is through [`decide`] or [`decide_lease_use`].
//!
//! Execution leases (spec 21) go through the same chain. An intent that asks
//! for a lease is judged as the action it would cover, plus the lease rules at
//! WHAT (the envelope) and RISK (two-key, critical, the high-risk limits); its
//! grant [`asks_lease`](Grant::asks_lease) and executes nothing. Each use of a
//! lease is judged again in full by [`decide_lease_use`], where only APPROVAL
//! differs: the lease's own approval counts while an approver can still give
//! it, and a use never escalates.
//!
//! The engine also authorizes the one action Chitala runs without anyone
//! asking: a resource's declared safe state after a failed outcome (spec 22),
//! as a [`RecoveryGrant`] from [`authorize_recovery`].
//!
//! Every input is unforgeable: intents and approvals arrive as
//! [`VerifiedIntent`] / [`VerifiedApproval`], which only a signature check can
//! produce, and the engine verifies each actor's capability token itself
//! (signature, revocation, holder binding, coverage of the resource or one of
//! its ancestors). The engine touches no clock or I/O.

use std::collections::BTreeSet;

use chitala_identity::{IdentityRegistry, Principal};
use chitala_intent::{
    Digest, Intent, IntentId, LeaseClause, LeaseTerms, Verdict as Answer, VerifiedApproval, VerifiedIntent,
};
use chitala_model::{
    CapabilityDef, CapabilityKind, CapabilityRegistry, DenyCode, EntityId, EntityKind, ParamType, ParamValue, Payload,
    PayloadError, RiskClass, TargetKind,
};
use chitala_resource::{Resource, ResourceGraph, ResourceId};
use chitala_token::{Presentation, RevocationList, TokenRef, TokenVerifier};

use crate::{
    DeviceAttrs, PolicyContext, PolicyDecision, PolicyEngine, PolicyError, PolicyRequest, PrincipalInfo, ResourceAttrs,
    ResourceInfo,
};

/// Tolerated clock skew for an approval's `issued_at`.
pub const APPROVAL_CLOCK_SKEW_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    Who,
    OnBehalfOf,
    What,
    Object,
    Context,
    Delegation,
    Risk,
    Approval,
}

impl Step {
    pub const ORDER: [Step; 8] = [
        Step::Who,
        Step::OnBehalfOf,
        Step::What,
        Step::Object,
        Step::Context,
        Step::Delegation,
        Step::Risk,
        Step::Approval,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Step::Who => "who",
            Step::OnBehalfOf => "on_behalf_of",
            Step::What => "what",
            Step::Object => "object",
            Step::Context => "context",
            Step::Delegation => "delegation",
            Step::Risk => "risk",
            Step::Approval => "approval",
        }
    }
}

/// One answered question, for the audit log and for humans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    pub step: Step,
    pub passed: bool,
    pub detail: String,
}

/// What the engine established about the capability token of one link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationEvidence {
    /// No token presented.
    None,
    /// The token did not verify against the domain key.
    Invalid(String),
    Revoked(String),
    /// The token verified but does not authorize this holder, resource and action now.
    Denied(String),
    /// The token authorizes the request.
    Granted {
        token_id: String,
        issuer: EntityId,
        depth: u8,
        reference: TokenRef,
    },
}

/// Read-only view of the domain for one decision.
pub struct AuthorityWorld<'a> {
    pub identities: &'a IdentityRegistry,
    pub registry: &'a CapabilityRegistry,
    pub resources: &'a ResourceGraph,
    pub policy: &'a PolicyEngine,
    pub tokens: &'a TokenVerifier,
    pub revocations: &'a RevocationList,
    /// Attributes of an enrolled device; `None` for unknown devices.
    pub devices: &'a dyn Fn(&EntityId) -> Option<DeviceAttrs>,
    pub now_ms: u64,
}

/// Check the token an actor attached to its intent: valid, not revoked, bound
/// to the actor, and granting the action on the resource or on an ancestor
/// (a right on a room covers what is in it).
pub fn delegation_evidence(world: &AuthorityWorld<'_>, intent: &Intent) -> DelegationEvidence {
    let Some(bytes) = &intent.authority else { return DelegationEvidence::None };
    let token = match world.tokens.verify(bytes) {
        Ok(t) => t,
        Err(e) => return DelegationEvidence::Invalid(e.to_string()),
    };
    if let Some(why) = world.revocations.revoked_because(&token) {
        return DelegationEvidence::Revoked(format!("token {}: {why}", short(&token.revocation_id)));
    }
    // proof of possession: the intent was verified with the actor's enrolled key
    let Some(key_id) = world.identities.get(&intent.actor).map(|p| p.key_id) else {
        return DelegationEvidence::Denied(format!("{} is not enrolled", intent.actor));
    };
    // a right to move a robot includes the right to stop it (spec 30)
    let mut capabilities = vec![&intent.action];
    if world.registry.get(&intent.action).is_some_and(|d| d.halts) {
        let motions = world.registry.iter().filter(|d| d.outcome.as_ref().is_some_and(|o| o.pose.is_some()));
        capabilities.extend(motions.map(|d| &d.id));
    }
    let mut last = String::from("the resource is not governed here");
    let lineage = world.resources.lineage(&intent.resource);
    for (r, capability) in lineage.iter().flat_map(|r| capabilities.iter().map(move |c| (r, *c))) {
        let presented = Presentation {
            actor: &intent.actor,
            key_id: &key_id,
            on_behalf_of: Some(&intent.on_behalf_of),
            target: r.id.as_entity(),
            capability,
            now_ms: world.now_ms,
        };
        match token.authorize(&presented) {
            Ok(()) => {
                return DelegationEvidence::Granted {
                    token_id: token.revocation_id.clone(),
                    issuer: token.issuer.clone(),
                    depth: token.depth,
                    reference: token.reference(),
                }
            }
            Err(e) => last = e.to_string(),
        }
    }
    DelegationEvidence::Denied(last)
}

fn short(id: &str) -> &str {
    &id[..id.len().min(16)]
}

/// Authority for exactly one intent. Neither `Clone` nor constructible outside
/// this module: it is the proof the trusted boundary demands before it mints a
/// physical command.
/// Spec 21: at high risk a lease covers at most this many uses, for at most this long.
pub const LEASE_HIGH_RISK_MAX_USES: u32 = 3;
pub const LEASE_HIGH_RISK_MAX_DURATION_MS: u64 = 60 * 60 * 1000;

/// What one use of an execution lease stands on, besides the use itself (spec
/// 21): the owners who approved the lease's terms. The node checks the rest of
/// the lease (window, uses, match, envelope) before asking.
#[derive(Debug, Clone, Copy)]
pub struct LeaseBacking<'a> {
    pub approved_by: &'a [EntityId],
}

#[derive(Debug)]
pub struct Grant {
    intent: IntentId,
    digest: Digest,
    actor: EntityId,
    on_behalf_of: EntityId,
    relayed_from: Vec<EntityId>,
    resource: ResourceId,
    def: CapabilityDef,
    params: Payload,
    device: EntityId,
    risk: RiskClass,
    approved_by: Vec<EntityId>,
    tokens: Vec<String>,
    token_refs: Vec<TokenRef>,
    policy_reasons: Vec<String>,
    decided_at_ms: u64,
    /// Set when the intent asked for a lease: the grant is for these terms and
    /// executes nothing itself.
    lease_terms: Option<LeaseTerms>,
}

impl Grant {
    /// The lease terms this grant is for, if the intent asked for a lease (spec
    /// 21). Such a grant never becomes an order.
    pub fn asks_lease(&self) -> Option<&LeaseTerms> {
        self.lease_terms.as_ref()
    }
    pub fn intent(&self) -> &IntentId {
        &self.intent
    }
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
    pub fn actor(&self) -> &EntityId {
        &self.actor
    }
    pub fn on_behalf_of(&self) -> &EntityId {
        &self.on_behalf_of
    }
    /// Actors of the relayed intents, nearest first (empty for a direct intent).
    pub fn relayed_from(&self) -> &[EntityId] {
        &self.relayed_from
    }
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }
    pub fn def(&self) -> &CapabilityDef {
        &self.def
    }
    pub fn params(&self) -> &Payload {
        &self.params
    }
    /// The device the resource binds this capability to.
    pub fn device(&self) -> &EntityId {
        &self.device
    }
    pub fn risk(&self) -> RiskClass {
        self.risk
    }
    /// The people who approved (empty when no approval was needed).
    pub fn approved_by(&self) -> &[EntityId] {
        &self.approved_by
    }
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }
    /// The tokens of every link, for re-checking revocation while the action
    /// executes (spec 19).
    pub fn token_refs(&self) -> &[TokenRef] {
        &self.token_refs
    }
    pub fn policy_reasons(&self) -> &[String] {
        &self.policy_reasons
    }
    pub fn decided_at_ms(&self) -> u64 {
        self.decided_at_ms
    }
}

/// A human must answer before the intent can proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escalation {
    pub intent: IntentId,
    pub digest: Digest,
    pub resource: ResourceId,
    pub risk: RiskClass,
    /// Owners of the resource who may (still) answer.
    pub approvers: Vec<EntityId>,
    /// How many different people must approve in all (2 on a two-key resource).
    pub quorum: u8,
    /// Who has approved so far.
    pub approved_by: Vec<EntityId>,
    /// Why a human is required (policy ids and constitutional rules).
    pub reasons: Vec<String>,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDenial {
    pub step: Step,
    pub code: DenyCode,
    pub reason: String,
    pub policy_reasons: Vec<String>,
}

#[derive(Debug)]
pub enum Verdict {
    Allow(Box<Grant>),
    Deny(AuthorityDenial),
    Escalate(Escalation),
}

#[derive(Debug)]
pub struct AuthorityDecision {
    pub verdict: Verdict,
    pub trace: Vec<StepRecord>,
    /// Effective risk, once known.
    pub risk: Option<RiskClass>,
}

impl AuthorityDecision {
    pub fn label(&self) -> &'static str {
        match self.verdict {
            Verdict::Allow(_) => "allow",
            Verdict::Deny(_) => "deny",
            Verdict::Escalate(_) => "escalate",
        }
    }

    pub fn denial(&self) -> Option<&AuthorityDenial> {
        match &self.verdict {
            Verdict::Deny(d) => Some(d),
            _ => None,
        }
    }
}

struct Req<'a> {
    links: Vec<Link<'a>>,
    digest: Digest,
    approvals: Vec<&'a chitala_intent::Approval>,
}

#[derive(Default)]
struct Run {
    trace: Vec<StepRecord>,
    risk: Option<RiskClass>,
}

impl Run {
    fn pass(&mut self, step: Step, detail: impl Into<String>) {
        self.trace.push(StepRecord { step, passed: true, detail: detail.into() });
    }

    fn deny(
        mut self,
        step: Step,
        code: DenyCode,
        reason: impl Into<String>,
        reasons: Vec<String>,
    ) -> AuthorityDecision {
        let reason = reason.into();
        self.trace.push(StepRecord { step, passed: false, detail: reason.clone() });
        AuthorityDecision {
            verdict: Verdict::Deny(AuthorityDenial { step, code, reason, policy_reasons: reasons }),
            trace: self.trace,
            risk: self.risk,
        }
    }

    fn finish(self, verdict: Verdict) -> AuthorityDecision {
        AuthorityDecision { verdict, trace: self.trace, risk: self.risk }
    }
}

/// Cedar attributes of `r` when `device` executes the requested capability.
pub fn resource_attrs(g: &ResourceGraph, r: &Resource, device: &DeviceAttrs) -> ResourceAttrs {
    let loc = g.location(&r.id);
    ResourceAttrs {
        kind: r.kind.to_string(),
        boundary: r.boundary.as_str().to_string(),
        zone: loc.and_then(|l| l.zone),
        security_class: device.security_class,
        owners: g.effective_owners(&r.id).to_vec(),
        ancestors: g.ancestors(&r.id).iter().map(|a| a.id.as_entity().clone()).collect(),
    }
}

struct Target<'a> {
    world: &'a AuthorityWorld<'a>,
    def: &'a CapabilityDef,
    id: &'a ResourceId,
    attrs: ResourceAttrs,
    risk: RiskClass,
}

impl Target<'_> {
    fn cedar(&self, who: &Principal, token: bool, approved: bool) -> Result<PolicyDecision, PolicyError> {
        let device = if who.id.kind() == EntityKind::Device { (self.world.devices)(&who.id) } else { None };
        self.world.policy.evaluate(&PolicyRequest {
            principal: PrincipalInfo { id: &who.id, roles: &who.roles, state: who.state, device: device.as_ref() },
            capability: &self.def.id,
            resource: ResourceInfo::Resource { id: self.id.as_entity(), attrs: &self.attrs },
            context: PolicyContext { token_granted: token, human_approved: approved, risk: self.risk },
        })
    }
}

fn names<'a>(ids: impl IntoIterator<Item = &'a EntityId>) -> String {
    ids.into_iter().map(ToString::to_string).collect::<Vec<_>>().join(" ← ")
}

struct Link<'a> {
    intent: &'a Intent,
    delegation: DelegationEvidence,
}

/// Decide one intent (with its relay chain) and the people's answers to it so
/// far. See the module documentation for the steps.
pub fn decide(
    world: &AuthorityWorld<'_>,
    verified: &VerifiedIntent,
    approvals: &[&VerifiedApproval],
) -> AuthorityDecision {
    decide_inner(world, verified, approvals, None)
}

/// Decide one use of an execution lease (spec 21): the whole chain again, with
/// the lease's approval in place of new answers. A use never escalates.
pub fn decide_lease_use(
    world: &AuthorityWorld<'_>,
    verified: &VerifiedIntent,
    lease: LeaseBacking<'_>,
) -> AuthorityDecision {
    decide_inner(world, verified, &[], Some(lease))
}

fn decide_inner(
    world: &AuthorityWorld<'_>,
    verified: &VerifiedIntent,
    approvals: &[&VerifiedApproval],
    lease: Option<LeaseBacking<'_>>,
) -> AuthorityDecision {
    let mut run = Run::default();
    let links: Vec<Link<'_>> = verified
        .chain()
        .into_iter()
        .map(|intent| Link { intent, delegation: delegation_evidence(world, intent) })
        .collect();
    let req = Req { links, digest: *verified.digest(), approvals: approvals.iter().map(|a| a.approval()).collect() };
    let outer = req.links[0].intent;
    let now = world.now_ms;

    // ── WHO ──
    let mut actors: Vec<&Principal> = Vec::with_capacity(req.links.len());
    for link in &req.links {
        let Some(p) = world.identities.get(&link.intent.actor) else {
            return run.deny(Step::Who, DenyCode::UnknownKey, format!("{} is not enrolled", link.intent.actor), vec![]);
        };
        if !p.state.may_act() {
            return run.deny(Step::Who, DenyCode::PrincipalState, format!("{} is {}", p.id, p.state), vec![]);
        }
        actors.push(p);
    }
    run.pass(Step::Who, names(actors.iter().map(|p| &p.id)));

    // ── ON_BEHALF_OF ──
    let mut persons: Vec<&Principal> = Vec::with_capacity(req.links.len());
    for (link, actor) in req.links.iter().zip(&actors) {
        let obo = &link.intent.on_behalf_of;
        let Some(person) = world.identities.get(obo).filter(|p| p.id.kind() == EntityKind::Person) else {
            return run.deny(
                Step::OnBehalfOf,
                DenyCode::OnBehalfOf,
                format!("{obo} is not an enrolled person"),
                vec![],
            );
        };
        if !person.state.may_act() {
            return run.deny(Step::OnBehalfOf, DenyCode::OnBehalfOf, format!("{obo} is {}", person.state), vec![]);
        }
        if !actor.acts_for(obo) {
            return run.deny(
                Step::OnBehalfOf,
                DenyCode::OnBehalfOf,
                format!("{} does not act for {obo} (agency is declared at enrollment, not claimed)", actor.id),
                vec![],
            );
        }
        persons.push(person);
    }
    run.pass(Step::OnBehalfOf, format!("{} acts for {}", outer.actor, outer.on_behalf_of));

    // ── WHAT ──
    let Some(def) = world.registry.get(&outer.action) else {
        return run.deny(
            Step::What,
            DenyCode::UnknownCapability,
            format!("{} is not in registry {}", outer.action, world.registry.version()),
            vec![],
        );
    };
    if def.target != TargetKind::Device {
        return run.deny(
            Step::What,
            DenyCode::UnsupportedByTarget,
            format!("{} administers the domain; domain administration is not requested through intents", def.id),
            vec![],
        );
    }
    let asks = match &outer.lease {
        Some(LeaseClause::Request(terms)) => Some(terms),
        _ => None,
    };
    // a lease request fixes every parameter outside its envelope; each envelope
    // range must be an integer parameter inside the registry's limits, and the
    // parameters must be valid at both ends of every range
    let mut variants = vec![outer.params.clone()];
    if asks.is_some() && def.kind != CapabilityKind::Action {
        return run.deny(
            Step::What,
            DenyCode::LeaseDenied,
            format!("{} is not an action: only actions are leased", def.id),
            vec![],
        );
    }
    if let Some(terms) = asks {
        let (mut low, mut high) = (outer.params.clone(), outer.params.clone());
        for (name, (min, max)) in &terms.envelope {
            let Some(pd) = def.params.iter().find(|p| &p.name == name) else {
                return run.deny(
                    Step::What,
                    DenyCode::LeaseDenied,
                    format!("{} has no parameter {name}", def.id),
                    vec![],
                );
            };
            if outer.params.contains_key(name) {
                return run.deny(
                    Step::What,
                    DenyCode::LeaseDenied,
                    format!("{name} is either fixed or in the envelope, not both"),
                    vec![],
                );
            }
            let ParamType::Integer { min: lo, max: hi } = pd.ty else {
                return run.deny(
                    Step::What,
                    DenyCode::LeaseDenied,
                    format!("{name} is not an integer parameter"),
                    vec![],
                );
            };
            if *min < lo || *max > hi {
                return run.deny(
                    Step::What,
                    DenyCode::LeaseDenied,
                    format!("envelope {name} [{min}, {max}] is not inside the registry's [{lo}, {hi}]"),
                    vec![],
                );
            }
            low.insert(name.clone(), ParamValue::Int(*min));
            high.insert(name.clone(), ParamValue::Int(*max));
        }
        variants = vec![low, high];
    }
    for params in &variants {
        if let Err(e) = def.validate(params) {
            return match e {
                PayloadError::Invalid(r) => run.deny(Step::What, DenyCode::PayloadInvalid, r, vec![]),
                PayloadError::OutOfRange(r) => run.deny(Step::What, DenyCode::SafetyEnvelope, r, vec![]),
            };
        }
    }
    run.pass(Step::What, format!("{} v{} ({:?}, registry risk {})", def.id, def.version, def.kind, def.risk));

    // ── OBJECT ──
    let Some(resource) = world.resources.get(&outer.resource) else {
        return run.deny(
            Step::Object,
            DenyCode::UnknownResource,
            format!("unknown resource {}", outer.resource),
            vec![],
        );
    };
    let Some(binding) = resource.binding(&def.id) else {
        return run.deny(
            Step::Object,
            DenyCode::UnsupportedByTarget,
            format!("{} ({}) has no binding for {}", resource.id, resource.kind, def.id),
            vec![],
        );
    };
    let Some(device) = (world.devices)(&binding.device) else {
        return run.deny(
            Step::Object,
            DenyCode::UnknownTarget,
            format!("{} is bound to unknown device {}", resource.id, binding.device),
            vec![],
        );
    };
    run.pass(
        Step::Object,
        format!("{} ({}, {}) → {}", resource.id, resource.kind, resource.boundary.as_str(), binding.device),
    );

    // ── CONTEXT ──
    if now >= outer.constraints.deadline_ms {
        return run.deny(Step::Context, DenyCode::Expired, "the intent's deadline has passed", vec![]);
    }
    match (&outer.lease, &lease) {
        (Some(LeaseClause::Use(_)), None) => {
            return run.deny(Step::Context, DenyCode::LeaseUnknown, "a lease use is judged against its lease", vec![])
        }
        (Some(LeaseClause::Use(_)), Some(_)) | (_, None) => {}
        (_, Some(_)) => return run.deny(Step::Context, DenyCode::Internal, "not a lease use", vec![]),
    }
    let mut seen = BTreeSet::new();
    for (i, link) in req.links.iter().enumerate() {
        let me = link.intent;
        if !seen.insert(&me.actor) {
            return run.deny(Step::Context, DenyCode::Provenance, format!("relay loop through {}", me.actor), vec![]);
        }
        let Some(upper) = i.checked_sub(1).map(|j| req.links[j].intent) else { continue };
        if me.action != outer.action || me.resource != outer.resource || me.params != outer.params {
            return run.deny(
                Step::Context,
                DenyCode::Provenance,
                format!("{} changed the request it relays from {}", upper.actor, me.actor),
                vec![],
            );
        }
        if me.on_behalf_of != upper.on_behalf_of {
            return run.deny(
                Step::Context,
                DenyCode::Provenance,
                format!(
                    "{} asked on behalf of {}; {} cannot relay it on behalf of {}: authority is not laundered through another agent",
                    me.actor, me.on_behalf_of, upper.actor, upper.on_behalf_of
                ),
                vec![],
            );
        }
        if me.requested_at_ms > upper.requested_at_ms || now >= me.constraints.deadline_ms {
            return run.deny(
                Step::Context,
                DenyCode::Provenance,
                format!("the intent of {} is newer than its relay or has expired", me.actor),
                vec![],
            );
        }
    }
    let relayed: Vec<EntityId> = req.links.iter().skip(1).map(|l| l.intent.actor.clone()).collect();
    run.pass(
        Step::Context,
        match (&outer.context.purpose, relayed.is_empty()) {
            (Some(p), true) => format!("direct; purpose: {p}"),
            (None, true) => "direct".to_string(),
            (Some(p), false) => format!("relayed from {}; purpose: {p}", names(&relayed)),
            (None, false) => format!("relayed from {}", names(&relayed)),
        },
    );

    let risk = binding.risk_floor.map_or(def.risk, |f| f.max(def.risk));
    run.risk = Some(risk);
    let target =
        Target { world, def, id: &resource.id, attrs: resource_attrs(world.resources, resource, &device), risk };

    // ── DELEGATION ── authority of a link = represented person ∩ token ∩ policy for the actor
    let mut tokens = Vec::new();
    let mut token_refs = Vec::new();
    // what lets each actor act once a human has agreed (used when one did)
    let mut approved_reasons = Vec::new();
    for ((link, actor), person) in req.links.iter().zip(&actors).zip(&persons) {
        let via =
            if link.intent.actor == outer.actor { String::new() } else { format!(" (relayed from {})", actor.id) };
        match target.cedar(person, false, true) {
            Err(e) => return run.deny(Step::Delegation, DenyCode::PolicyError, e.to_string(), vec![]),
            Ok(d) if !d.allowed => {
                return run.deny(
                    Step::Delegation,
                    DenyCode::PolicyDenied,
                    format!("{} is not entitled to {} on {}{via}", person.id, def.id, resource.id),
                    d.reasons,
                )
            }
            Ok(_) => {}
        }
        let token = actor.id != person.id;
        if token {
            let fail = |code, why: &str| (code, format!("{}{via}: {why}", actor.id));
            let failure = match &link.delegation {
                DelegationEvidence::Granted { token_id, reference, .. } => {
                    tokens.push(token_id.clone());
                    token_refs.push(reference.clone());
                    None
                }
                DelegationEvidence::None => Some(fail(
                    DenyCode::TokenMissing,
                    "no capability token; non-human principals have no ambient authority",
                )),
                DelegationEvidence::Invalid(e) => Some(fail(DenyCode::TokenInvalid, e)),
                DelegationEvidence::Revoked(e) => Some(fail(DenyCode::TokenRevoked, e)),
                DelegationEvidence::Denied(e) => Some(fail(DenyCode::TokenDenied, e)),
            };
            if let Some((code, why)) = failure {
                return run.deny(Step::Delegation, code, why, vec![]);
            }
        }
        match target.cedar(actor, token, true) {
            Err(e) => return run.deny(Step::Delegation, DenyCode::PolicyError, e.to_string(), vec![]),
            Ok(d) if !d.allowed => {
                return run.deny(
                    Step::Delegation,
                    DenyCode::PolicyDenied,
                    format!("no policy lets {} perform {} on {}{via}", actor.id, def.id, resource.id),
                    d.reasons,
                )
            }
            Ok(d) => approved_reasons.extend(d.reasons),
        }
    }
    run.pass(
        Step::Delegation,
        if tokens.is_empty() {
            format!("{} is entitled and acts in person", outer.on_behalf_of)
        } else {
            format!("{} is entitled; delegated by token {}", outer.on_behalf_of, tokens.join(", "))
        },
    );

    // ── RISK ── no actor exceeds its own ceiling, nor that of the human it represents
    for ((link, actor), person) in req.links.iter().zip(&actors).zip(&persons) {
        for p in [actor, person] {
            if p.state.max_risk().is_none_or(|max| risk > max) {
                return run.deny(
                    Step::Risk,
                    DenyCode::PrincipalState,
                    format!("{} is {} and may not perform {risk} actions", p.id, p.state),
                    vec![],
                );
            }
        }
        if let Some(max) = link.intent.constraints.max_risk.filter(|m| risk > *m) {
            return run.deny(
                Step::Risk,
                DenyCode::Constraint,
                format!("effective risk {risk} exceeds the limit {max} set by {}", link.intent.actor),
                vec![],
            );
        }
    }
    run.pass(
        Step::Risk,
        match binding.risk_floor {
            Some(f) if f > def.risk => format!("{risk} (raised from {} at {})", def.risk, resource.id),
            _ => risk.to_string(),
        },
    );

    // execution leases (spec 21): never on a two-key resource or for a critical
    // action; at high risk only a few uses for a short time; the envelope stays
    // inside the resource's own limits (SAFE-5)
    if asks.is_some() || lease.is_some() {
        if world.resources.two_key(&resource.id) {
            return run.deny(
                Step::Risk,
                DenyCode::LeaseDenied,
                format!("{} is a two-key resource: its actions are not leased", resource.id),
                vec![],
            );
        }
        if risk == RiskClass::Critical {
            return run.deny(Step::Risk, DenyCode::LeaseDenied, "critical actions are decided one at a time", vec![]);
        }
    }
    if let Some(terms) = asks {
        if risk >= RiskClass::High
            && (terms.max_uses > LEASE_HIGH_RISK_MAX_USES || terms.duration_ms > LEASE_HIGH_RISK_MAX_DURATION_MS)
        {
            return run.deny(
                Step::Risk,
                DenyCode::LeaseDenied,
                format!(
                    "a {risk} lease allows at most {LEASE_HIGH_RISK_MAX_USES} uses within {} minutes",
                    LEASE_HIGH_RISK_MAX_DURATION_MS / 60_000
                ),
                vec![],
            );
        }
        for l in resource.limits(&def.id) {
            if let Some((min, max)) = terms.envelope.get(&l.param) {
                if *min < l.min || *max > l.max {
                    return run.deny(
                        Step::Risk,
                        DenyCode::LeaseDenied,
                        format!(
                            "envelope {} [{min}, {max}] is not inside {}'s [{}, {}]",
                            l.param, resource.id, l.min, l.max
                        ),
                        vec![],
                    );
                }
            }
        }
    }

    // ── APPROVAL ──
    let mut why_human: Vec<String> = Vec::new();
    let mut permit_reasons = Vec::new();
    for actor in &actors {
        // a person's own intent is a human decision when they own the resource
        let own = actor.id.kind() == EntityKind::Person && world.resources.is_owner(&resource.id, &actor.id);
        match target.cedar(actor, actor.id.kind() != EntityKind::Person, own) {
            Err(e) => return run.deny(Step::Approval, DenyCode::PolicyError, e.to_string(), vec![]),
            Ok(d) if d.allowed => permit_reasons.extend(d.reasons),
            Ok(d) => why_human.extend(d.reasons),
        }
        if actor.id.kind() != EntityKind::Person && risk >= RiskClass::High {
            why_human.push("constitution: an AI is never the final authority for a high-risk action".into());
        }
        if risk == RiskClass::Critical && !own {
            why_human.push("constitution: critical actions need an owner's decision".into());
        }
    }
    // two keys: on a two-key resource, a high-risk action needs two people; a
    // person acting in person on a resource they own is already one of them
    let two_key = risk >= RiskClass::High && world.resources.two_key(&resource.id);
    let in_person_owner = outer.actor.kind() == EntityKind::Person
        && req.links.len() == 1
        && world.resources.is_owner(&resource.id, &outer.actor);
    if two_key {
        why_human.push(format!("two-key resource: two people must agree to a {risk} action"));
    }
    let quorum: usize = if two_key && !in_person_owner { 2 } else { 1 };
    why_human.sort();
    why_human.dedup();
    permit_reasons.sort();
    permit_reasons.dedup();

    let approved_by = if why_human.is_empty() {
        run.pass(Step::Approval, "not required");
        Vec::new()
    } else {
        // owners whose own state still lets them take this decision — never the
        // requester, whose own intent is already their decision
        let approvers: Vec<EntityId> = world
            .resources
            .effective_owners(&resource.id)
            .iter()
            .filter(|o| world.identities.get(o).is_some_and(|p| p.state.max_risk().is_some_and(|m| m >= risk)))
            .filter(|o| !(in_person_owner && **o == outer.actor))
            .cloned()
            .collect();
        let mut agreed: Vec<EntityId> = Vec::new();
        for a in &req.approvals {
            let invalid = |why: String| (DenyCode::ApprovalInvalid, why);
            let problem = if a.intent != outer.id || a.intent_digest != req.digest {
                Some(invalid("the approval answers a different intent".into()))
            } else if !approvers.contains(&a.approver) {
                Some(invalid(format!("{} is not an owner of {} who can approve it", a.approver, resource.id)))
            } else if a.issued_at_ms.saturating_add(APPROVAL_CLOCK_SKEW_MS) < outer.requested_at_ms
                || a.issued_at_ms > now.saturating_add(APPROVAL_CLOCK_SKEW_MS)
                || now >= a.expires_at_ms
            {
                Some(invalid("the approval is not valid at this time".into()))
            } else if a.verdict == Answer::Reject {
                Some((DenyCode::ApprovalRejected, format!("{} rejected the intent", a.approver)))
            } else {
                None
            };
            if let Some((code, why)) = problem {
                return run.deny(Step::Approval, code, why, why_human);
            }
            if !agreed.contains(&a.approver) {
                agreed.push(a.approver.clone());
            }
        }
        if let Some(backing) = lease {
            // the lease's terms were approved; that approval stands while one of
            // its approvers can still give it. A use never asks anyone again.
            agreed = backing.approved_by.iter().filter(|o| approvers.contains(o)).cloned().collect();
            if agreed.len() < quorum {
                return run.deny(
                    Step::Approval,
                    DenyCode::ApprovalInvalid,
                    format!(
                        "the lease's approval no longer stands: none of its approvers can still approve a {risk} action at {}",
                        resource.id
                    ),
                    why_human,
                );
            }
        }
        if agreed.len() < quorum {
            if req.links.iter().any(|l| l.intent.constraints.no_escalation) {
                return run.deny(
                    Step::Approval,
                    DenyCode::Constraint,
                    "a human must approve, but the requester asked not to escalate",
                    why_human,
                );
            }
            let remaining: Vec<EntityId> = approvers.iter().filter(|a| !agreed.contains(a)).cloned().collect();
            if remaining.len() < quorum - agreed.len() {
                let who = if quorum > 1 { "two different owners" } else { "an owner" };
                return run.deny(
                    Step::Approval,
                    DenyCode::PolicyDenied,
                    format!("{who} of {} must approve, but not enough can", resource.id),
                    why_human,
                );
            }
            let progress = if agreed.is_empty() { String::new() } else { format!("{} approved; ", names(&agreed)) };
            run.trace.push(StepRecord {
                step: Step::Approval,
                passed: false,
                detail: format!(
                    "{progress}waiting for {} ({} of {quorum})",
                    names(&remaining).replace(" ← ", " or "),
                    quorum - agreed.len()
                ),
            });
            let escalation = Escalation {
                intent: outer.id,
                digest: req.digest,
                resource: resource.id.clone(),
                risk,
                approvers: remaining,
                quorum: quorum as u8,
                approved_by: agreed,
                reasons: why_human,
                deadline_ms: outer.constraints.deadline_ms,
            };
            return run.finish(Verdict::Escalate(escalation));
        }
        let how = if lease.is_some() { "approved for the lease by" } else { "approved by" };
        run.pass(Step::Approval, format!("{how} {}", names(&agreed).replace(" ← ", " and ")));
        agreed
    };

    let policy_reasons = if !approved_by.is_empty() {
        approved_reasons.sort();
        approved_reasons.dedup();
        approved_reasons
    } else {
        permit_reasons
    };
    let grant = Grant {
        intent: outer.id,
        digest: req.digest,
        actor: outer.actor.clone(),
        on_behalf_of: outer.on_behalf_of.clone(),
        relayed_from: relayed,
        resource: resource.id.clone(),
        def: def.clone(),
        params: outer.params.clone(),
        device: binding.device.clone(),
        risk,
        approved_by,
        tokens,
        token_refs,
        policy_reasons,
        decided_at_ms: now,
        lease_terms: asks.cloned(),
    };
    run.finish(Verdict::Allow(Box::new(grant)))
}

#[path = "recovery.rs"]
mod recovery;
pub use recovery::{authorize_recovery, RecoveryGrant, RecoveryRequest};

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
