//! The Home/Site Node (Blueprint v9 "Chitala Home/Site Server", v17 §3–4).
//!
//! `Node::handle` is the whole trust chain of milestone 0.0.1:
//!
//! ```text
//! signed CSME → Reference Monitor → (deny → audit + SecurityDenied event + containment)
//!                                 → (allow → audit → adapter / domain operation → twin → event → audit)
//! ```
//!
//! AI principals take the intent path instead (module `intents`, specs 15–17):
//! intent → Authority Engine → Safety → (human approval) → trusted boundary.
//!
//! Every physical action — a person's request as much as an AI's intent — then
//! passes Safety and becomes a command only at the Trusted Execution Boundary
//! (`chitala-boundary`, spec 19); the adapter host's receipt is checked before
//! its report is believed, and the resource's witness is observed to verify
//! that the world ended up as intended (module `outcomes`, spec 22).
//!
//! An allowed action is only executed after its decision record is durably in the
//! audit log ("no evidence, no action"). Domain operations — delegation,
//! revocation, security-state changes — are capabilities like any other and go
//! through the same monitor.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use chitala_adapters::{AdapterError, Observed, Provenance, Simulation};
use chitala_audit::{redact_payload, Anchor, AuditLog};
use chitala_boundary::{
    verify_receipt, Authority, DecisionContext, Expectation, MintedOrder, TrustedExecutionBoundary,
};
use chitala_bus::{EventBus, Filter, Subscription};
use chitala_identity::{IdentityRegistry, Keypair, PublicKey};
use chitala_intent::{IntentId, APPROVAL_CONTENT_TYPE, INTENT_CONTENT_TYPE};
use chitala_model::{
    payload, CapabilityDef, CapabilityId, CapabilityKind, CapabilityRegistry, DenyCode, DeviceDescriptor, EntityId,
    EntityKind, Event, EventKind, ExecCode, ParamValue, Payload, RiskClass, SecurityState, TargetKind,
};
use chitala_monitor::{
    device_state, evaluate_policy, Authorized, Decision, Denial, Monitor, MonitorConfig, TargetInfo, Targets, World,
};
use chitala_platform::{TrustedClock, Visibility};
use chitala_policy::{
    authority::resource_attrs, DeviceAttrs, PolicyContext, PolicyEngine, PolicyRequest, PrincipalInfo, ResourceInfo,
};
use chitala_resource::{Resource, ResourceGraph, ResourceId};
use chitala_safety::{Observation, Proposed, Safety, SafetyConfig};
use chitala_state::{Origin, TwinStore};
use chitala_token::{bytes_from_base64, Grant, RevocationList, Right, TokenAuthority, TokenRef, TokenVerifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::config::{ContainmentConfig, StoredObject};
use crate::executor::{Executed, Executor};
use crate::ipc::{request_digest, sign_reply, ExecError, Response, PROTOCOL};
use crate::NodeError;

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Everything needed to build a node; produced from a config file or in memory.
pub struct NodeParts {
    pub domain: EntityId,
    pub node_id: EntityId,
    /// Signs replies (v10 manager authentication). Separate from the authority key.
    pub node_key: Keypair,
    pub authority_key: Keypair,
    pub principals: Vec<(EntityId, PublicKey, Vec<String>)>,
    /// Which humans each non-human principal acts for (spec §15 `on_behalf_of`).
    pub agency: Vec<(EntityId, Vec<EntityId>)>,
    pub devices: Vec<DeviceDescriptor>,
    /// The governed physical world (spec §14).
    pub resources: Vec<Resource>,
    pub safety: SafetyConfig,
    /// Where device actions run: isolated adapter host components in production
    /// ([`crate::executor::ComponentHost`]), in-process only for tests and the demo.
    pub executor: Arc<dyn Executor>,
    pub policy: PolicySource,
    pub audit: AuditLog,
    /// Persisted authority state (see [`load_domain_state`]); default for a new domain.
    pub state: DomainState,
    /// Where `state` is persisted (private); `None` keeps it in memory only.
    pub state_file: Option<StoredObject>,
    pub containment: ContainmentConfig,
    pub monitor: MonitorConfig,
    /// The platform's entropy (PAL, spec 18): ids, token key chains.
    pub entropy: Arc<dyn chitala_platform::Entropy>,
    pub clock: Clock,
    /// The trusted clock behind `clock`, if any: wall-clock regressions it
    /// observes are written to the audit log.
    pub clock_watch: Option<Arc<TrustedClock>>,
    /// The only producer of physical commands. Every executor must accept its
    /// order key.
    pub boundary: TrustedExecutionBoundary,
}

/// Where the domain policy comes from.
pub enum PolicySource {
    /// The embedded default policy (Security Constitution included).
    Default,
    /// Cedar source, validated against the registry schema at start-up.
    Cedar(String),
    /// An already validated engine, shared between nodes (tests, fuzzing).
    Engine(Arc<PolicyEngine>),
}

/// A token the domain issued, kept so revocation can follow the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedRecord {
    pub holder: EntityId,
    pub issuer: EntityId,
    pub rights: Vec<Right>,
    pub expires_at_ms: u64,
    pub depth: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// Authority state that must survive restarts (revocations, containment).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainState {
    /// Bumped on every authority change (v13 §7 policy/trust epoch).
    pub epoch: u64,
    pub revocations: RevocationList,
    /// Principals not in TRUSTED.
    pub principal_states: BTreeMap<EntityId, SecurityState>,
    pub issued: BTreeMap<String, IssuedRecord>,
    /// Audit head when this state was written. On start-up the audit log must
    /// still contain it, and the log may not record a higher epoch than this
    /// state: together they detect a rolled-back state file (un-revoking tokens)
    /// and a deleted or truncated audit log (v13 §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_anchor: Option<Anchor>,
    /// Safety holds in force, with their reasons (spec 17 `SAFE-1-HOLD`). They
    /// survive a restart: a hold that a crash or a power cut lifted would be a
    /// protection gone without anyone deciding it (threat model N8). Placing or
    /// lifting one bumps the epoch, so a state file rolled back past it is
    /// refused at start-up.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub holds: BTreeMap<ResourceId, String>,
    /// Execution leases by id (spec 21), with their uses: a lease outlives a
    /// restart, and a use counted is never given again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub leases: BTreeMap<String, Lease>,
    /// Resources in recovery after a failed outcome, with why (spec 22). Like
    /// holds, they survive a restart and only a person ends them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub recovery: BTreeMap<ResourceId, String>,
    /// Actions that may change the world and whose outcome is not settled
    /// yet, by intent or request id (spec 22). Written before the decision is
    /// recorded, with an epoch bump; watched again after a restart, so the
    /// uncertainty about the physical world never vanishes with the node.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inflight: BTreeMap<String, InFlight>,
}

/// Read the persisted domain state; a missing object is a new domain. State
/// that others could read or modify is refused, not used.
pub fn load_domain_state(stored: &StoredObject) -> Result<DomainState, NodeError> {
    match stored.read(Visibility::Private)? {
        None => Ok(DomainState::default()),
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| NodeError::Config(format!("{}: {e}", stored.path))),
    }
}

struct Containment {
    cfg: ContainmentConfig,
    denials: HashMap<EntityId, VecDeque<u64>>,
}

impl Containment {
    /// Codes that indicate probing for authority rather than an honest mistake.
    /// `E_PRINCIPAL_STATE` counts too: a contained principal that keeps reaching
    /// above its risk ceiling is still probing.
    fn counts(code: DenyCode) -> bool {
        use DenyCode::*;
        matches!(
            code,
            PrincipalState
                | TokenMissing
                | TokenInvalid
                | TokenRevoked
                | TokenDenied
                | PolicyDenied
                | UnknownTarget
                | UnknownCapability
                | UnsupportedByTarget
                | RiskMismatch
                | Replay
                | RateLimited
                | IntentRequired
                | UnknownResource
                | OnBehalfOf
                | Provenance
        )
    }

    /// Record a denial; returns the state the actor should now be in, if any.
    fn record(&mut self, actor: &EntityId, now: u64) -> Option<(SecurityState, usize)> {
        let w = self.denials.entry(actor.clone()).or_default();
        w.push_back(now);
        while matches!(w.front(), Some(t) if *t + self.cfg.window_ms <= now) {
            w.pop_front();
        }
        let n = w.len();
        let state = if n >= self.cfg.quarantine_after as usize {
            SecurityState::Quarantined
        } else if n >= self.cfg.restricted_after as usize {
            SecurityState::Restricted
        } else if n >= self.cfg.suspicious_after as usize {
            SecurityState::Suspicious
        } else {
            return None;
        };
        Some((state, n))
    }
}

struct Directory<'a> {
    domain: &'a EntityId,
    domain_caps: &'a [CapabilityId],
    devices: &'a BTreeMap<EntityId, DeviceDescriptor>,
    identities: &'a IdentityRegistry,
}

impl Targets for Directory<'_> {
    fn target(&self, id: &EntityId) -> Option<TargetInfo> {
        if id == self.domain {
            return Some(TargetInfo {
                id: id.clone(),
                kind: TargetKind::Domain,
                capabilities: self.domain_caps.to_vec(),
                device: None,
            });
        }
        self.devices.get(id).map(|d| TargetInfo {
            id: id.clone(),
            kind: TargetKind::Device,
            capabilities: d.capabilities.clone(),
            device: Some(DeviceAttrs {
                security_class: d.security_class,
                room: d.room.clone(),
                state: device_state(self.identities, id),
            }),
        })
    }
}

macro_rules! directory {
    ($s:ident) => {
        Directory { domain: &$s.domain, domain_caps: &$s.domain_caps, devices: &$s.devices, identities: &$s.identities }
    };
}

macro_rules! world {
    ($s:ident, $dir:ident, $now:expr) => {
        World {
            identities: &$s.identities,
            registry: &$s.registry,
            targets: &$dir,
            resources: &$s.resources,
            tokens: &$s.verifier,
            revocations: &$s.state.revocations,
            policy: &$s.policy,
            now_ms: $now,
        }
    };
}

// after the macros: the intent path uses them
#[path = "intents.rs"]
mod intents;
#[path = "leases.rs"]
mod leases;
pub use leases::{Lease, LEASE_RETENTION_MS, MAX_LEASES, MAX_LEASES_PER_ACTOR, MAX_STORED_LEASES};
#[path = "outcomes.rs"]
mod outcomes;
pub use outcomes::{InFlight, OutcomeStatus};
#[path = "plans.rs"]
mod plans;
pub use plans::{PlanStatus, MAX_PLANS, MAX_PLANS_PER_ACTOR, MAX_STORED_PLANS, PLAN_RETENTION_MS};

/// Result of [`Node::begin`]. Lives for one request only, so the size of the
/// finished response does not matter.
#[allow(clippy::large_enum_variant)]
pub enum Step {
    /// Decided and finished: denials, domain operations, failures.
    Done(Response),
    /// A device operation to run with the adapter host, then [`Node::finish`].
    Device(PendingDevice),
}

/// Lives for one request only, like [`Step`].
#[allow(clippy::large_enum_variant)]
enum DeviceOp {
    Observe,
    /// A minted order, sent at most once, what its receipt must answer, the
    /// authority it depends on, and what it promises about the world.
    Execute {
        order: Option<MintedOrder>,
        expect: Expectation,
        fence: Fence,
        watch: Option<outcomes::Watch>,
    },
}

/// What in-flight orders are re-checked against: the domain's revocations and
/// the principals that can no longer act (spec 19 "Authority fence").
#[derive(Debug, Default, Clone)]
struct AuthorityView {
    revocations: RevocationList,
    unable: BTreeMap<EntityId, SecurityState>,
    /// Resources under a safety hold.
    holds: BTreeSet<ResourceId>,
    /// Execution leases that were revoked (spec 21).
    revoked_leases: BTreeSet<String>,
    /// Resources in recovery after a failed outcome (spec 22).
    recovering: BTreeSet<ResourceId>,
    /// Plans a person cancelled (spec 23).
    cancelled_plans: BTreeSet<String>,
}

/// What one order depends on, re-checked right before it is sent: a
/// revocation of one of its tokens, a principal of its decision that can no
/// longer act, a token that expired, or a safety hold placed on its resource
/// (or one it is in) stops it. Anything else (an unrelated delegation) does not.
struct Fence {
    view: Arc<RwLock<AuthorityView>>,
    tokens: Vec<TokenRef>,
    principals: Vec<EntityId>,
    /// The order's resource and every resource it is in.
    resources: Vec<ResourceId>,
    /// The execution lease the order is one use of, if any.
    lease: Option<String>,
    /// The resource whose declared safe state this order is, if it is one:
    /// recovery there does not stop it (spec 22).
    safe_state_of: Option<ResourceId>,
    /// The plan the order is one step of, if any (spec 23).
    plan: Option<String>,
    clock: Clock,
}

impl Fence {
    fn check(&self) -> Result<(), String> {
        let now = (self.clock)();
        if let Some(t) = self.tokens.iter().find(|t| now >= t.expires_at_ms) {
            return Err(format!("token {} expired", &t.revocation_id[..t.revocation_id.len().min(16)]));
        }
        let v = self.view.read().map_err(|_| "the authority view is unavailable".to_string())?;
        if let Some(r) = self.resources.iter().find(|r| v.holds.contains(*r)) {
            return Err(format!("{r} is under a safety hold"));
        }
        if let Some(r) =
            self.resources.iter().find(|r| v.recovering.contains(*r) && self.safe_state_of.as_ref() != Some(*r))
        {
            return Err(format!("{r} is in recovery"));
        }
        if let Some(l) = self.lease.as_ref().filter(|l| v.revoked_leases.contains(*l)) {
            return Err(format!("lease {} was revoked", &l[..l.len().min(16)]));
        }
        if let Some(p) = self.plan.as_ref().filter(|p| v.cancelled_plans.contains(*p)) {
            return Err(format!("plan {} was cancelled", &p[..p.len().min(16)]));
        }
        for t in &self.tokens {
            if let Some(why) = v.revocations.revokes(t) {
                return Err(format!("token {}: {why}", &t.revocation_id[..t.revocation_id.len().min(16)]));
            }
        }
        for p in &self.principals {
            if let Some(s) = v.unable.get(p) {
                return Err(format!("{p} is now {s}"));
            }
        }
        Ok(())
    }
}

/// Phase 2 of a device request: it needs no node state, so the IPC server runs
/// it without holding the node lock — a slow or hung device cannot stall the
/// Reference Monitor for everyone else.
pub struct PendingDevice {
    executor: Arc<dyn Executor>,
    device: EntityId,
    adapter: String,
    op: DeviceOp,
    mid: String,
    decision_seq: u64,
    /// The witness's state right after an order that may have executed (spec
    /// 22), and when the node received it.
    witnessed: Option<(Result<Observed, AdapterError>, u64)>,
    clock: Clock,
    /// When the device's answer arrived (a time the node can trust, unlike a
    /// later moment once it holds its lock again).
    answered_at: Option<u64>,
}

/// An observation of a device whose state Safety relies on, run outside the
/// node lock like [`PendingDevice`].
pub struct Observer {
    executor: Arc<dyn Executor>,
    device: EntityId,
    clock: Clock,
    /// The device witnesses a pending outcome: its adapter is asked to
    /// confirm the state current (F9b).
    evidence: bool,
}

impl Observer {
    pub fn device(&self) -> &EntityId {
        &self.device
    }
    /// The observation, and when the node received it.
    pub fn run(&self) -> (Result<Observed, AdapterError>, u64) {
        let r = if self.evidence {
            self.executor.observe_evidence(&self.device)
        } else {
            self.executor.observe(&self.device)
        };
        (r, (self.clock)())
    }
}

impl PendingDevice {
    /// Run the device operation. An order is not sent if the authority it was
    /// decided on changed in the meantime — one of its tokens was revoked, or
    /// a principal of the decision can no longer act: the decision it carries
    /// is out of date. After an order that may have executed, the resource's
    /// witness is observed, so the outcome can be verified (spec 22).
    pub fn run(&mut self) -> Result<Executed, AdapterError> {
        match &mut self.op {
            DeviceOp::Observe => {
                let r = self.executor.observe(&self.device);
                self.answered_at = Some((self.clock)());
                r.map(|o| Executed { state: o.state, receipt: None, age_ms: o.age_ms, provenance: o.provenance })
            }
            DeviceOp::Execute { order, fence, watch, .. } => {
                fence.check().map_err(|why| {
                    AdapterError::Rejected(format!(
                        "authority changed since the decision ({why}); the order was not sent"
                    ))
                })?;
                let order = order.take().ok_or_else(|| AdapterError::Rejected("the order was already sent".into()))?;
                // from now on the order may act: only a state produced since is evidence of it
                if let Some(w) = watch.as_mut() {
                    w.sent_at_ms = (self.clock)();
                }
                let result = self.executor.execute(&self.device, order);
                // a reported execution, or one whose fate is unknown, may have
                // changed the world; an order the gate rejected, a device that
                // refused or could not be reached, an adapter that could not
                // run it: nothing happened
                let maybe_executed = matches!(&result, Ok(_) | Err(AdapterError::Indeterminate(_)));
                if let Some(w) = watch.as_ref().filter(|_| maybe_executed) {
                    let seen = self.executor.observe_evidence(&w.witness);
                    self.witnessed = Some((seen, (self.clock)()));
                }
                result
            }
        }
    }
}

/// The periodic pass asks a device whose observation failed again after this
/// long, doubling up to [`OBSERVE_BACKOFF_MAX_MS`] (F5).
pub const OBSERVE_BACKOFF_MIN_MS: u64 = 1_000;
pub const OBSERVE_BACKOFF_MAX_MS: u64 = 30_000;

/// Where in time an observation received at `received` comes from: when its
/// source produced the state, `age_ms` before (F9), and when its adapter
/// confirmed it current (F9b). Each `None` when its adapter cannot tell.
fn origin(received: u64, age_ms: Option<u64>, provenance: Provenance) -> Origin {
    Origin {
        produced_at_ms: age_ms.map(|age| received.saturating_sub(age)),
        confirmed_at_ms: match provenance {
            Provenance::ConfirmedCurrent { age_ms } => Some(received.saturating_sub(age_ms)),
            Provenance::Uncertain => None,
        },
    }
}

pub struct Node {
    domain: EntityId,
    node_id: EntityId,
    node_key: Keypair,
    identities: IdentityRegistry,
    registry: CapabilityRegistry,
    domain_caps: Vec<CapabilityId>,
    policy: Arc<PolicyEngine>,
    authority: TokenAuthority,
    verifier: TokenVerifier,
    devices: BTreeMap<EntityId, DeviceDescriptor>,
    resources: ResourceGraph,
    safety: Safety,
    /// Escalated intents waiting for a human.
    pending: BTreeMap<IntentId, intents::PendingIntent>,
    executor: Arc<dyn Executor>,
    monitor: Monitor,
    twins: TwinStore,
    /// Devices whose last observation failed: when the periodic pass asks
    /// again, and the wait that led there (F5; never persisted).
    observe_backoff: BTreeMap<EntityId, (u64, u64)>,
    bus: EventBus,
    audit: AuditLog,
    state: DomainState,
    state_file: Option<StoredObject>,
    containment: Containment,
    clock: Clock,
    clock_watch: Option<Arc<TrustedClock>>,
    entropy: Arc<dyn chitala_platform::Entropy>,
    boundary: TrustedExecutionBoundary,
    /// What pending device operations are re-checked against (see [`PendingDevice::run`]).
    authority_view: Arc<RwLock<AuthorityView>>,
    /// Devices executing an order, until when (SAFE-7-BUSY).
    in_flight: BTreeMap<EntityId, u64>,
    /// Resources an executing order acts on, until when (SAFE-7-BUSY): one
    /// resource reached through two devices still takes one action at a time.
    busy_resources: BTreeMap<ResourceId, u64>,
    /// Outcomes waiting for their witness, by order id (spec 22).
    outcomes: BTreeMap<String, outcomes::Pending>,
    /// Plans by id (spec 23), in memory only, and the step ids of each.
    plans: BTreeMap<String, plans::Plan>,
    plan_steps: BTreeMap<String, (String, usize)>,
}

/// Whom an AI agent may use a delegated right for (spec 05 "Context binding"):
/// the person named, else the delegator if the agent serves them, else the one
/// person it serves. Persons, devices and services represent nobody but
/// themselves, so their tokens are unbound.
fn binding_for(
    holder: &chitala_identity::Principal,
    delegator: &EntityId,
    named: Option<EntityId>,
) -> Result<Vec<EntityId>, ExecError> {
    if holder.id.kind() != EntityKind::Ai {
        return match named {
            Some(_) => Err(exec(
                ExecCode::InvalidArgument,
                format!("{} acts for nobody but itself; for_person applies to AI agents", holder.id),
            )),
            None => Ok(Vec::new()),
        };
    }
    let person = match named {
        Some(p) => p,
        None if holder.serves.contains(delegator) => delegator.clone(),
        None if holder.serves.len() == 1 => holder.serves[0].clone(),
        None => {
            return Err(exec(
                ExecCode::InvalidArgument,
                format!("say for whom {} may use the right (for_person)", holder.id),
            ))
        }
    };
    if !holder.serves.contains(&person) {
        return Err(exec(ExecCode::DelegationDenied, format!("{} does not act for {person}", holder.id)));
    }
    Ok(vec![person])
}

fn exec(code: ExecCode, message: impl Into<String>) -> ExecError {
    ExecError { code, message: message.into() }
}

fn random_id(entropy: &dyn chitala_platform::Entropy) -> String {
    hex::encode(chitala_platform::random_array::<16>(entropy))
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// The state an action promises (its registry outcome, spec 22), used as the
/// twin's desired state.
fn expected_state(def: &CapabilityDef, p: &Payload) -> Payload {
    def.outcome.as_ref().map(|o| o.expect(p)).unwrap_or_default()
}

impl Node {
    pub fn new(parts: NodeParts) -> Result<Self, NodeError> {
        let registry = CapabilityRegistry::core_v0_1();
        let policy = match parts.policy {
            PolicySource::Default => Arc::new(PolicyEngine::with_default_policies(&registry)?),
            PolicySource::Cedar(src) => Arc::new(PolicyEngine::new(&registry, &src)?),
            PolicySource::Engine(engine) => engine,
        };
        let mut identities = IdentityRegistry::new();
        for (id, pk, roles) in &parts.principals {
            let roles: Vec<&str> = roles.iter().map(String::as_str).collect();
            identities.enroll(id.clone(), *pk, &roles).map_err(|e| NodeError::Config(e.to_string()))?;
        }
        let state = parts.state;
        for (id, s) in &state.principal_states {
            // a principal removed from the config simply disappears
            let _ = identities.set_state(id, *s);
        }

        let mut devices = BTreeMap::new();
        for d in parts.devices {
            for c in &d.capabilities {
                match registry.get(c) {
                    Some(def) if def.target == TargetKind::Device => {}
                    _ => return Err(NodeError::Config(format!("{}: {c} is not a device capability", d.id))),
                }
            }
            if !parts.executor.manages(&d.id) {
                return Err(NodeError::Config(format!("{}: no adapter host serves it", d.id)));
            }
            match parts.executor.session(&d.id) {
                Some(s) if s.order_key == parts.boundary.order_key() => {}
                _ => {
                    return Err(NodeError::Config(format!(
                        "{}: its adapter host does not accept this node's order key",
                        d.id
                    )))
                }
            }
            if devices.insert(d.id.clone(), d).is_some() {
                return Err(NodeError::Config("duplicate device id".into()));
            }
        }
        for (id, serves) in &parts.agency {
            identities.set_serves(id, serves).map_err(|e| NodeError::Config(e.to_string()))?;
        }
        let resources = ResourceGraph::new(parts.resources, &registry).map_err(|e| NodeError::Config(e.to_string()))?;
        resources
            .check_devices(|d, c| devices.get(d).map(|x: &DeviceDescriptor| x.supports(c)))
            .map_err(|e| NodeError::Config(e.to_string()))?;
        let domain_caps = registry.iter().filter(|d| d.target == TargetKind::Domain).map(|d| d.id.clone()).collect();
        let authority = TokenAuthority::new(&parts.authority_key, Arc::clone(&parts.entropy));
        let verifier = authority.verifier();

        let mut node = Self {
            domain: parts.domain,
            node_id: parts.node_id,
            node_key: parts.node_key,
            identities,
            registry,
            domain_caps,
            policy,
            authority,
            verifier,
            devices,
            resources,
            safety: Safety::new(parts.safety),
            pending: BTreeMap::new(),
            executor: parts.executor,
            monitor: Monitor::new(parts.monitor),
            twins: TwinStore::default(),
            observe_backoff: BTreeMap::new(),
            bus: EventBus::new(),
            audit: parts.audit,
            state,
            state_file: parts.state_file,
            containment: Containment { cfg: parts.containment, denials: HashMap::new() },
            clock: parts.clock,
            clock_watch: parts.clock_watch,
            entropy: parts.entropy,
            authority_view: Arc::new(RwLock::new(AuthorityView::default())),
            in_flight: BTreeMap::new(),
            busy_resources: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            plans: BTreeMap::new(),
            plan_steps: BTreeMap::new(),
            boundary: parts.boundary,
        };
        // holds in force before the restart are in force again
        let held: Vec<(ResourceId, String)> = node.state.holds.iter().map(|(r, w)| (r.clone(), w.clone())).collect();
        for (resource, reason) in held {
            node.safety.hold(resource, reason);
        }
        // and so are recoveries: only a person ends one
        let recovering: Vec<(ResourceId, String)> =
            node.state.recovery.iter().map(|(r, w)| (r.clone(), w.clone())).collect();
        for (resource, reason) in recovering {
            node.safety.recover(resource, reason);
        }
        node.refresh_authority_view();
        let now = node.now();
        node.monitor.reject_issued_before(now);
        let ids: Vec<EntityId> = node.devices.keys().cloned().collect();
        for id in &ids {
            node.refresh(id, now);
        }
        let in_flight = node.state.inflight.values().filter(|e| e.minted()).count();
        let f = json!({
            "event": "start",
            "domain": node.domain.to_string(),
            "epoch": node.state.epoch,
            "in_flight": in_flight,
            "policy_fp": node.policy.fingerprint(),
            "registry": format!("{}/{}", node.registry.name(), node.registry.version()),
            "devices": ids.len(),
            "resources": node.resources.len(),
            "principals": node.identities.principals().count(),
            "order_key": hex::encode(node.boundary.order_key_id()),
        });
        node.audit.append(now, "node", obj(f))?;
        node.record_clock_regression(now);
        // orders that may have reached a device before the restart are watched
        // again; the start-up observation may already settle them
        if node.restore_inflight(now) > 0 {
            let seen: Vec<(EntityId, Payload, Option<u64>)> = node
                .pending_witnesses()
                .into_iter()
                .filter_map(|w| {
                    let at = node.twins.get(&w).and_then(|t| outcomes::evidence_at(&t.origin()));
                    node.twins.evidence(&w, now).map(|(_, state)| (w.clone(), state.clone(), at))
                })
                .collect();
            for (w, state, at) in seen {
                node.witnessed(&w, &state, at, now);
            }
        }
        Ok(node)
    }

    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    pub fn domain(&self) -> &EntityId {
        &self.domain
    }
    pub fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }
    pub fn identities(&self) -> &IdentityRegistry {
        &self.identities
    }
    pub fn twins(&self) -> &TwinStore {
        &self.twins
    }
    pub fn resources(&self) -> &ResourceGraph {
        &self.resources
    }
    /// The safety layer, read-only: holds change through [`Node::hold`] and
    /// [`Node::release`], which audit them and stop orders in flight.
    pub fn safety(&self) -> &Safety {
        &self.safety
    }

    /// Place a safety hold on a resource (and everything in it): no action
    /// there until it is released, including orders already in flight
    /// (`domain.safety_hold`, spec 17).
    pub fn hold(&mut self, resource: &ResourceId, reason: &str, by: &EntityId) -> Result<(), NodeError> {
        if self.resources.get(resource).is_none() {
            return Err(NodeError::Config(format!("unknown resource {resource}")));
        }
        let now = self.now();
        let reason: String = reason.chars().take(280).collect();
        self.safety.hold(resource.clone(), reason.clone());
        self.state.holds.insert(resource.clone(), reason.clone());
        self.state.epoch += 1;
        self.save_state();
        self.refresh_authority_view();
        self.safety_changed("hold", resource, Some(&reason), by, now);
        Ok(())
    }

    /// Release a resource: lift its safety hold and end its recovery after a
    /// failed outcome (spec 22). Returns `false` if it had neither.
    pub fn release(&mut self, resource: &ResourceId, by: &EntityId) -> bool {
        let now = self.now();
        let held = self.safety.release(resource);
        let recovering = self.safety.end_recovery(resource);
        if held {
            self.state.holds.remove(resource);
        }
        if recovering {
            self.state.recovery.remove(resource);
        }
        if held || recovering {
            self.state.epoch += 1;
            self.save_state();
            self.refresh_authority_view();
            let lifted = match (held, recovering) {
                (true, true) => "hold, recovery",
                (true, false) => "hold",
                _ => "recovery",
            };
            self.safety_changed("release", resource, Some(lifted), by, now);
        }
        held || recovering
    }

    fn safety_changed(&mut self, op: &str, resource: &ResourceId, reason: Option<&str>, by: &EntityId, now: u64) {
        let reason: Option<String> = reason.map(|r| r.chars().take(280).collect());
        let f = json!({
            "op": op,
            "resource": resource.to_string(),
            "reason": reason,
            "by": by.to_string(),
            "epoch": self.state.epoch,
        });
        self.audit_signed(now, "safety", obj(f));
        let data = payload([("op", op.to_string()), ("resource", resource.to_string())]);
        self.publish(EventKind::SafetyChanged, by.clone(), data, None, now);
    }

    /// Whether `device` is still executing an order (SAFE-7-BUSY).
    fn device_busy(&self, device: &EntityId, now: u64) -> bool {
        self.in_flight.get(device).is_some_and(|until| now < *until)
    }

    /// Whether an order on `resource`, through whichever device, is still
    /// executing (SAFE-7-BUSY). Only the resource itself: its neighbours and
    /// the spaces around it are other things.
    fn resource_busy(&self, resource: &ResourceId, now: u64) -> bool {
        self.busy_resources.get(resource).is_some_and(|until| now < *until)
    }
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }
    pub fn domain_state(&self) -> &DomainState {
        &self.state
    }
    pub fn authority_public_key(&self) -> PublicKey {
        self.authority.public_key()
    }
    pub fn verifier(&self) -> &TokenVerifier {
        &self.verifier
    }
    pub fn subscribe(&self, filter: Filter) -> Subscription {
        self.bus.subscribe(filter)
    }

    /// Pre-authentication announcement: protocol versions and domain only
    /// (v4 §5 minimal metadata before authentication), signed by the node.
    pub fn hello(&self) -> Value {
        let mut v = json!({
            "protocol": PROTOCOL,
            "csme_versions": [chitala_csme::CSME_VERSION],
            "registry": format!("{}/{}", self.registry.name(), self.registry.version()),
            "domain": self.domain.to_string(),
        });
        sign_reply(&mut v, &self.node_id, &self.node_key);
        v
    }

    pub fn node_public_key(&self) -> PublicKey {
        self.node_key.public_key()
    }

    /// Write a signed audit checkpoint (e.g. on shutdown).
    pub fn checkpoint(&mut self) -> Result<(), NodeError> {
        let now = self.now();
        self.audit.checkpoint(now)?;
        Ok(())
    }

    // ───────────────────────────── request path ─────────────────────────────

    /// Judge and execute one request; the reply is bound to the request bytes and
    /// signed with the node key.
    pub fn handle(&mut self, bytes: &[u8]) -> Response {
        serde_json::from_value(self.handle_signed(bytes)).unwrap_or_default()
    }

    /// [`Node::handle`] as the signed JSON object sent over IPC. Runs the three
    /// phases back to back; the IPC server runs phase 2 without the node lock.
    pub fn handle_signed(&mut self, bytes: &[u8]) -> Value {
        let mut step = self.begin(bytes);
        // a plan goes on as far as it can without waiting (spec 23)
        let response = loop {
            let r = match step {
                Step::Done(r) => r,
                Step::Device(mut p) => {
                    let outcome = p.run();
                    self.finish(p, outcome)
                }
            };
            match self.continue_plan_of(&r) {
                Some(next) => step = next,
                None => break r,
            }
        };
        self.seal(response, bytes)
    }

    /// Phase 1 (node lock held): Reference Monitor decision, Safety, evidence,
    /// and — for device actions — an order minted by the boundary.
    pub fn begin(&mut self, bytes: &[u8]) -> Step {
        match self.begin_request(bytes) {
            Step::Done(mut r) => {
                let now = self.now();
                self.plan_track(&mut r, now);
                Step::Done(r)
            }
            device => device,
        }
    }

    fn begin_request(&mut self, bytes: &[u8]) -> Step {
        let now = self.now();
        self.record_clock_regression(now);
        self.expire_pending(now);
        match chitala_csme::content_type_of(bytes).as_deref() {
            Some(INTENT_CONTENT_TYPE) => return self.begin_intent(bytes, now),
            Some(APPROVAL_CONTENT_TYPE) => return self.begin_approval(bytes, now),
            _ => {}
        }
        let decision = {
            let dir = directory!(self);
            let world = world!(self, dir, now);
            self.monitor.check(&world, bytes)
        };
        match decision {
            Decision::Deny(d) => Step::Done(self.on_deny(d, now)),
            Decision::Allow(a) => self.on_allow(a, now),
        }
    }

    /// Phase 3 (node lock held): fold the adapter host's answer into the twin,
    /// publish events, record the outcome.
    pub fn finish(&mut self, mut p: PendingDevice, outcome: Result<Executed, AdapterError>) -> Response {
        let now = self.now();
        let mut extra = Map::new();
        // the outcome of an order that may have executed, and whether it is still pending
        let mut judged: Option<(Value, Option<outcomes::Pending>)> = None;
        let result = match (&mut p.op, outcome) {
            (DeviceOp::Observe, Ok(ex)) => {
                let origin = origin(p.answered_at.unwrap_or(now), ex.age_ms, ex.provenance);
                self.observed(&p.device, ex.state.clone(), &p.adapter, None, origin, now);
                self.witnessed(&p.device, &ex.state, outcomes::evidence_at(&origin), now);
                Ok(self.twins.view(&p.device, now))
            }
            (DeviceOp::Observe, Err(e)) => {
                self.unobservable(&p.device, now);
                let mut view = self.twins.view(&p.device, now);
                view["observe_error"] = json!(e.to_string());
                Ok(view)
            }
            (DeviceOp::Execute { expect, watch, fence, .. }, outcome) => {
                // the device and the resource are free again; the order's
                // authority was re-checked when it was sent
                self.in_flight.remove(&p.device);
                if let Some(r) = fence.resources.first() {
                    self.busy_resources.remove(r);
                }
                extra.insert("order".into(), json!(hex::encode(expect.order_id())));
                extra.insert("order_digest".into(), json!(hex::encode(expect.order_digest())));
                extra.insert("executor".into(), json!(hex::encode(expect.executor())));
                // the host's report counts only if its receipt answers exactly this order
                let checked = outcome.and_then(|ex| {
                    verify_receipt(expect, ex.receipt.as_ref(), &ex.state).map(|()| ex).map_err(|e| {
                        extra.insert("receipt_error".into(), json!(e.to_string()));
                        AdapterError::Failed(format!("{e}; the adapter host's report was not applied"))
                    })
                });
                let receipt_failed = extra.contains_key("receipt_error");
                match checked {
                    Ok(ex) => {
                        if let Some(r) = &ex.receipt {
                            extra.insert(
                                "receipt".into(),
                                json!({"executed_at_ms": r.executed_at_ms, "state_digest": hex::encode(r.state_digest)}),
                            );
                        }
                        self.observed(&p.device, ex.state, &p.adapter, Some(p.mid.clone()), Origin::default(), now);
                        if let Some(w) = watch.take() {
                            judged = Some(self.judge(w, true, p.witnessed.take(), &p.mid, p.decision_seq, now));
                        }
                        Ok(self.twins.view(&p.device, now))
                    }
                    Err(e) => {
                        let code = if receipt_failed { ExecCode::ReceiptInvalid } else { e.code() };
                        let data = payload([("code", code.as_str().to_string()), ("message", e.to_string())]);
                        self.publish(EventKind::AdapterError, p.device.clone(), data, Some(p.mid.clone()), now);
                        // the order may have executed: did the world change anyway?
                        if let (Some(w), Some(seen)) = (watch.take(), p.witnessed.take()) {
                            judged = Some(self.judge(w, false, Some(seen), &p.mid, p.decision_seq, now));
                        }
                        Err(exec(code, e.to_string()))
                    }
                }
            }
        };
        let order = extra.get("order").and_then(Value::as_str).map(str::to_string);
        if let Some((view, _)) = &judged {
            // "outcome" in an execution record is ok | error (spec 09)
            extra.insert("verification".into(), view.clone());
        }
        let executes = matches!(p.op, DeviceOp::Execute { .. });
        let mut response = self.complete_with(&p.mid, p.decision_seq, &p.device, result, extra, now);
        let mut watching = false;
        if let Some((view, pending)) = judged {
            if let (Some(order), Some(pending)) = (order, pending) {
                self.keep_pending(order, pending, response.audit_seq);
                watching = true;
            }
            response.outcome = Some(view);
        }
        // settled at once, or certainly not executed: nothing left uncertain
        if executes && !watching {
            self.forget(&p.mid);
        }
        self.plan_track(&mut response, now);
        response
    }

    /// Bind a response to the request bytes and sign it with the node key.
    pub fn seal(&self, mut r: Response, request: &[u8]) -> Value {
        r.request = Some(request_digest(request));
        let mut v = serde_json::to_value(&r).unwrap_or(Value::Null);
        sign_reply(&mut v, &self.node_id, &self.node_key);
        v
    }

    fn on_deny(&mut self, d: Denial, now: u64) -> Response {
        let mid = d.message_id.map(hex::encode);
        let reason: String = d.reason.chars().take(300).collect();
        let mut f = obj(json!({
            "decision": "deny",
            "code": d.code.as_str(),
            "stage": d.stage.as_str(),
            "reason": reason,
            "authenticated": d.authenticated,
            "policy_fp": self.policy.fingerprint(),
            "epoch": self.state.epoch,
        }));
        let opt = |v: Option<String>| v.map(Value::String).unwrap_or(Value::Null);
        f.insert("actor".into(), opt(d.actor.as_ref().map(ToString::to_string)));
        f.insert("mid".into(), opt(mid.clone()));
        f.insert("target".into(), opt(d.target.as_ref().map(ToString::to_string)));
        f.insert("capability".into(), opt(d.capability.as_ref().map(ToString::to_string)));
        f.insert("token".into(), opt(d.token_id.clone()));
        f.insert("policy".into(), json!(d.policy_reasons));
        let seq = self.audit.append(now, "decision", f).ok().map(|a| a.seq);

        let mut data = payload([("code", d.code.as_str()), ("stage", d.stage.as_str())]);
        data.insert("authenticated".into(), d.authenticated.into());
        if let Some(c) = &d.capability {
            data.insert("capability".into(), ParamValue::Text(c.to_string()));
        }
        if let Some(t) = &d.target {
            data.insert("target".into(), ParamValue::Text(t.to_string()));
        }
        let source = d.actor.clone().unwrap_or_else(|| self.node_id.clone());
        self.publish(EventKind::SecurityDenied, source, data, mid.clone(), now);

        if let Some(actor) = d.actor.as_ref().filter(|a| d.authenticated && a.kind() != EntityKind::Person) {
            if Containment::counts(d.code) {
                self.contain(actor, now);
            }
        }

        Response {
            decision: "deny".into(),
            mid,
            code: Some(d.code),
            stage: Some(d.stage.as_str().into()),
            reason: d.authenticated.then_some(d.reason),
            result: None,
            error: None,
            audit_seq: seq,
            ..Default::default()
        }
    }

    /// Automatic containment of a non-human principal (v8 §9).
    fn contain(&mut self, actor: &EntityId, now: u64) {
        let Some((target, n)) = self.containment.record(actor, now) else { return };
        let Some(from) = self.identities.get(actor).map(|p| p.state) else { return };
        let on_ladder = matches!(from, SecurityState::Trusted | SecurityState::Suspicious | SecurityState::Restricted);
        if on_ladder && target > from && from.can_transition(target) {
            let reason = format!("{n} authority denials within {} ms", self.containment.cfg.window_ms);
            let by = self.node_id.clone();
            self.apply_state(actor, from, target, &by, &reason, now);
        }
    }

    fn on_allow(&mut self, a: Box<Authorized>, now: u64) -> Step {
        let mid = a.message_id_hex();
        let device_action = a.def().target == TargetKind::Device && a.def().kind == CapabilityKind::Action;
        let mut f = obj(json!({
            "decision": "allow",
            "mid": mid,
            "actor": a.actor().to_string(),
            "target": a.target().to_string(),
            "capability": a.capability().to_string(),
            "risk": a.def().risk.label(),
            "policy": a.policy_reasons(),
            "policy_fp": self.policy.fingerprint(),
            "epoch": self.state.epoch,
            "payload": redact_payload(a.payload()),
        }));
        if let Some(t) = a.token() {
            f.insert("token".into(), json!({"id": t.revocation_id, "issuer": t.issuer.to_string(), "depth": t.depth}));
        }

        // A physical action is cleared by Safety like any intent: whoever asks,
        // nothing unsafe happens (spec 17).
        let cleared = if device_action {
            let Some((resource, risk_floor)) = self.governing_resource(a.target(), a.capability()) else {
                let why = format!("{} on {} is not bound to a governed resource", a.capability(), a.target());
                return Step::Done(self.request_refused(&a, DenyCode::Safety, "safety", why, vec![], now));
            };
            let risk = risk_floor.map_or(a.def().risk, |floor| floor.max(a.def().risk));
            // two keys: one person alone cannot act on a two-key resource
            if risk >= RiskClass::High && self.resources.two_key(&resource) {
                let why = format!(
                    "{resource} needs two keys for a {risk} action: one person alone cannot do it; \
                     submit an intent so a second person can approve"
                );
                return Step::Done(self.request_refused(&a, DenyCode::TwoKeyRequired, "approval", why, vec![], now));
            }
            let Some(view) = self.safety_view(&resource, a.target(), now) else {
                let why = format!("{resource} is not governed");
                return Step::Done(self.request_refused(&a, DenyCode::Safety, "safety", why, vec![], now));
            };
            let proposed = Proposed {
                subject: &a.envelope().message_id,
                resource: &resource,
                capability: a.def(),
                params: a.payload(),
                risk,
                device: a.target(),
                device_state: view.device_state,
                observation: view.observation.as_ref().map(|(age, st)| Observation { age_ms: *age, state: st }),
                device_busy: self.device_busy(a.target(), now),
                resource_busy: self.resource_busy(&resource, now),
            };
            match self.safety.clear(&self.resources, &proposed, now) {
                Ok(c) => {
                    f.insert("resource".into(), json!(resource.to_string()));
                    f.insert("safety".into(), json!("cleared"));
                    Some((c, risk))
                }
                Err(v) => {
                    let rule = v.rule.id().to_string();
                    return Step::Done(self.request_refused(
                        &a,
                        DenyCode::Safety,
                        "safety",
                        v.to_string(),
                        vec![rule],
                        now,
                    ));
                }
            }
        } else {
            None
        };
        let authority = Authority::Request(a);
        // an action that may change the world is on record before its decision
        let watch = cleared.as_ref().and_then(|(c, risk)| self.watch_for(&authority, c.resource(), *risk));
        if let Some(w) = &watch {
            if let Err(e) = self.reserve(&mid, w.clone()) {
                return Step::Done(Response {
                    decision: "allow".into(),
                    mid: Some(mid),
                    error: Some(e),
                    ..Default::default()
                });
            }
            f.insert("epoch".into(), json!(self.state.epoch));
        }
        let ctx_fp = self.policy.fingerprint();
        let ctx = DecisionContext { domain: &self.domain, policy_fingerprint: ctx_fp, epoch: self.state.epoch };
        if cleared.is_some() {
            f.insert("context".into(), authority.context(&ctx));
        }
        // no evidence, no action
        let decision_seq = match self.audit.append(now, "decision", f) {
            Ok(x) => x.seq,
            Err(e) => {
                self.forget(&mid);
                return Step::Done(Response {
                    decision: "allow".into(),
                    mid: Some(mid),
                    error: Some(exec(ExecCode::Internal, format!("audit unavailable, action not executed: {e}"))),
                    ..Default::default()
                });
            }
        };
        let Authority::Request(a) = authority else { unreachable!("built above") };

        if a.def().target == TargetKind::Domain {
            let outcome = self.exec_domain(&a, now);
            return Step::Done(self.complete(&mid, decision_seq, a.target(), outcome, now));
        }
        let device = a.target().clone();
        let adapter = self.adapter_name(&device);
        let op = match cleared {
            None => DeviceOp::Observe,
            Some((clearance, _)) => {
                self.twins.set_desired(&device, &expected_state(a.def(), a.payload()), now);
                match self.mint(Authority::Request(a), clearance, decision_seq, now, None, watch) {
                    Ok(op) => op,
                    Err(e) => {
                        self.forget(&mid);
                        return Step::Done(self.complete(&mid, decision_seq, &device, Err(e), now));
                    }
                }
            }
        };
        Step::Device(PendingDevice {
            executor: Arc::clone(&self.executor),
            device,
            adapter,
            op,
            mid,
            decision_seq,
            witnessed: None,
            clock: Arc::clone(&self.clock),
            answered_at: None,
        })
    }

    /// Hand an authorized, cleared action to the Trusted Execution Boundary:
    /// the order is bound to the adapter host instance that serves the device.
    /// `risk` is the action's effective risk at its resource: a broken promise
    /// of medium risk or more puts the resource in recovery (spec 22).
    fn mint(
        &mut self,
        authority: Authority,
        clearance: chitala_safety::Clearance,
        evidence: u64,
        now: u64,
        lease: Option<String>,
        watch: Option<outcomes::Watch>,
    ) -> Result<DeviceOp, ExecError> {
        let device = authority.device().clone();
        let subject = hex::encode(authority.subject());
        let safe_state_of = self
            .resources
            .get(clearance.resource())
            .and_then(|r| r.safe_state.as_ref())
            .filter(|s| s.capability == authority.def().id && &s.params == authority.params())
            .map(|_| clearance.resource().clone());
        // what the order depends on, to re-check right before it is sent
        let (tokens, mut principals): (Vec<TokenRef>, Vec<EntityId>) = match &authority {
            Authority::Intent(g) => (
                g.token_refs().to_vec(),
                [g.actor(), g.on_behalf_of()]
                    .into_iter()
                    .chain(g.relayed_from())
                    .chain(g.approved_by())
                    .cloned()
                    .collect(),
            ),
            Authority::Request(a) => {
                (a.token().map(|t| vec![t.reference.clone()]).unwrap_or_default(), vec![a.actor().clone()])
            }
            // the node itself, on the owners' declaration: nothing to revoke
            Authority::Recovery(_) => (Vec::new(), Vec::new()),
        };
        principals.push(device.clone());
        principals.sort();
        principals.dedup();
        let resources = self.resources.lineage(clearance.resource()).iter().map(|r| r.id.clone()).collect();
        let busy_resource = clearance.resource().clone();
        let clearance_resource = &clearance.resource().clone();
        let fence = Fence {
            view: Arc::clone(&self.authority_view),
            tokens,
            principals,
            resources,
            lease,
            safe_state_of,
            plan: self.plan_of_subject(authority.subject()),
            clock: Arc::clone(&self.clock),
        };
        let session = self
            .executor
            .session(&device)
            .ok_or_else(|| exec(ExecCode::DeviceUnavailable, format!("no adapter host serves {device}")))?;
        let fp = self.policy.fingerprint();
        let ctx = DecisionContext { domain: &self.domain, policy_fingerprint: fp, epoch: self.state.epoch };
        let order = self
            .boundary
            .mint(authority, clearance, &ctx, evidence, &session.executor, now)
            .map_err(|e| exec(ExecCode::Internal, e.to_string()))?;
        // persisted before the order can leave the node: from here on it may
        // reach the device. If that fails, the order is dropped unsent.
        let mut watch = watch;
        if let Some(w) = watch.as_mut() {
            // the order may act from now on (refined to when it is sent)
            w.sent_at_ms = now;
            self.minted(&subject, &hex::encode(order.expectation().order_id()), evidence, now)?;
        }
        // the device and the resource are busy until the order is answered or
        // expires (SAFE-7-BUSY)
        let until = order.expectation().expires_at_ms();
        self.in_flight.insert(device, until);
        self.busy_resources.insert(busy_resource, until);
        // the witness will now report this action, not an earlier one
        self.supersede(clearance_resource, now);
        Ok(DeviceOp::Execute { expect: order.expectation().clone(), order: Some(order), fence, watch })
    }

    /// The resource that binds `capability` on `device`, and its risk floor.
    fn governing_resource(
        &self,
        device: &EntityId,
        capability: &CapabilityId,
    ) -> Option<(ResourceId, Option<chitala_model::RiskClass>)> {
        self.resources.bound_to(device).find_map(|rid| {
            let b = self.resources.get(rid)?.binding(capability)?;
            (&b.device == device).then(|| (rid.clone(), b.risk_floor))
        })
    }

    /// The Reference Monitor allowed a request, but Safety refuses it or it
    /// needs a second key.
    fn request_refused(
        &mut self,
        a: &Authorized,
        code: DenyCode,
        stage: &str,
        why: String,
        rules: Vec<String>,
        now: u64,
    ) -> Response {
        let mid = a.message_id_hex();
        let reason: String = why.chars().take(300).collect();
        let f = obj(json!({
            "decision": "deny",
            "code": code.as_str(),
            "stage": stage,
            "reason": reason,
            "authenticated": true,
            "actor": a.actor().to_string(),
            "mid": mid,
            "target": a.target().to_string(),
            "capability": a.capability().to_string(),
            "safety": rules,
            "policy_fp": self.policy.fingerprint(),
            "epoch": self.state.epoch,
        }));
        let seq = self.audit.append(now, "decision", f).ok().map(|x| x.seq);
        let mut data = payload([("code", code.as_str()), ("stage", stage)]);
        data.insert("capability".into(), ParamValue::Text(a.capability().to_string()));
        data.insert("target".into(), ParamValue::Text(a.target().to_string()));
        self.publish(EventKind::SecurityDenied, a.actor().clone(), data, Some(mid.clone()), now);
        // these refusals are not probing: they never count towards containment
        Response {
            decision: "deny".into(),
            mid: Some(mid),
            code: Some(code),
            stage: Some(stage.into()),
            reason: Some(reason),
            audit_seq: seq,
            ..Default::default()
        }
    }

    /// Record the outcome of an allowed request and build its response.
    fn complete(
        &mut self,
        mid: &str,
        decision_seq: u64,
        target: &EntityId,
        outcome: Result<Value, ExecError>,
        now: u64,
    ) -> Response {
        self.complete_with(mid, decision_seq, target, outcome, Map::new(), now)
    }

    /// [`Node::complete`] with extra fields for the execution record (the
    /// order, its digest and the verified receipt).
    fn complete_with(
        &mut self,
        mid: &str,
        decision_seq: u64,
        target: &EntityId,
        outcome: Result<Value, ExecError>,
        extra: Map<String, Value>,
        now: u64,
    ) -> Response {
        let mut f = obj(json!({ "mid": mid, "decision_seq": decision_seq }));
        f.extend(extra);
        match &outcome {
            Ok(_) => {
                f.insert("outcome".into(), json!("ok"));
            }
            Err(e) => {
                f.insert("outcome".into(), json!("error"));
                f.insert("code".into(), json!(e.code.as_str()));
                f.insert("message".into(), json!(e.message.chars().take(300).collect::<String>()));
            }
        }
        if let Some(t) = self.twins.get(target) {
            f.insert("state_version".into(), json!(t.version));
        }
        let seq = self.audit.append(now, "execution", f).ok().map(|x| x.seq);
        let (result, error) = match outcome {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e)),
        };
        Response {
            decision: "allow".into(),
            mid: Some(mid.to_string()),
            result,
            error,
            audit_seq: seq.or(Some(decision_seq)),
            ..Default::default()
        }
    }

    // ───────────────────────────── devices ─────────────────────────────

    fn adapter_name(&self, device: &EntityId) -> String {
        self.devices.get(device).map(|d| d.adapter.clone()).unwrap_or_default()
    }

    /// Fold an observation into the twin and announce changes.
    fn observed(
        &mut self,
        device: &EntityId,
        state: Payload,
        adapter: &str,
        caused_by: Option<String>,
        origin: Origin,
        now: u64,
    ) {
        self.observe_backoff.remove(device);
        self.twins.ensure(device);
        if let Some(change) = self.twins.apply_reported(device, state, adapter, now, origin) {
            let mut data = change.changed;
            data.insert("version".into(), ParamValue::Int(change.version as i64));
            self.publish(EventKind::StateChanged, device.clone(), data, caused_by, now);
        }
    }

    /// An observation of `device` failed. Its last known state is no evidence
    /// any more (F6), and the periodic pass asks it again after 1, 2, 4, 8 and
    /// 16 s, then every 30 s, until a good observation (F5). The pace only
    /// spares the device and its adapter: Safety is not affected, as the
    /// state is unknown meanwhile, and the witnesses of pending outcomes are
    /// still asked on every pass.
    pub(super) fn unobservable(&mut self, device: &EntityId, now: u64) {
        self.twins.lost(device, now);
        let wait = match self.observe_backoff.get(device) {
            Some((_, wait)) => (wait * 2).min(OBSERVE_BACKOFF_MAX_MS),
            None => OBSERVE_BACKOFF_MIN_MS,
        };
        self.observe_backoff.insert(device.clone(), (now + wait, wait));
    }

    /// Devices whose state a resource's state reference relies on and that
    /// have not reported for half of the age it allows (or never, or cannot be
    /// observed now), and the witnesses of outcomes still pending (spec 22). Observing them ahead of
    /// time keeps Safety's freshness rule (SAFE-3) from refusing actions only
    /// because nobody looked recently; `ipc::serve` does so periodically.
    pub fn due_observations(&self, now: u64) -> Vec<Observer> {
        let witnesses = self.pending_witnesses();
        let mut due: BTreeMap<EntityId, u64> = BTreeMap::new();
        for r in self.resources.iter() {
            if let Some(sref) = &r.state {
                let age = due.entry(sref.device.clone()).or_insert(u64::MAX);
                *age = (*age).min(sref.max_age_ms);
            }
        }
        due.into_iter()
            .filter(|(device, max_age)| {
                let twin = self.twins.get(device);
                let lost = twin.is_some_and(|t| t.unobservable_since_ms.is_some());
                let reported = twin.and_then(|t| t.reported_at_ms);
                let waiting = self.observe_backoff.get(device).is_some_and(|(next, _)| now < *next);
                witnesses.contains(device)
                    || (!waiting && (lost || reported.is_none_or(|at| now.saturating_sub(at) >= max_age / 2)))
            })
            .map(|(device, _)| Observer {
                executor: Arc::clone(&self.executor),
                evidence: witnesses.contains(&device),
                device,
                clock: Arc::clone(&self.clock),
            })
            .collect()
    }

    /// Fold the result of an [`Observer`] into the twin.
    pub fn observed_by(&mut self, observer: &Observer, (outcome, received): (Result<Observed, AdapterError>, u64)) {
        let now = self.now();
        match outcome {
            Ok(o) => {
                let adapter = self.adapter_name(&observer.device);
                let origin = origin(received, o.age_ms, o.provenance);
                self.observed(&observer.device, o.state.clone(), &adapter, None, origin, now);
                self.witnessed(&observer.device, &o.state, outcomes::evidence_at(&origin), now);
            }
            Err(_) => {
                self.unobservable(&observer.device, now);
            }
        }
    }

    /// Observe a device synchronously (start-up, simulation).
    fn refresh(&mut self, device: &EntityId, now: u64) -> Option<AdapterError> {
        match self.executor.observe(device) {
            Ok(o) => {
                let adapter = self.adapter_name(device);
                let origin = origin(self.now(), o.age_ms, o.provenance);
                self.observed(device, o.state.clone(), &adapter, None, origin, now);
                self.witnessed(device, &o.state, outcomes::evidence_at(&origin), now);
                None
            }
            Err(e) => {
                self.unobservable(device, now);
                Some(e)
            }
        }
    }

    /// Apply a simulated physical change to a virtual device (demo, tests).
    pub fn simulate(&mut self, device: &EntityId, change: Simulation) -> Result<(), NodeError> {
        let now = self.now();
        if !self.devices.contains_key(device) {
            return Err(NodeError::Config(format!("unknown device {device}")));
        }
        self.executor.simulate(device, &change).map_err(|e| NodeError::Adapter(e.to_string()))?;
        self.refresh(device, now);
        Ok(())
    }

    /// A simulated change the node does not look at (tests): the world moves on
    /// while nobody observes it, as a real device that drops off does.
    pub fn simulate_unseen(&self, device: &EntityId, change: Simulation) -> Result<(), NodeError> {
        if !self.devices.contains_key(device) {
            return Err(NodeError::Config(format!("unknown device {device}")));
        }
        self.executor.simulate(device, &change).map_err(|e| NodeError::Adapter(e.to_string()))
    }

    // ───────────────────────────── domain operations ─────────────────────────────

    fn exec_domain(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        match a.capability().as_str() {
            "domain.list_devices" => Ok(self.list_devices()),
            "domain.list_approvals" => Ok(self.list_approvals(a.actor())),
            "domain.delegate" => self.delegate(a, now),
            "domain.revoke_token" => self.revoke(a, now),
            "domain.revoke_all" => self.revoke_all(a, now),
            "domain.safety_hold" => self.exec_hold(a, true),
            "domain.safety_release" => self.exec_hold(a, false),
            "domain.lease_revoke" => self.lease_revoke(a, now),
            "domain.list_leases" => Ok(self.list_leases(a.actor(), now)),
            "domain.plan_cancel" => self.plan_cancel(a, now),
            "domain.list_plans" => Ok(self.list_plans(a.actor())),
            "domain.set_principal_state" => self.set_state(a, now),
            other => Err(exec(ExecCode::Internal, format!("{other} is not implemented by this node"))),
        }
    }

    fn list_devices(&self) -> Value {
        let list: Vec<Value> = self
            .devices
            .values()
            .map(|d| {
                json!({
                    "id": d.id.to_string(),
                    "name": d.name,
                    "room": d.room,
                    "security_class": d.security_class.label(),
                    "adapter": d.adapter,
                    "capabilities": d.capabilities.iter().map(ToString::to_string).collect::<Vec<_>>(),
                })
            })
            .collect();
        json!({ "devices": list })
    }

    fn delegate(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let p = a.payload();
        let text = |k: &str| match p.get(k) {
            Some(ParamValue::Text(t)) => Ok(t.as_str()),
            _ => Err(exec(ExecCode::InvalidArgument, format!("missing {k}"))),
        };
        let bad = |e: &dyn std::fmt::Display| exec(ExecCode::InvalidArgument, e.to_string());
        let holder = EntityId::parse(text("holder")?).map_err(|e| bad(&e))?;
        let target = EntityId::parse(text("target")?).map_err(|e| bad(&e))?;
        let capability = CapabilityId::parse(text("capability")?).map_err(|e| bad(&e))?;
        let ttl_s = p.get("ttl_s").and_then(ParamValue::as_int).unwrap_or(0).max(0) as u64;
        let start_s = p.get("start_s").and_then(ParamValue::as_int).unwrap_or(0).max(0) as u64;
        let redelegate = u8::try_from(p.get("redelegate").and_then(ParamValue::as_int).unwrap_or(0))
            .ok()
            .filter(|r| *r < chitala_token::MAX_DELEGATION_DEPTH)
            .ok_or_else(|| exec(ExecCode::InvalidArgument, "redelegate must be 0, 1 or 2"))?;
        let for_person = match p.get("for_person") {
            Some(ParamValue::Text(t)) => Some(EntityId::parse(t).map_err(|e| bad(&e))?),
            _ => None,
        };
        let parent_text = match p.get("parent_token") {
            Some(ParamValue::Text(t)) => Some(t.clone()),
            _ => None,
        };
        let actor = a.actor().clone();
        if holder == actor {
            return Err(exec(ExecCode::DelegationDenied, "a principal cannot delegate to itself"));
        }
        let holder_p =
            self.identities.get(&holder).cloned().ok_or_else(|| {
                exec(ExecCode::InvalidArgument, format!("{holder} is not enrolled in {}", self.domain))
            })?;
        let actor_p = self.identities.get(&actor).cloned().ok_or_else(|| exec(ExecCode::Internal, "actor vanished"))?;
        let def = self
            .registry
            .get(&capability)
            .cloned()
            .ok_or_else(|| exec(ExecCode::InvalidArgument, format!("unknown capability {capability}")))?;
        let for_persons = binding_for(&holder_p, &actor, for_person)?;
        let grant = Grant {
            holder: holder.clone(),
            // proof of possession: only messages signed with this key can use it
            holder_key: holder_p.key_id,
            issuer: actor.clone(),
            rights: vec![Right::new(target.clone(), capability.clone())],
            not_before_ms: if start_s == 0 { 0 } else { now.saturating_add(start_s.saturating_mul(1000)) },
            not_after_ms: now.saturating_add(start_s.saturating_add(ttl_s).saturating_mul(1000)),
            redelegate,
            // tokens issued now die with any revocation floor raised later
            issued_epoch: self.state.epoch,
            for_persons,
        };

        if target.kind() == EntityKind::Resource {
            self.check_resource_delegation(&actor_p, &holder_p, &target, &def, parent_text.is_some())?;
        }
        let (issued, parent_id) = {
            let dir = directory!(self);
            let resource_target = target.kind() == EntityKind::Resource;
            let info = if resource_target {
                None
            } else {
                Some(
                    dir.target(&target)
                        .filter(|t| t.kind == def.target && t.capabilities.contains(&capability))
                        .ok_or_else(|| {
                            exec(ExecCode::InvalidArgument, format!("{target} does not offer {capability}"))
                        })?,
                )
            };
            let world = world!(self, dir, now);
            let internal = |e: &dyn std::fmt::Display| exec(ExecCode::Internal, e.to_string());

            // the holder must be able to use the right at all (Security Constitution)
            if let Some(info) = &info {
                let hd = evaluate_policy(&world, &holder_p, info, &def, true).map_err(|e| internal(&e))?;
                if !hd.allowed {
                    return Err(exec(
                        ExecCode::DelegationDenied,
                        format!(
                            "{holder} may never use {capability} on {target} (forbidden by {})",
                            hd.reasons.join(", ")
                        ),
                    ));
                }
            }
            match parent_text {
                Some(t) => {
                    let parent = bytes_from_base64(&t)
                        .and_then(|b| self.verifier.verify(&b))
                        .map_err(|e| exec(ExecCode::DelegationDenied, format!("parent token: {e}")))?;
                    if self.state.revocations.is_revoked(&parent) {
                        return Err(exec(ExecCode::DelegationDenied, "parent token has been revoked"));
                    }
                    let issued = self
                        .authority
                        .delegate(&parent, &actor, &actor_p.key_id, &grant, now)
                        .map_err(|e| exec(ExecCode::DelegationDenied, e.to_string()))?;
                    (issued, Some(parent.revocation_id))
                }
                None => {
                    // resource targets: the issuer's entitlement was checked above
                    let ad = match &info {
                        Some(info) => evaluate_policy(&world, &actor_p, info, &def, false).map_err(|e| internal(&e))?,
                        None => chitala_policy::PolicyDecision { allowed: true, reasons: vec![] },
                    };
                    if !ad.allowed {
                        return Err(exec(
                            ExecCode::DelegationDenied,
                            format!("{actor} does not hold {capability} on {target}; present a parent_token"),
                        ));
                    }
                    let issued = self
                        .authority
                        .issue(&grant, now)
                        .map_err(|e| exec(ExecCode::DelegationDenied, e.to_string()))?;
                    (issued, None)
                }
            }
        };

        self.state.issued.retain(|_, r| r.expires_at_ms > now);
        self.state.issued.insert(
            issued.revocation_id.clone(),
            IssuedRecord {
                holder: holder.clone(),
                issuer: actor.clone(),
                rights: grant.rights.clone(),
                expires_at_ms: issued.expires_at_ms,
                depth: issued.depth,
                parent: parent_id.clone(),
            },
        );
        self.state.epoch += 1;
        self.save_state();
        let f = json!({
            "op": "issue",
            "token": issued.revocation_id,
            "holder": holder.to_string(),
            "issuer": actor.to_string(),
            "right": format!("{target}/{capability}"),
            "depth": issued.depth,
            "redelegate": issued.redelegate,
            "for": issued.for_persons.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "not_before_ms": grant.not_before_ms,
            "expires_at_ms": issued.expires_at_ms,
            "parent": parent_id,
            "epoch": self.state.epoch,
        });
        self.audit_signed(now, "authority", obj(f));
        let data = payload([
            ("op", "issue".to_string()),
            ("token", issued.revocation_id.clone()),
            ("holder", holder.to_string()),
        ]);
        self.publish(EventKind::AuthorityChanged, actor, data, Some(a.message_id_hex()), now);
        Ok(json!({
            "token": issued.base64,
            "revocation_id": issued.revocation_id,
            "not_before_ms": grant.not_before_ms,
            "expires_at_ms": issued.expires_at_ms,
            "depth": issued.depth,
            "redelegate": issued.redelegate,
            "for": issued.for_persons.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "holder": holder.to_string(),
            "target": target.to_string(),
            "capability": capability.to_string(),
        }))
    }

    /// Delegation of a right on a resource (or a container of resources). The
    /// capability must be bound at the target or below it, the holder must be
    /// able to use it there at all (with a human's approval if need be), and —
    /// for a root grant — the issuer must be entitled to it everywhere it covers.
    fn check_resource_delegation(
        &self,
        issuer: &chitala_identity::Principal,
        holder: &chitala_identity::Principal,
        target: &EntityId,
        def: &chitala_model::CapabilityDef,
        has_parent: bool,
    ) -> Result<(), ExecError> {
        let bad = |why: String| exec(ExecCode::InvalidArgument, why);
        let rid = ResourceId::from_entity(target.clone()).map_err(|e| bad(e.to_string()))?;
        if self.resources.get(&rid).is_none() {
            return Err(bad(format!("unknown resource {target}")));
        }
        let covered: Vec<&Resource> =
            self.resources.descendants_or_self(&rid).into_iter().filter(|r| r.binding(&def.id).is_some()).collect();
        if covered.is_empty() {
            return Err(bad(format!("nothing at or below {target} offers {}", def.id)));
        }
        for r in covered {
            let binding = r.binding(&def.id).expect("filtered");
            let device = self.devices.get(&binding.device).map(|d| DeviceAttrs {
                security_class: d.security_class,
                room: d.room.clone(),
                state: device_state(&self.identities, &d.id),
            });
            let Some(device) = device else { continue };
            let attrs = resource_attrs(&self.resources, r, &device);
            let risk = binding.risk_floor.map_or(def.risk, |f| f.max(def.risk));
            let eval = |who: &chitala_identity::Principal, token: bool| {
                self.policy.evaluate(&PolicyRequest {
                    principal: PrincipalInfo { id: &who.id, roles: &who.roles, state: who.state, device: None },
                    capability: &def.id,
                    resource: ResourceInfo::Resource { id: r.id.as_entity(), attrs: &attrs },
                    context: PolicyContext { token_granted: token, human_approved: true, risk },
                })
            };
            let internal = |e: chitala_policy::PolicyError| exec(ExecCode::Internal, e.to_string());
            let hd = eval(holder, holder.id.kind() != EntityKind::Person).map_err(internal)?;
            if !hd.allowed {
                return Err(exec(
                    ExecCode::DelegationDenied,
                    format!(
                        "{} may never use {} on {} (forbidden by {})",
                        holder.id,
                        def.id,
                        r.id,
                        hd.reasons.join(", ")
                    ),
                ));
            }
            if !has_parent {
                let id = eval(issuer, false).map_err(internal)?;
                if !id.allowed {
                    return Err(exec(
                        ExecCode::DelegationDenied,
                        format!("{} is not entitled to {} on {}; present a parent_token", issuer.id, def.id, r.id),
                    ));
                }
            }
        }
        Ok(())
    }

    fn revoke(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let rid = match a.payload().get("revocation_id") {
            Some(ParamValue::Text(t)) => t.trim().to_ascii_lowercase(),
            _ => return Err(exec(ExecCode::InvalidArgument, "missing revocation_id")),
        };
        if rid.len() != 128 || !rid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(exec(ExecCode::InvalidArgument, "revocation_id must be 128 hex digits"));
        }
        let actor = a.actor().clone();
        let privileged =
            self.identities.get(&actor).map(|p| p.roles.iter().any(|r| r == "owner" || r == "admin")).unwrap_or(false);
        // the issuer of the token or of any ancestor may revoke it
        let mut in_chain = false;
        let mut cursor = self.state.issued.get(&rid);
        let mut hops = 0;
        while let Some(r) = cursor {
            if r.issuer == actor {
                in_chain = true;
                break;
            }
            hops += 1;
            cursor = r.parent.as_ref().filter(|_| hops < 8).and_then(|p| self.state.issued.get(p));
        }
        if !(privileged || in_chain) {
            return Err(exec(
                ExecCode::NotPermitted,
                "only an issuer in the delegation chain, an owner or an admin may revoke this token",
            ));
        }
        let newly = self.state.revocations.revoke(&rid);
        if newly {
            self.state.epoch += 1;
            self.save_state();
            self.refresh_authority_view();
            let f = json!({"op": "revoke", "token": rid, "by": actor.to_string(), "epoch": self.state.epoch});
            self.audit_signed(now, "authority", obj(f));
            let data = payload([("op", "revoke".to_string()), ("token", rid.clone())]);
            self.publish(EventKind::AuthorityChanged, actor, data, Some(a.message_id_hex()), now);
        }
        Ok(json!({ "revoked": rid, "already_revoked": !newly }))
    }

    /// Raise a revocation floor (spec 05 "Revocation epochs"): every token issued
    /// before now that `principal` holds, issued or passed on dies at once —
    /// or, without a principal, every token of the domain. An owner or an
    /// admin may do this for anyone; everyone may do it for themselves.
    fn revoke_all(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let principal = match a.payload().get("principal") {
            Some(ParamValue::Text(t)) => {
                Some(EntityId::parse(t).map_err(|e| exec(ExecCode::InvalidArgument, e.to_string()))?)
            }
            None => None,
            Some(_) => return Err(exec(ExecCode::InvalidArgument, "principal must be text")),
        };
        let actor = a.actor().clone();
        let privileged =
            self.identities.get(&actor).map(|p| p.roles.iter().any(|r| r == "owner" || r == "admin")).unwrap_or(false);
        if !privileged && principal.as_ref() != Some(&actor) {
            return Err(exec(
                ExecCode::NotPermitted,
                "only an owner or an admin may revoke the tokens of others or of the whole domain; you may revoke your own",
            ));
        }
        self.state.epoch += 1;
        let floor = self.state.epoch;
        let raised = self.state.revocations.revoke_before(principal.as_ref(), floor);
        self.save_state();
        self.refresh_authority_view();
        let whom = principal.as_ref().map_or_else(|| chitala_token::EVERYONE.to_string(), ToString::to_string);
        let f = json!({"op": "revoke_all", "principal": whom, "floor": floor, "by": actor.to_string(), "epoch": self.state.epoch});
        self.audit_signed(now, "authority", obj(f));
        let data = payload([("op", "revoke_all".to_string()), ("principal", whom.clone())]);
        self.publish(EventKind::AuthorityChanged, actor, data, Some(a.message_id_hex()), now);
        Ok(json!({ "principal": whom, "floor": floor, "raised": raised }))
    }

    fn exec_hold(&mut self, a: &Authorized, place: bool) -> Result<Value, ExecError> {
        let p = a.payload();
        let resource = match p.get("resource") {
            Some(ParamValue::Text(t)) => {
                ResourceId::parse(t).map_err(|e| exec(ExecCode::InvalidArgument, e.to_string()))?
            }
            _ => return Err(exec(ExecCode::InvalidArgument, "missing resource")),
        };
        let by = a.actor().clone();
        if place {
            let reason = match p.get("reason") {
                Some(ParamValue::Text(t)) => t.clone(),
                _ => "safety hold".to_string(),
            };
            self.hold(&resource, &reason, &by).map_err(|e| exec(ExecCode::InvalidArgument, e.to_string()))?;
            Ok(json!({ "held": resource.to_string() }))
        } else {
            let was_held = self.safety.holds().any(|(r, _)| r == &resource);
            let was_recovering = self.safety.recovering().any(|(r, _)| r == &resource);
            self.release(&resource, &by);
            Ok(json!({ "released": resource.to_string(), "was_held": was_held, "was_recovering": was_recovering }))
        }
    }

    fn set_state(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let p = a.payload();
        let principal = match p.get("principal") {
            Some(ParamValue::Text(t)) => {
                EntityId::parse(t).map_err(|e| exec(ExecCode::InvalidArgument, e.to_string()))?
            }
            _ => return Err(exec(ExecCode::InvalidArgument, "missing principal")),
        };
        let to = match p.get("state") {
            Some(ParamValue::Text(t)) => SecurityState::ALL
                .iter()
                .copied()
                .find(|s| s.label().eq_ignore_ascii_case(t.trim()))
                .ok_or_else(|| exec(ExecCode::InvalidArgument, format!("unknown security state {t:?}")))?,
            _ => return Err(exec(ExecCode::InvalidArgument, "missing state")),
        };
        if &principal == a.actor() {
            return Err(exec(ExecCode::NotPermitted, "a principal cannot change its own security state"));
        }
        let from = self
            .identities
            .get(&principal)
            .map(|p| p.state)
            .ok_or_else(|| exec(ExecCode::InvalidArgument, format!("{principal} is not enrolled")))?;
        if !from.can_transition(to) {
            return Err(exec(ExecCode::InvalidArgument, format!("transition {from} → {to} is not allowed")));
        }
        let by = a.actor().clone();
        self.apply_state(&principal, from, to, &by, "manual", now);
        Ok(json!({ "principal": principal.to_string(), "from": from.label(), "to": to.label() }))
    }

    fn apply_state(
        &mut self,
        principal: &EntityId,
        from: SecurityState,
        to: SecurityState,
        by: &EntityId,
        reason: &str,
        now: u64,
    ) {
        if self.identities.set_state(principal, to).is_err() {
            return;
        }
        if to == SecurityState::Trusted {
            self.state.principal_states.remove(principal);
        } else {
            self.state.principal_states.insert(principal.clone(), to);
        }
        self.state.epoch += 1;
        self.save_state();
        self.refresh_authority_view();
        let f = json!({
            "principal": principal.to_string(),
            "from": from.label(),
            "to": to.label(),
            "by": by.to_string(),
            "reason": reason,
            "epoch": self.state.epoch,
        });
        self.audit_signed(now, "security_state", obj(f));
        let data = payload([
            ("from", from.label().to_string()),
            ("to", to.label().to_string()),
            ("by", by.to_string()),
            ("reason", reason.to_string()),
        ]);
        self.publish(EventKind::SecurityStateChanged, principal.clone(), data, None, now);
    }

    // ───────────────────────────── plumbing ─────────────────────────────

    /// A wall clock that went backwards is ignored by the trusted clock, but it
    /// is evidence (an attempt to revive expired tokens, a failing RTC): audit it.
    fn record_clock_regression(&mut self, now: u64) {
        let Some(behind) = self.clock_watch.as_ref().and_then(|c| c.take_regression()) else { return };
        let f = json!({"event": "wall_clock_regression", "behind_ms": behind, "kept_time_ms": now});
        self.audit_signed(now, "clock", obj(f));
    }

    /// Authority and security-state records are signed immediately: they are the
    /// evidence an investigator needs most (v16 §7).
    fn audit_signed(&mut self, now: u64, kind: &str, fields: Map<String, Value>) {
        if self.audit.append(now, kind, fields).is_ok() {
            let _ = self.audit.checkpoint(now);
        }
    }

    fn publish(&self, kind: EventKind, source: EntityId, data: Payload, caused_by: Option<String>, now: u64) {
        self.bus.publish(Event { id: random_id(&*self.entropy), kind, source, ts_ms: now, data, caused_by });
    }

    /// Publish the current revocations and the principals that can no longer
    /// act to the orders in flight (their fences).
    fn refresh_authority_view(&self) {
        let unable =
            self.identities.principals().filter(|p| !p.state.may_act()).map(|p| (p.id.clone(), p.state)).collect();
        let holds = self.safety.holds().map(|(r, _)| r.clone()).collect();
        let revoked_leases =
            self.state.leases.iter().filter(|(_, l)| l.revoked_by.is_some()).map(|(id, _)| id.clone()).collect();
        let recovering = self.safety.recovering().map(|(r, _)| r.clone()).collect();
        let cancelled_plans = self.cancelled_plans();
        if let Ok(mut v) = self.authority_view.write() {
            *v = AuthorityView {
                revocations: self.state.revocations.clone(),
                unable,
                holds,
                revoked_leases,
                recovering,
                cancelled_plans,
            };
        }
    }

    /// Persist authority state *before* the matching audit record is written: a
    /// crash in between leaves the state ahead of the log, which start-up
    /// accepts; the opposite order would look like a rollback.
    fn save_state(&mut self) {
        let _ = self.persist();
    }

    /// Write the state durably (the platform replaces the file atomically and
    /// syncs it, spec 18) and say whether it worked. A failure is audited.
    /// The write-ahead record of an action relies on it: an order leaves the
    /// node only after its record is durable (spec 22).
    fn persist(&mut self) -> Result<(), String> {
        self.state.audit_anchor = self.audit.anchor();
        let Some(stored) = &self.state_file else { return Ok(()) };
        let text = serde_json::to_vec_pretty(&self.state).expect("domain state serializes");
        stored.write_atomic(&text, Visibility::Private).map_err(|e| {
            let now = self.now();
            let f = json!({"event": "state_write_failed", "error": e.to_string()});
            let _ = self.audit.append(now, "node", obj(f));
            e.to_string()
        })
    }
}
