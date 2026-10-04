//! Authority for a safe-state action after a failed outcome (spec 22).
//!
//! When an action's outcome fails, the node may bring the resource back to
//! the safe state its owners declared in the domain configuration, once and
//! without anyone asking (Project Lead decision, 2026-10-04). That is still
//! authority, so it comes from here, the Authority Engine, as a
//! [`RecoveryGrant`] with no public constructor; the trusted boundary demands
//! it together with a Safety clearance, like every other physical action.
//!
//! The engine grants exactly the declared safe state and nothing else:
//!
//! - the resource exists and declares a safe state;
//! - the action is bound there to a device and is a registered device action
//!   with valid parameters;
//! - its effective risk is at most medium (registry risk raised by the
//!   binding's floor): an action that needs a human, such as unlocking, is
//!   never run this way;
//! - the actor is the node itself (a service principal), never an AI or a
//!   person.
//!
//! The node runs it at most once per failed outcome, and the failure of a
//! safe-state action never leads to another.

use chitala_model::{
    CapabilityDef, CapabilityKind, CapabilityRegistry, EntityId, EntityKind, ParamValue, Payload, RiskClass, TargetKind,
};
use chitala_resource::{ResourceGraph, ResourceId};
use sha2::{Digest as _, Sha256};

/// Domain separation of [`RecoveryGrant::digest`].
const DIGEST_DOMAIN: &[u8] = b"chitala-recovery-v1\x00";

/// What the node asks for: the safe state of `resource`, because the outcome
/// recorded at audit sequence `trigger` failed.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryRequest<'a> {
    pub graph: &'a ResourceGraph,
    pub registry: &'a CapabilityRegistry,
    pub resource: &'a ResourceId,
    /// The node: a service principal.
    pub actor: &'a EntityId,
    /// A fresh random id for this recovery; the order's subject.
    pub subject: [u8; 16],
    /// Audit sequence number of the failed outcome.
    pub trigger: u64,
    pub now_ms: u64,
}

/// Proof that the Authority Engine authorized one resource's safe-state
/// action. Neither `Clone` nor constructible outside this crate.
#[derive(Debug)]
pub struct RecoveryGrant {
    subject: [u8; 16],
    digest: [u8; 32],
    actor: EntityId,
    resource: ResourceId,
    owners: Vec<EntityId>,
    def: CapabilityDef,
    params: Payload,
    device: EntityId,
    risk: RiskClass,
    trigger: u64,
    decided_at_ms: u64,
}

impl RecoveryGrant {
    pub fn subject(&self) -> &[u8; 16] {
        &self.subject
    }
    /// SHA-256 over the subject, resource, action, parameters and trigger.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn actor(&self) -> &EntityId {
        &self.actor
    }
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }
    /// The owners who declared the safe state (the resource's effective owners).
    pub fn owners(&self) -> &[EntityId] {
        &self.owners
    }
    pub fn def(&self) -> &CapabilityDef {
        &self.def
    }
    pub fn params(&self) -> &Payload {
        &self.params
    }
    pub fn device(&self) -> &EntityId {
        &self.device
    }
    pub fn risk(&self) -> RiskClass {
        self.risk
    }
    /// Audit sequence number of the failed outcome that led here.
    pub fn trigger(&self) -> u64 {
        self.trigger
    }
    pub fn decided_at_ms(&self) -> u64 {
        self.decided_at_ms
    }
}

/// Grant the declared safe state of one resource, or say why not.
pub fn authorize_recovery(req: RecoveryRequest<'_>) -> Result<RecoveryGrant, String> {
    if req.actor.kind() != EntityKind::Service {
        return Err(format!("{} is not the node: only Chitala itself runs a safe state unasked", req.actor));
    }
    let r = req.graph.get(req.resource).ok_or_else(|| format!("{} is not a governed resource", req.resource))?;
    let safe = r.safe_state.as_ref().ok_or_else(|| format!("{} declares no safe state", req.resource))?;
    let binding = r.binding(&safe.capability).ok_or_else(|| format!("{} is not bound at {}", safe.capability, r.id))?;
    let def = req.registry.get(&safe.capability).ok_or_else(|| format!("{} is not registered", safe.capability))?;
    if def.kind != CapabilityKind::Action || def.target != TargetKind::Device {
        return Err(format!("{} is not a device action", def.id));
    }
    def.validate(&safe.params).map_err(|e| format!("safe state {}: {e}", def.id))?;
    let risk = binding.risk_floor.map_or(def.risk, |f| f.max(def.risk));
    if risk > RiskClass::Medium {
        return Err(format!("{} is {risk} risk at {}: a person must decide it", def.id, r.id));
    }
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update(req.subject);
    let mut field = |tag: u8, bytes: &[u8]| {
        h.update([tag]);
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    };
    field(b'r', r.id.to_string().as_bytes());
    field(b'c', def.id.as_str().as_bytes());
    for (k, v) in &safe.params {
        field(b'k', k.as_bytes());
        match v {
            ParamValue::Bool(b) => field(b'b', &[u8::from(*b)]),
            ParamValue::Int(i) => field(b'i', &i.to_be_bytes()),
            ParamValue::Text(t) => field(b't', t.as_bytes()),
        }
    }
    field(b'#', &req.trigger.to_be_bytes());
    Ok(RecoveryGrant {
        subject: req.subject,
        digest: h.finalize().into(),
        actor: req.actor.clone(),
        resource: r.id.clone(),
        owners: req.graph.effective_owners(&r.id).to_vec(),
        def: def.clone(),
        params: safe.params.clone(),
        device: binding.device.clone(),
        risk,
        trigger: req.trigger,
        decided_at_ms: req.now_ms,
    })
}
