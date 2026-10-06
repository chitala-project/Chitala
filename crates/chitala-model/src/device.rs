//! Device descriptors (minimal Entity Manifest for v0.1) and events.

use serde::{Deserialize, Serialize};

use crate::class::SecurityClass;
use crate::id::{CapabilityId, EntityId};
use crate::value::Payload;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDescriptor {
    pub id: EntityId,
    pub name: String,
    /// Adapter that owns the device (`mock`, `home-assistant`, ...).
    pub adapter: String,
    pub capabilities: Vec<CapabilityId>,
    pub security_class: SecurityClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
}

impl DeviceDescriptor {
    pub fn supports(&self, cap: &CapabilityId) -> bool {
        self.capabilities.contains(cap)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    StateChanged,
    SecurityDenied,
    AdapterError,
    /// A token was issued or revoked.
    AuthorityChanged,
    /// A principal moved in the security state machine.
    SecurityStateChanged,
    /// An intent needs a human decision (spec §16 APPROVAL).
    ApprovalRequested,
    /// A human answered (or the question expired).
    ApprovalAnswered,
    /// A safety hold was placed on a resource or released, or a resource
    /// entered or left recovery.
    SafetyChanged,
    /// The outcome of an action was settled: verified against the world, or
    /// not (spec 22).
    Outcome,
    /// A plan moved: a step finished, it is waiting for a person, or it ended
    /// (spec 23).
    Plan,
    /// A device's observed state: published when an observation changed it,
    /// or when the device can be observed again. `data` is the whole
    /// reported state; `ts_ms` is when its source produced it (spec 29).
    Observed,
    /// A device can no longer be observed, from `ts_ms` (spec 29).
    Unobservable,
}

impl EventKind {
    /// Security-relevant events are kept when an event queue overflows
    /// (v16 §27: bounded buffers must prefer security/safety evidence).
    pub fn is_security(self) -> bool {
        matches!(
            self,
            EventKind::SecurityDenied
                | EventKind::AuthorityChanged
                | EventKind::SecurityStateChanged
                | EventKind::ApprovalRequested
                | EventKind::ApprovalAnswered
                | EventKind::SafetyChanged
                | EventKind::Outcome
                | EventKind::Plan
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Hex-encoded 16-byte id.
    pub id: String,
    pub kind: EventKind,
    pub source: EntityId,
    pub ts_ms: u64,
    #[serde(default)]
    pub data: Payload,
    /// Hex message id of the CSME envelope that caused this event, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caused_by: Option<String>,
}
