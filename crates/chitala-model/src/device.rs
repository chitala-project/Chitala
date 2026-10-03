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
}

impl EventKind {
    /// Security-relevant events are kept when an event queue overflows
    /// (v16 §27: bounded buffers must prefer security/safety evidence).
    pub fn is_security(self) -> bool {
        matches!(self, EventKind::SecurityDenied | EventKind::AuthorityChanged | EventKind::SecurityStateChanged)
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
