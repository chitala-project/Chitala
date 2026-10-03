//! Chitala core model (spec: `specs/01-core-model.md`, `specs/03-classification.md`).
//!
//! Everything in this crate is plain data: identifiers, the unified classification
//! scales, the capability registry and payload values. No I/O, no crypto.

#![forbid(unsafe_code)]

pub mod capability;
pub mod class;
pub mod deny;
pub mod device;
pub mod id;
pub mod value;

pub use capability::{
    CapabilityDef, CapabilityKind, CapabilityRegistry, ParamDef, ParamType, PayloadError, TargetKind,
};
pub use class::{
    AutonomyLevel, DataClass, HardwareProfile, MessageType, QosClass, RiskClass, SecurityClass, SecurityState,
};
pub use deny::{DenyCode, ExecCode};
pub use device::{DeviceDescriptor, Event, EventKind};
pub use id::{CapabilityId, EntityId, EntityKind, IdError};
pub use value::{payload, ParamValue, Payload};
