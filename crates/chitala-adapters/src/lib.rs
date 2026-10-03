//! Device adapters (Blueprint v17 §6–8, v10 §11).
//!
//! An adapter translates canonical capabilities into a concrete device or
//! protocol. Adapters are *below* the Reference Monitor: [`DeviceAdapter::execute`]
//! only accepts a [`chitala_monitor::Authorized`], which nothing but the monitor can
//! create. Connecting a device never grants authority (v17 §6).
//!
//! - [`mock::MockAdapter`]: virtual light / switch / thermostat / lock with fault
//!   injection and device-side invariants (mock-first development, v17 §7).
//! - [`home_assistant::HomeAssistantAdapter`]: REST bridge to an existing Home
//!   Assistant installation; its devices are legacy-class and sit behind the
//!   gateway (v5 §11).

#![forbid(unsafe_code)]

pub mod home_assistant;
pub mod mock;

use chitala_model::{EntityId, ExecCode, Payload};
use chitala_monitor::Authorized;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdapterError {
    /// Device offline or unreachable → `X_DEVICE_UNAVAILABLE`.
    #[error("device unavailable: {0}")]
    Unavailable(String),
    /// The device refused through a local invariant (Constitution C5) → `X_DEVICE_REFUSED`.
    #[error("device refused: {0}")]
    Refused(String),
    /// Adapter cannot map the request or the device failed → `X_ADAPTER`.
    #[error("adapter error: {0}")]
    Failed(String),
}

impl AdapterError {
    pub fn code(&self) -> ExecCode {
        match self {
            AdapterError::Unavailable(_) => ExecCode::DeviceUnavailable,
            AdapterError::Refused(_) => ExecCode::DeviceRefused,
            AdapterError::Failed(_) => ExecCode::Adapter,
        }
    }
}

/// Physical-world changes and faults for virtual devices (v17 §7 fault injection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Simulation {
    Offline(bool),
    DoorOpen(bool),
    /// The next `execute` fails with this error.
    FailNext(AdapterError),
}

pub trait DeviceAdapter: Send {
    /// Adapter name as used in device descriptors (`mock`, `home-assistant`).
    fn name(&self) -> &str;

    /// Whether this adapter manages `device`.
    fn manages(&self, device: &EntityId) -> bool;

    /// Current state as the device reports it.
    fn observe(&mut self, device: &EntityId) -> Result<Payload, AdapterError>;

    /// Execute an allowed action; returns the device's new reported state.
    fn execute(&mut self, action: &Authorized) -> Result<Payload, AdapterError>;

    /// Apply a simulated change. Only virtual adapters support this.
    fn simulate(&mut self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        let _ = (device, change);
        Err(AdapterError::Failed(format!("adapter {} does not support simulation", self.name())))
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Obtaining an `Authorized` in tests requires running the real monitor.

    use chitala_identity::{test_seed, IdentityRegistry, Keypair};
    use chitala_model::{
        CapabilityId, CapabilityRegistry, EntityId, MessageType, Payload, SecurityClass, SecurityState, TargetKind,
    };
    use chitala_monitor::{Authorized, Decision, Monitor, MonitorConfig, TargetInfo, Targets, World};
    use chitala_policy::{DeviceAttrs, PolicyEngine};
    use chitala_token::{RevocationList, TokenAuthority};

    struct One(TargetInfo);
    impl Targets for One {
        fn target(&self, id: &EntityId) -> Option<TargetInfo> {
            (id == &self.0.id).then(|| self.0.clone())
        }
    }

    /// Have the owner ask the monitor for `capability` on `device`.
    pub fn authorize(
        device: &EntityId,
        capabilities: &[CapabilityId],
        capability: &str,
        payload: Payload,
    ) -> Authorized {
        let registry = CapabilityRegistry::core_v0_1();
        let mut ids = IdentityRegistry::new();
        let owner = Keypair::from_seed(&test_seed("person:alice"));
        ids.enroll(EntityId::parse("person:alice").unwrap(), owner.public_key(), &["owner"]).unwrap();
        let targets = One(TargetInfo {
            id: device.clone(),
            kind: TargetKind::Device,
            capabilities: capabilities.to_vec(),
            device: Some(DeviceAttrs { security_class: SecurityClass::Sc2, room: None, state: SecurityState::Trusted }),
        });
        let tokens = TokenAuthority::new(&Keypair::from_seed(&test_seed("authority"))).verifier();
        let policy = PolicyEngine::with_default_policies(&registry).unwrap();
        let revocations = RevocationList::new();
        let cap = CapabilityId::parse(capability).unwrap();
        let def = registry.get(&cap).unwrap();
        let now = 1_790_000_000_000;
        let msg = chitala_csme::Csme {
            message_id: chitala_csme::new_message_id(),
            correlation_id: None,
            source: EntityId::parse("service:test").unwrap(),
            destination: device.clone(),
            actor: EntityId::parse("person:alice").unwrap(),
            capability: cap,
            capability_version: def.version,
            message_type: MessageType::Command,
            issued_at_ms: now,
            expires_at_ms: now + 10_000,
            context_ref: None,
            authority: None,
            risk: def.risk,
            payload,
        };
        let world = World {
            identities: &ids,
            registry: &registry,
            targets: &targets,
            tokens: &tokens,
            revocations: &revocations,
            policy: &policy,
            now_ms: now,
        };
        match Monitor::new(MonitorConfig::default()).check(&world, &msg.sign(&owner)) {
            Decision::Allow(a) => *a,
            Decision::Deny(d) => panic!("test request denied: {} {}", d.code, d.reason),
        }
    }
}
