//! Device adapters and the adapter host (Blueprint A.3, v8 §3 & §12, v17 §6–8).
//!
//! Adapters translate canonical capabilities into a concrete device or protocol.
//! They run **outside the trusted-core process**, in an adapter host
//! ([`host`]), and act only on [`VerifiedOrder`]s: execution orders signed by the
//! Trusted Execution Boundary's order key, addressed to this host instance,
//! fresh and never seen before (spec 19). The only way to obtain a
//! `VerifiedOrder` is [`OrderGate::admit`], and an adapter consumes it when it
//! executes it. A crashing, hanging or compromised
//! adapter therefore cannot reach the Reference Monitor, and cannot act on
//! anything the monitor did not allow (Blueprint A.3 "an adapter crash must not
//! bring down the Authority/Safety Core"; v8 §12 device-side enforcement).
//!
//! - [`mock::MockAdapter`]: virtual light / switch / thermostat / lock with fault
//!   injection and device-side invariants (mock-first development, v17 §7).
//! - [`home_assistant::HomeAssistantAdapter`]: REST bridge to an existing Home
//!   Assistant installation; its devices are legacy-class (v5 §11).
//! - [`profile::HomeProfile`]: the Home Capability Profile (spec 24), the
//!   normalised state and the Home Assistant and Matter mappings of lights,
//!   plugs and locks.

#![forbid(unsafe_code)]

#[cfg(feature = "conformance")]
pub mod conformance;
#[cfg(any(feature = "home-assistant", feature = "direct-matter"))]
mod device_read;
pub mod direct_matter;
#[cfg(all(feature = "home-assistant", any(test, feature = "fake-ha")))]
pub mod fake_ha;
#[cfg(all(feature = "home-assistant", any(test, feature = "fake-ha")))]
pub mod fake_matter;
pub mod home_assistant;
pub mod host;
pub mod mock;
pub mod profile;

use std::collections::HashMap;
use std::sync::Arc;

use chitala_csme::order::{message_digest, Digest32, ExecOrder, MAX_ORDER_LIFETIME_MS};
use chitala_identity::PublicKey;
use chitala_model::{CapabilityId, EntityId, ExecCode, Payload};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdapterError {
    /// Device offline or unreachable → `X_DEVICE_UNAVAILABLE`.
    #[error("device unavailable: {0}")]
    Unavailable(String),
    /// The device refused through a local invariant (Constitution C5) → `X_DEVICE_REFUSED`.
    #[error("device refused: {0}")]
    Refused(String),
    /// The order was not admitted: bad signature, stale or replayed → `X_ORDER_REJECTED`.
    #[error("order rejected: {0}")]
    Rejected(String),
    /// Adapter cannot map the request or the device failed → `X_ADAPTER`.
    #[error("adapter error: {0}")]
    Failed(String),
    /// The command may have executed and the adapter cannot tell: it was
    /// delivered, then the answer was lost → `X_EXECUTION_UNKNOWN`. Never
    /// resent; Chitala observes the world to decide (spec 22).
    #[error("execution unknown: {0}")]
    Indeterminate(String),
}

impl AdapterError {
    pub fn code(&self) -> ExecCode {
        match self {
            AdapterError::Unavailable(_) => ExecCode::DeviceUnavailable,
            AdapterError::Refused(_) => ExecCode::DeviceRefused,
            AdapterError::Rejected(_) => ExecCode::OrderRejected,
            AdapterError::Failed(_) => ExecCode::Adapter,
            AdapterError::Indeterminate(_) => ExecCode::ExecutionUnknown,
        }
    }

    /// Rebuild from a wire code (adapter host → node). Unknown codes are failures.
    pub fn from_code(code: &str, message: String) -> Self {
        match code {
            "X_DEVICE_UNAVAILABLE" => AdapterError::Unavailable(message),
            "X_DEVICE_REFUSED" => AdapterError::Refused(message),
            "X_ORDER_REJECTED" => AdapterError::Rejected(message),
            "X_EXECUTION_UNKNOWN" => AdapterError::Indeterminate(message),
            _ => AdapterError::Failed(message),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            AdapterError::Unavailable(m)
            | AdapterError::Refused(m)
            | AdapterError::Rejected(m)
            | AdapterError::Failed(m)
            | AdapterError::Indeterminate(m) => m,
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
    /// While stuck, the device reports every action as done but nothing
    /// physically changes (a jammed bolt, a lying adapter): only observing it
    /// again shows the truth (spec 22).
    Stuck(bool),
    /// The next action takes effect only at the n-th observation after it (a
    /// slow actuator); until then the device reports its old state.
    Lag(u32),
}

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// An execution order that passed the gate. No public constructor, not
/// `Clone`: an adapter consumes it when it executes it.
#[derive(Debug)]
pub struct VerifiedOrder {
    order: ExecOrder,
    digest: Digest32,
}

impl VerifiedOrder {
    pub fn id(&self) -> &[u8; 16] {
        &self.order.id
    }
    pub fn actor(&self) -> &EntityId {
        &self.order.actor
    }
    /// The device the order is for.
    pub fn target(&self) -> &EntityId {
        &self.order.device
    }
    pub fn capability(&self) -> &CapabilityId {
        &self.order.capability
    }
    pub fn payload(&self) -> &Payload {
        &self.order.params
    }
    pub fn order(&self) -> &ExecOrder {
        &self.order
    }
    /// SHA-256 of the order bytes as admitted.
    pub fn digest(&self) -> &Digest32 {
        &self.digest
    }
}

/// Tolerated clock skew between node and adapter host.
pub const ORDER_SKEW_MS: u64 = 5_000;
/// Upper bound on remembered order ids.
pub const MAX_SEEN_ORDERS: usize = 10_000;

/// Admits execution orders: the boundary's order key, this host's executor
/// session, parameters matching their digest, freshness, single use.
pub struct OrderGate {
    order_key: PublicKey,
    executor: [u8; 16],
    clock: Clock,
    seen: HashMap<[u8; 16], u64>,
}

impl OrderGate {
    /// A gate for one adapter host instance: `executor` is the session the
    /// node gave this instance, so orders for any other instance — another
    /// host, or this host before a restart — are refused.
    pub fn new(order_key: PublicKey, executor: [u8; 16], clock: Clock) -> Self {
        Self { order_key, executor, clock, seen: HashMap::new() }
    }

    pub fn executor(&self) -> &[u8; 16] {
        &self.executor
    }

    pub fn clock(&self) -> Clock {
        Arc::clone(&self.clock)
    }

    pub fn admit(&mut self, bytes: &[u8]) -> Result<VerifiedOrder, AdapterError> {
        let order = ExecOrder::open(bytes, &self.order_key)
            .map_err(|e| AdapterError::Rejected(format!("{}: {}", e.code, e.reason)))?;
        if order.executor != self.executor {
            return Err(AdapterError::Rejected("order is for another adapter host instance".into()));
        }
        let now = (self.clock)();
        if order.issued_at_ms > now.saturating_add(ORDER_SKEW_MS) {
            return Err(AdapterError::Rejected("order is from the future".into()));
        }
        if now >= order.expires_at_ms || order.expires_at_ms <= order.issued_at_ms {
            return Err(AdapterError::Rejected("order has expired".into()));
        }
        if order.expires_at_ms - order.issued_at_ms > MAX_ORDER_LIFETIME_MS {
            return Err(AdapterError::Rejected("order lifetime too long".into()));
        }
        if self.seen.contains_key(&order.id) {
            return Err(AdapterError::Rejected("order already executed".into()));
        }
        if self.seen.len() >= MAX_SEEN_ORDERS {
            self.seen.retain(|_, until| *until > now);
            if self.seen.len() >= MAX_SEEN_ORDERS {
                return Err(AdapterError::Rejected("too many outstanding orders".into()));
            }
        }
        self.seen.insert(order.id, order.expires_at_ms.saturating_add(ORDER_SKEW_MS));
        Ok(VerifiedOrder { order, digest: message_digest(bytes) })
    }
}

/// A state as an adapter observed it, with how old it is (v0.3 step ③A,
/// finding F9). A state can be read now and still be minutes old: Home
/// Assistant goes on serving a dead device's last state. Only a state its
/// source produced after an order can tell what the order did (spec 22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub state: Payload,
    /// How long before this answer the state's source produced it: 0 for a
    /// device read now; for a state a backend keeps, the time since the
    /// backend last heard it from the device. `None` when nobody can tell.
    pub age_ms: Option<u64>,
    /// Whether the state is tied to the device itself, now.
    pub provenance: Provenance,
}

/// Whether an adapter established that a state is its device's current one
/// (v0.3 step ③A, finding F9b). A gateway's timestamp is not physical
/// freshness: Home Assistant re-emits a dead device's cached value with a new
/// one. Only a confirmed state can tell what an order did (spec 22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// The adapter reached the device this long before its answer, and no
    /// earlier than the state was produced: a read from the device itself, or
    /// an exchange with it after its backend reported the state.
    ConfirmedCurrent { age_ms: u64 },
    /// Nothing ties the state to the device now.
    Uncertain,
}

impl Observed {
    /// A state read from the device itself, now.
    pub fn live(state: Payload) -> Self {
        Self { state, age_ms: Some(0), provenance: Provenance::ConfirmedCurrent { age_ms: 0 } }
    }

    /// A state of unknown age: history, never evidence of what an order did.
    pub fn of_unknown_age(state: Payload) -> Self {
        Self { state, age_ms: None, provenance: Provenance::Uncertain }
    }
}

pub trait DeviceAdapter: Send {
    /// Adapter name as used in device descriptors (`mock`, `home-assistant`).
    fn name(&self) -> &str;

    /// Whether this adapter manages `device`.
    fn manages(&self, device: &EntityId) -> bool;

    /// Current state as the device reports it, and how old it is.
    fn observe(&mut self, device: &EntityId) -> Result<Observed, AdapterError>;

    /// [`DeviceAdapter::observe`] for evidence of what an order did (spec 22):
    /// the adapter also tries to confirm that the state is the device's
    /// current one ([`Provenance`]), which may take an exchange with the
    /// device. By default, the plain observation.
    fn observe_evidence(&mut self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.observe(device)
    }

    /// Execute an admitted order, consuming it; returns the device's new
    /// reported state.
    fn execute(&mut self, order: VerifiedOrder) -> Result<Payload, AdapterError>;

    /// Apply a simulated change. Only virtual adapters support this.
    fn simulate(&mut self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        let _ = (device, change);
        Err(AdapterError::Failed(format!("adapter {} does not support simulation", self.name())))
    }
}

/// Test helpers: real signed orders through a real gate.
#[cfg(test)]
pub(crate) mod testkit {
    use std::sync::atomic::{AtomicU64, Ordering};

    use chitala_csme::order::payload_digest;
    use chitala_identity::{test_seed, Keypair};

    use super::*;

    pub const NOW: u64 = 1_790_000_000_000;
    /// The executor session of the test host.
    pub const SESSION: [u8; 16] = [0x5e; 16];

    /// Stands in for the boundary's order key.
    pub fn order_key() -> Keypair {
        Keypair::from_seed(&test_seed("boundary"))
    }

    pub fn fixed_clock(ms: u64) -> (Clock, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(ms));
        let c = Arc::clone(&t);
        (Arc::new(move || c.load(Ordering::SeqCst)), t)
    }

    static COUNTER: AtomicU64 = AtomicU64::new(1);

    pub fn order(device: &EntityId, capability: &str, params: Payload) -> ExecOrder {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&n.to_be_bytes());
        ExecOrder {
            id,
            executor: SESSION,
            subject: [1; 16],
            subject_digest: [2; 32],
            actor: EntityId::parse("person:alice").unwrap(),
            resource: EntityId::parse(&format!("resource:{}", device.local())).unwrap(),
            device: device.clone(),
            capability: CapabilityId::parse(capability).unwrap(),
            capability_version: 1,
            params_digest: payload_digest(&params),
            params,
            context_digest: [3; 32],
            epoch: 1,
            evidence_seq: 1,
            cleared_at_ms: NOW,
            issued_at_ms: NOW,
            expires_at_ms: NOW + 10_000,
        }
    }

    /// Sign with the order key and admit through a gate.
    pub fn authorize(device: &EntityId, capability: &str, payload: Payload) -> VerifiedOrder {
        let (clock, _) = fixed_clock(NOW);
        OrderGate::new(order_key().public_key(), SESSION, clock)
            .admit(&order(device, capability, payload).sign(&order_key()))
            .expect("test order is admitted")
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use chitala_identity::{test_seed, Keypair};

    fn light() -> EntityId {
        EntityId::parse("device:light").unwrap()
    }

    #[test]
    fn gate_admits_only_fresh_single_use_orders_for_this_instance() {
        let (clock, time) = fixed_clock(NOW);
        let mut gate = OrderGate::new(order_key().public_key(), SESSION, clock);
        let bytes = order(&light(), "light.turn_on", Payload::new()).sign(&order_key());
        let admitted = gate.admit(&bytes).unwrap();
        assert_eq!(admitted.digest(), &message_digest(&bytes));
        // replay
        assert!(matches!(gate.admit(&bytes), Err(AdapterError::Rejected(m)) if m.contains("already")));
        // signed by anyone but the boundary — even the node identity or an owner of the domain
        for k in ["service:node", "person:alice"] {
            let forged = order(&light(), "light.turn_on", Payload::new()).sign(&Keypair::from_seed(&test_seed(k)));
            assert!(matches!(gate.admit(&forged), Err(AdapterError::Rejected(_))), "{k}");
        }
        // for another adapter host instance (another host, or this one before a restart)
        let mut elsewhere = order(&light(), "light.turn_on", Payload::new());
        elsewhere.executor = [0x77; 16];
        assert!(
            matches!(gate.admit(&elsewhere.sign(&order_key())), Err(AdapterError::Rejected(m)) if m.contains("instance"))
        );
        // too long-lived
        let mut long = order(&light(), "light.turn_on", Payload::new());
        long.expires_at_ms = NOW + MAX_ORDER_LIFETIME_MS + 1;
        assert!(gate.admit(&long.sign(&order_key())).is_err());
        // stale: executed late (v15 §7)
        let late = order(&light(), "light.turn_on", Payload::new()).sign(&order_key());
        time.store(NOW + 10_000, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(gate.admit(&late), Err(AdapterError::Rejected(m)) if m.contains("expired")));
        assert!(gate.admit(b"garbage").is_err());
    }

    #[test]
    fn error_codes_round_trip() {
        for e in [
            AdapterError::Unavailable("a".into()),
            AdapterError::Refused("b".into()),
            AdapterError::Rejected("c".into()),
            AdapterError::Failed("d".into()),
        ] {
            assert_eq!(AdapterError::from_code(e.code().as_str(), e.message().to_string()), e);
        }
        assert_eq!(AdapterError::from_code("X_WHATEVER", "m".into()), AdapterError::Failed("m".into()));
    }
}
