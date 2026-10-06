//! The direct Matter adapter (v0.3 step ⑤, spec 27). Chitala governs Matter
//! devices on its own fabric, not through Home Assistant:
//!
//! - Chitala owns the fabric;
//! - a Matter controller implements the protocol ([`DirectMatterBackend`]:
//!   matter.js now, pure Rust later);
//! - this adapter, in the Rust adapter host, owns Chitala's semantics: which
//!   command a capability is, what a state is, what an answer says about an
//!   order, and when a state is tied to the device;
//! - the Trusted Core does not change.
//!
//! **Observing.** A plain observation is the subscription's: the values the
//! device reported, as old as the last time it was heard (a report, or a
//! keep-alive saying nothing changed). It is not evidence of what an order
//! did. For evidence, the device is read itself: its values, confirmed as of
//! when the read began (as for Matter devices behind Home Assistant, F10).
//!
//! **Executing.** The profile maps the capability to a cluster command, sent
//! once, as a Timed Invoke when the profile says so. What the answer says:
//!
//! | The backend says | The order |
//! |---|---|
//! | success | done: the device's state read right after is returned. If it cannot be read, the fate is unknown |
//! | not sent: no session, or no answer to a read just before | certainly not executed (`X_DEVICE_UNAVAILABLE`) |
//! | a status the device gives before acting: access, busy, invalid in state | refused (`X_DEVICE_REFUSED`), certainly not executed |
//! | a status for a command it cannot take: unsupported, invalid, constraint, timed interaction needed | not executed (`X_ADAPTER`) |
//! | `FAILURE`, `TIMEOUT`, any other status | unknown: a lock that jams moved part way (`X_EXECUTION_UNKNOWN`) |
//! | no answer | unknown (`X_EXECUTION_UNKNOWN`) |
//!
//! Nothing is ever sent twice.

pub mod backend;
#[cfg(any(test, feature = "conformance"))]
pub mod fake;

use std::collections::BTreeMap;
use std::sync::Arc;

use chitala_model::{CapabilityId, DeviceDescriptor, EntityId, Payload};

use crate::device_read::{DeviceRead, READ_WAIT};
use crate::profile::{DeviceClass, HomeProfile};
use crate::{AdapterError, DeviceAdapter, Observed, Provenance, VerifiedOrder};
pub use backend::{DirectMatterBackend, InvokeError, ProfileAttribute, ProfileCommand, Subscribed, Target, Values};

/// The adapter's name in device descriptors.
pub const ADAPTER: &str = "matter";

/// A device and where it is on Chitala's fabric.
struct Bound {
    target: Target,
    class: &'static DeviceClass,
}

pub struct DirectMatterAdapter {
    backend: Arc<dyn DirectMatterBackend>,
    devices: BTreeMap<EntityId, Bound>,
    reads: BTreeMap<Target, DeviceRead<Values>>,
}

impl std::fmt::Debug for DirectMatterAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let devices: BTreeMap<_, _> = self.devices.iter().map(|(d, b)| (d, (b.target, &b.class.class))).collect();
        f.debug_struct("DirectMatterAdapter").field("devices", &devices).finish_non_exhaustive()
    }
}

/// The Home profile class whose capabilities a device's are, each one
/// mapped to a Matter command (reading the state needs none).
pub fn class_of(device: &DeviceDescriptor) -> Result<&'static DeviceClass, AdapterError> {
    let acts: Vec<&CapabilityId> = device.capabilities.iter().filter(|c| c.as_str() != "device.read_state").collect();
    let class = HomeProfile::v0_1()
        .classes()
        .iter()
        .find(|c| !acts.is_empty() && acts.iter().all(|a| c.capabilities().any(|k| k == *a)))
        .ok_or_else(|| AdapterError::Failed(format!("{}: no Home profile class has these capabilities", device.id)))?;
    if let Some(a) = acts.iter().find(|a| !class.matter.commands.contains_key(**a)) {
        return Err(AdapterError::Failed(format!(
            "{}: the Home profile maps no Matter command for {a} ({} devices)",
            device.id, class.class
        )));
    }
    Ok(class)
}

impl DirectMatterAdapter {
    /// The adapter for `devices`, each at its target, on `backend`. Every
    /// device is subscribed to the attributes its class maps.
    pub fn new(
        backend: Arc<dyn DirectMatterBackend>,
        devices: &[(DeviceDescriptor, Target)],
    ) -> Result<Self, AdapterError> {
        let mut bound = BTreeMap::new();
        for (d, target) in devices {
            let class = class_of(d)?;
            backend
                .subscribe(*target, &ProfileAttribute::of_class(class))
                .map_err(|e| AdapterError::Failed(format!("{}: cannot subscribe to {target}: {e}", d.id)))?;
            bound.insert(d.id.clone(), Bound { target: *target, class });
        }
        Ok(Self { backend, devices: bound, reads: BTreeMap::new() })
    }

    fn bound(&self, device: &EntityId) -> Result<(Target, &'static DeviceClass), AdapterError> {
        self.devices
            .get(device)
            .map(|b| (b.target, b.class))
            .ok_or_else(|| AdapterError::Failed(format!("{device} is not a Matter device of this adapter")))
    }
}

fn ms(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// What a status the device answered says about the order (Matter Core
/// specification, Interaction Model status codes).
pub fn status_error(status: u8, cluster_status: Option<u8>) -> AdapterError {
    let what = match cluster_status {
        Some(c) => format!("status 0x{status:02X}, cluster status 0x{c:02X}"),
        None => format!("status 0x{status:02X}"),
    };
    match status {
        // the device would not act: access, busy, not in a state to
        0x7E | 0x9C | 0x9D | 0xCB => AdapterError::Refused(format!("the device refused it ({what}); it did not run")),
        // the device cannot take this command as sent
        0x7F | 0x80 | 0x81 | 0x85 | 0x87 | 0x89 | 0x9B | 0xC3 | 0xC6 | 0xC9 | 0xCA => {
            AdapterError::Failed(format!("the device could not take it ({what}); it did not run"))
        }
        // FAILURE, TIMEOUT and the rest: it may have done part of it
        _ => AdapterError::Indeterminate(format!("the device answered failure ({what}); it may have acted")),
    }
}

impl DeviceAdapter for DirectMatterAdapter {
    fn name(&self) -> &str {
        ADAPTER
    }

    fn manages(&self, device: &EntityId) -> bool {
        self.devices.contains_key(device)
    }

    /// The subscription's state, as old as the last time the device was
    /// heard. Not evidence: only a read is ([`Self::observe_evidence`]).
    fn observe(&mut self, device: &EntityId) -> Result<Observed, AdapterError> {
        let (target, class) = self.bound(device)?;
        let s =
            self.backend.subscribed(target).filter(|s| s.live).ok_or_else(|| {
                AdapterError::Unavailable(format!("{device}: the device cannot be reached ({target})"))
            })?;
        let state = class.matter_state(&backend::raw(&s.values))?;
        Ok(Observed { state, age_ms: Some(ms(s.last_heard.elapsed())), provenance: Provenance::Uncertain })
    }

    /// The device read itself: its state, confirmed as of when the read
    /// began. A read waits up to [`READ_WAIT`] and goes on in the background;
    /// until one comes back, the subscription's state, unconfirmed.
    fn observe_evidence(&mut self, device: &EntityId) -> Result<Observed, AdapterError> {
        let (target, class) = self.bound(device)?;
        let backend = Arc::clone(&self.backend);
        let attributes = ProfileAttribute::of_class(class);
        let read = self.reads.entry(target).or_default().take(READ_WAIT, move || backend.read(target, &attributes));
        if let Some((began, values)) = read {
            if let Ok(state) = class.matter_state(&backend::raw(&values)) {
                let age_ms = ms(began.elapsed());
                return Ok(Observed {
                    state,
                    age_ms: Some(age_ms),
                    provenance: Provenance::ConfirmedCurrent { age_ms },
                });
            }
        }
        self.observe(device)
    }

    fn execute(&mut self, order: VerifiedOrder) -> Result<Payload, AdapterError> {
        let device = order.target().clone();
        let (target, class) = self.bound(&device)?;
        let command = ProfileCommand::of(class, order.capability()).ok_or_else(|| {
            AdapterError::Failed(format!("the Home profile maps no Matter command for {}", order.capability()))
        })?;
        if !order.payload().is_empty() {
            return Err(AdapterError::Failed(format!(
                "{} takes no parameters through the direct Matter adapter yet; nothing was sent",
                order.capability()
            )));
        }
        // the order is spent here: whatever happens, it is never sent again
        drop(order);
        match self.backend.invoke(target, &command) {
            Ok(()) => {}
            Err(InvokeError::NotSent(why)) => {
                return Err(AdapterError::Unavailable(format!("{device} ({target}): {why}; nothing was sent")))
            }
            Err(InvokeError::Status { status, cluster_status }) => return Err(status_error(status, cluster_status)),
            Err(InvokeError::Indeterminate(why)) => return Err(AdapterError::Indeterminate(why)),
        }
        // the device did it: its state right after, as it reports it
        self.backend
            .read(target, &ProfileAttribute::of_class(class))
            .map_err(AdapterError::Failed)
            .and_then(|values| class.matter_state(&backend::raw(&values)))
            .map_err(|e| {
                AdapterError::Indeterminate(format!("the device answered success, but cannot be read now: {e}"))
            })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
