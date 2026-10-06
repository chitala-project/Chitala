//! Telemetry and history, local (spec 29): what devices did over time.
//!
//! Questions like "how long did the air conditioner run today?" or "how many
//! times was the pump switched on?" need a history of state, which the audit
//! log (actions and outcomes) is not. This crate records it and answers them,
//! outside the Trusted Core: the node only publishes what it observed
//! (`Observed`, `Unobservable` on its event bus); recording, storage and
//! arithmetic happen here, and decide nothing.
//!
//! - **Observed time, not command time:** a state counts from when its
//!   source produced it, as observed, not from when an order left.
//! - **Unobservable time is unknown,** never the last state; so is time
//!   before a device was observed, while the node was not running, and when
//!   the recorder missed events. It is reported apart.
//! - **Changes outside Chitala count:** the observation sees them.

#![forbid(unsafe_code)]

pub mod log;
pub mod query;
pub mod recorder;

use chitala_model::{EntityId, Payload};
use serde::{Deserialize, Serialize};

/// One line of the history log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "r", rename_all = "snake_case")]
pub enum Record {
    /// The recorder started: every device is unknown until observed.
    Start { at: u64 },
    /// From `at` (when its source produced it), the device's state is
    /// `state`; a key absent from it is unknown. `observed_at` is when the
    /// node observed it.
    Observed { device: EntityId, at: u64, observed_at: u64, state: Payload },
    /// From `at`, the device cannot be observed: its state is unknown.
    Unobservable { device: EntityId, at: u64 },
    /// The recorder missed events: every device is unknown from `at` until
    /// its next record.
    Gap { at: u64 },
}

impl Record {
    pub fn at(&self) -> u64 {
        match self {
            Record::Start { at } | Record::Gap { at } => *at,
            Record::Observed { at, .. } | Record::Unobservable { at, .. } => *at,
        }
    }

    /// The device the record is about; `None` for every device.
    pub fn device(&self) -> Option<&EntityId> {
        match self {
            Record::Observed { device, .. } | Record::Unobservable { device, .. } => Some(device),
            Record::Start { .. } | Record::Gap { .. } => None,
        }
    }
}
