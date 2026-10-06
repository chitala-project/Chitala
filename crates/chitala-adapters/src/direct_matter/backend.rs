//! What the direct Matter adapter needs from a Matter controller: the
//! [`DirectMatterBackend`] (spec 27). It is narrow and typed. A backend reads
//! and subscribes to the attributes the Home profile maps, and invokes the
//! commands the Home profile maps. Nothing else: no attribute writes, no
//! commissioning, no fabric management, no generic passthrough.
//!
//! The paths a backend is handed are built from the profile only
//! ([`ProfileAttribute`], [`ProfileCommand`]: their fields are private), so
//! the adapter cannot ask a backend for anything the profile does not map. A
//! backend that crosses a process boundary checks them again on the other
//! side.
//!
//! Backends: `MatterJsBackend` (a matter.js sidecar holding Chitala's own
//! fabric), and later `RsMatterBackend` (pure Rust). Both must pass the same
//! conformance suite (spec 26); the adapter's semantics do not depend on
//! which one runs.

use std::time::{Duration, Instant};

use chitala_model::CapabilityId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::profile::{hex_id, DeviceClass};

/// A Matter node's endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Target {
    pub node: u64,
    pub endpoint: u16,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node {} endpoint {}", self.node, self.endpoint)
    }
}

/// An attribute the Home profile maps for a device class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileAttribute {
    cluster: u32,
    attribute: u32,
}

impl ProfileAttribute {
    /// Every attribute the profile maps for `class`.
    pub fn of_class(class: &DeviceClass) -> Vec<Self> {
        class
            .matter
            .attributes
            .iter()
            .filter_map(|a| Some(Self { cluster: hex_id(&a.cluster)?, attribute: hex_id(&a.attribute)? }))
            .collect()
    }

    pub fn cluster(&self) -> u32 {
        self.cluster
    }

    pub fn attribute(&self) -> u32 {
        self.attribute
    }
}

/// The attributes the Home profile maps for a device class: what is read and
/// subscribed for a device of that class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileAttributes {
    class: String,
    attributes: Vec<ProfileAttribute>,
}

impl ProfileAttributes {
    pub fn of_class(class: &DeviceClass) -> Self {
        Self { class: class.class.clone(), attributes: ProfileAttribute::of_class(class) }
    }

    pub fn class(&self) -> &str {
        &self.class
    }

    pub fn attributes(&self) -> &[ProfileAttribute] {
        &self.attributes
    }
}

/// A command the Home profile maps for a capability of a device class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCommand {
    class: String,
    capability: CapabilityId,
    cluster: u32,
    command: u32,
    timed: bool,
}

impl ProfileCommand {
    /// The command `class` maps `capability` to, if the profile maps one.
    pub fn of(class: &DeviceClass, capability: &CapabilityId) -> Option<Self> {
        let c = class.matter.commands.get(capability)?;
        Some(Self {
            class: class.class.clone(),
            capability: capability.clone(),
            cluster: hex_id(&c.cluster)?,
            command: hex_id(&c.command)?,
            timed: c.timed,
        })
    }

    pub fn class(&self) -> &str {
        &self.class
    }

    pub fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    pub fn cluster(&self) -> u32 {
        self.cluster
    }

    pub fn command(&self) -> u32 {
        self.command
    }

    /// Whether the command must be sent as a Timed Invoke.
    pub fn timed(&self) -> bool {
        self.timed
    }
}

/// Attributes and their values, as the device answered them.
pub type Values = Vec<(ProfileAttribute, Value)>;

/// The values as the profile normalises them: (cluster, attribute, value).
pub fn raw(values: &Values) -> Vec<(u32, u32, Value)> {
    values.iter().map(|(a, v)| (a.cluster, a.attribute, v.clone())).collect()
}

/// What a backend's subscription holds for a target.
#[derive(Debug, Clone, PartialEq)]
pub struct Subscribed {
    pub values: Values,
    /// When the device was last heard: a report, or a keep-alive that says
    /// nothing changed since.
    pub last_heard: Instant,
    /// Whether the backend still holds the subscription up. A device that
    /// went silent is noticed only after the subscription's interval and a
    /// margin: until then, the age since it was last heard grows.
    pub live: bool,
    /// The interval the device agreed to keep the subscription alive at, if
    /// known: it is heard from at least this often while it works.
    pub max_interval: Option<Duration>,
}

/// Why an invoke did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvokeError {
    /// The command certainly never reached the device: no session could be
    /// had, or the device did not answer a read just before.
    NotSent(String),
    /// The device answered with an Interaction Model status other than
    /// success (and a cluster status, if any).
    Status { status: u8, cluster_status: Option<u8> },
    /// It may have reached the device, and no answer came.
    Indeterminate(String),
    /// The backend refused the request before sending anything (it is not
    /// the profile's, or the endpoint is not a device of the class).
    Rejected(String),
}

/// A Matter controller, as the direct Matter adapter uses it.
pub trait DirectMatterBackend: Send + Sync {
    /// Keep `attributes` of `target` subscribed: the device reports their
    /// changes, and a keep-alive at the subscription's interval.
    fn subscribe(&self, target: Target, attributes: &ProfileAttributes) -> Result<(), String>;

    /// Read `attributes` of `target` from the device now: a Read interaction
    /// with no data version filter, so the device sends every value, bounded
    /// by the backend's timeout. An attribute the device does not have is
    /// left out; none at all is an error.
    fn read(&self, target: Target, attributes: &ProfileAttributes) -> Result<Values, String>;

    /// Invoke `command` on `target`, once, as a Timed Invoke when the
    /// profile says so. A backend never sends it again by itself.
    /// [`InvokeError::NotSent`] only when the command certainly never left.
    fn invoke(&self, target: Target, command: &ProfileCommand) -> Result<(), InvokeError>;

    /// What the subscription holds for `target`, if there is one.
    fn subscribed(&self, target: Target) -> Option<Subscribed>;
}
