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
//! | the backend refused the request itself: not the profile's, or not a device of the class | not executed (`X_ADAPTER`) |
//! | `FAILURE`, `TIMEOUT`, any other status | unknown: a lock that jams moved part way (`X_EXECUTION_UNKNOWN`) |
//! | no answer | unknown (`X_EXECUTION_UNKNOWN`) |
//!
//! Nothing is ever sent twice.

#[cfg(feature = "direct-matter")]
mod adapter;
pub mod backend;
#[cfg(any(test, feature = "conformance"))]
pub mod fake;
#[cfg(all(feature = "direct-matter", any(test, feature = "conformance")))]
pub mod fake_sidecar;
#[cfg(feature = "direct-matter")]
pub mod matter_js;

use std::collections::BTreeMap;

use chitala_model::EntityId;

#[cfg(feature = "direct-matter")]
pub use adapter::{class_of, status_error, DirectMatterAdapter};
pub use backend::{
    DirectMatterBackend, InvokeError, ProfileAttribute, ProfileAttributes, ProfileCommand, Subscribed, Target, Values,
};

/// The adapter's name in device descriptors.
pub const ADAPTER: &str = "matter";

/// The direct Matter section of the node config (also sent to the adapter
/// host). Its paths reach the host absolute: the hosted node resolves them
/// against the config's directory.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectMatterConfig {
    /// The Node.js runtime that runs the matter.js sidecar: an absolute path.
    pub runtime: String,
    /// The sidecar's entry point (`sidecars/matter-js/src/main.ts`).
    pub sidecar: String,
    /// Chitala's fabric: a private directory, claimed by one sidecar at a time.
    pub storage: String,
    /// The longest interval the controller asks devices to keep alive at.
    #[serde(default = "default_ceiling")]
    pub subscription_ceiling_s: u32,
    /// Chitala device → its node and endpoint on Chitala's fabric.
    pub devices: BTreeMap<EntityId, Target>,
}

fn default_ceiling() -> u32 {
    60
}
