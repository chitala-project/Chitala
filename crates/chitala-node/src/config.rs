//! Node configuration (spec `specs/11-node-ipc.md` §Config) and what the
//! platform makes of it (spec 18).
//!
//! The config only carries public keys; private keys live in the platform's
//! [`SecureKeyStore`](chitala_platform::SecureKeyStore). Locations in the config
//! (`keys_dir`, `socket`, `audit_log`, …) are opaque strings to the node: a
//! platform binding ([`crate::hosted`] on Linux/macOS) resolves them into a
//! [`Domain`] and a [`NodeEnv`] — key store, storage objects, an IPC endpoint and
//! an execution host. Nothing below this module knows what a file, a socket or a
//! process is.

use std::fmt;
use std::sync::Arc;

use chitala_identity::{Keypair, PublicKey};
use chitala_model::{DeviceDescriptor, EntityId};
use chitala_platform::{Endpoint, KeyRef, Platform, PlatformError, Storage, StoragePath, Visibility};
use chitala_resource::Resource;
use serde::{Deserialize, Serialize};

use crate::NodeError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalConfig {
    pub id: EntityId,
    /// Hex Ed25519 public key.
    pub public_key: String,
    #[serde(default)]
    pub roles: Vec<String>,
    /// For non-human principals: the persons it acts for (spec §15).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub serves: Vec<EntityId>,
}

pub use chitala_adapters::home_assistant::HomeAssistantConfig;

/// Automatic containment of non-human principals (v8 §9, v11 §16.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentConfig {
    pub window_ms: u64,
    pub suspicious_after: u32,
    pub restricted_after: u32,
    pub quarantine_after: u32,
}

impl Default for ContainmentConfig {
    fn default() -> Self {
        Self { window_ms: 60_000, suspicious_after: 5, restricted_after: 10, quarantine_after: 20 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// `domain:<name>` — the trust domain this node is authoritative for.
    pub domain: EntityId,
    /// `service:<name>` — the node's own identity (signs audit checkpoints).
    pub node_id: EntityId,
    /// Hex public key of the domain authority (token issuer).
    pub authority_public_key: String,
    /// Hex public key of the node (`node_id`). Clients pin it and reject replies
    /// not signed with it (v10 §2 manager authentication).
    pub node_public_key: String,
    /// Where the private keys live. Locations are resolved by the platform
    /// binding (hosted: paths relative to the config file's directory).
    #[serde(default = "default_keys_dir")]
    pub keys_dir: String,
    /// The node's IPC endpoint (hosted: a Unix socket).
    #[serde(default = "default_socket")]
    pub socket: String,
    #[serde(default = "default_audit")]
    pub audit_log: String,
    #[serde(default = "default_state")]
    pub state_file: String,
    /// Cedar policy; the embedded default policy when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_file: Option<String>,
    pub principals: Vec<PrincipalConfig>,
    pub devices: Vec<DeviceDescriptor>,
    /// The governed physical world (spec §14): sites, rooms, doors… bound to devices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<Resource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_assistant: Option<HomeAssistantConfig>,
    /// The adapter host component (hosted: path of the `chitala-adapter-host`
    /// binary; next to the running binary, or `$CHITALA_ADAPTER_HOST`, when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_host: Option<String>,
    #[serde(default)]
    pub containment: ContainmentConfig,
}

fn default_keys_dir() -> String {
    "keys".into()
}
fn default_socket() -> String {
    "chitala.sock".into()
}
fn default_audit() -> String {
    "audit.audit.jsonl".into()
}
fn default_state() -> String {
    "domain-state.json".into()
}

/// Name of the domain authority's key in the key store.
pub const AUTHORITY_KEY: &str = "domain-authority";

/// Name of a principal's key in the key store: `person:alice` → `person-alice`
/// (the hosted key store keeps it in `keys/person-alice.key`).
pub fn key_ref(id: &EntityId) -> Result<KeyRef, NodeError> {
    KeyRef::new(format!("{}-{}", id.kind(), id.local())).map_err(|e| NodeError::Key(format!("{id}: {e}")))
}

pub fn parse_public_key(hex_str: &str) -> Result<PublicKey, NodeError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| NodeError::Key(format!("bad public key hex: {e}")))?;
    bytes.try_into().map_err(|_| NodeError::Key("public key must be 32 bytes".into()))
}

/// One object in a platform's storage.
#[derive(Clone)]
pub struct StoredObject {
    pub storage: Arc<dyn Storage>,
    pub path: StoragePath,
}

impl StoredObject {
    pub fn new(storage: Arc<dyn Storage>, path: StoragePath) -> Self {
        Self { storage, path }
    }

    pub fn read(&self, visibility: Visibility) -> Result<Option<Vec<u8>>, NodeError> {
        self.storage.read(&self.path, visibility).map_err(|e| self.error(e))
    }

    pub fn write_atomic(&self, data: &[u8], visibility: Visibility) -> Result<(), NodeError> {
        self.storage.write_atomic(&self.path, data, visibility).map_err(|e| self.error(e))
    }

    /// Claim this object for one holder (`<path>.lock`, [`Storage::claim`]):
    /// a second claim fails while the guard lives.
    pub fn claim(&self) -> Result<Box<dyn chitala_platform::Claim>, NodeError> {
        let lock = StoragePath::new(format!("{}.lock", self.path)).map_err(|e| self.error(e))?;
        self.storage.claim(&lock).map_err(|e| match e {
            PlatformError::AlreadyExists(_) => NodeError::Platform(format!(
                "another node is running on this domain (it holds {lock}); this one stopped before writing anything"
            )),
            e => self.error(e),
        })
    }

    fn error(&self, e: PlatformError) -> NodeError {
        NodeError::Storage(format!("{}: {e}", self.path))
    }
}

impl fmt::Debug for StoredObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StoredObject({})", self.path)
    }
}

/// A domain as one platform presents it: the config, the platform (key store,
/// storage, IPC, execution host, clock, entropy) and the node's endpoint.
/// Everything a client needs; the node additionally needs a [`NodeEnv`].
#[derive(Clone)]
pub struct Domain {
    pub config: NodeConfig,
    pub platform: Platform,
    pub endpoint: Endpoint,
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Domain")
            .field("domain", &self.config.domain)
            .field("platform", &self.platform.name)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl Domain {
    pub fn authority_public_key(&self) -> Result<PublicKey, NodeError> {
        parse_public_key(&self.config.authority_public_key)
    }

    pub fn node_public_key(&self) -> Result<PublicKey, NodeError> {
        parse_public_key(&self.config.node_public_key)
    }

    /// A principal's key pair from the key store. The key leaves the store:
    /// only exportable stores can serve it (spec 18, decision D3).
    pub fn keypair(&self, id: &EntityId) -> Result<Keypair, NodeError> {
        self.export(&key_ref(id)?)
    }

    pub fn authority_keypair(&self) -> Result<Keypair, NodeError> {
        self.export(&KeyRef::new(AUTHORITY_KEY).map_err(|e| NodeError::Key(e.to_string()))?)
    }

    fn export(&self, key: &KeyRef) -> Result<Keypair, NodeError> {
        let seed = self.platform.keys.export_seed(key).map_err(|e| match e {
            PlatformError::NotFound(_) => NodeError::Key(format!("no key {key} in this platform's key store")),
            e => NodeError::Key(format!("key {key}: {e}")),
        })?;
        Ok(Keypair::from_seed(&seed))
    }

    /// A client for this domain's node, with the node key pinned.
    pub fn client(&self) -> Result<crate::NodeClient, NodeError> {
        Ok(crate::NodeClient::new(Arc::clone(&self.platform.ipc), self.endpoint.clone(), self.node_public_key()?))
    }
}

/// What only the node itself needs from the platform, besides the [`Domain`].
#[derive(Clone)]
pub struct NodeEnv {
    pub audit_log: StoredObject,
    pub state_file: StoredObject,
    pub policy_file: Option<StoredObject>,
    /// The adapter host component, as the platform's execution host locates it.
    pub adapter_host: String,
    /// Environment granted to the Home Assistant adapter host (its token) and
    /// to no other component.
    pub home_assistant_env: Vec<(String, String)>,
}

impl fmt::Debug for NodeEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never print the granted values: they are secrets
        let granted: Vec<&str> = self.home_assistant_env.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("NodeEnv")
            .field("audit_log", &self.audit_log)
            .field("state_file", &self.state_file)
            .field("policy_file", &self.policy_file)
            .field("adapter_host", &self.adapter_host)
            .field("home_assistant_env", &granted)
            .finish()
    }
}
