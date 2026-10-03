//! Node configuration and key files (spec `specs/11-node-ipc.md` §Config).
//!
//! All relative paths are resolved against the directory of the config file.
//! Private keys live in separate files (hex Ed25519 seed, mode 0600), never in the
//! config itself. The config only carries public keys.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chitala_identity::{Keypair, PublicKey};
use chitala_model::{DeviceDescriptor, EntityId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::NodeError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalConfig {
    pub id: EntityId,
    /// Hex Ed25519 public key.
    pub public_key: String,
    #[serde(default)]
    pub roles: Vec<String>,
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
    #[serde(default = "default_keys_dir")]
    pub keys_dir: PathBuf,
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    #[serde(default = "default_audit")]
    pub audit_log: PathBuf,
    #[serde(default = "default_state")]
    pub state_file: PathBuf,
    /// Cedar policy file; the embedded default policy when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_file: Option<PathBuf>,
    pub principals: Vec<PrincipalConfig>,
    pub devices: Vec<DeviceDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_assistant: Option<HomeAssistantConfig>,
    /// Path of the `chitala-adapter-host` binary; next to the running binary
    /// (or `$CHITALA_ADAPTER_HOST`) when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_host: Option<PathBuf>,
    #[serde(default)]
    pub containment: ContainmentConfig,
}

fn default_keys_dir() -> PathBuf {
    "keys".into()
}
fn default_socket() -> PathBuf {
    "chitala.sock".into()
}
fn default_audit() -> PathBuf {
    "audit.audit.jsonl".into()
}
fn default_state() -> PathBuf {
    "domain-state.json".into()
}

/// A loaded config plus the directory its relative paths refer to.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: NodeConfig,
    pub base_dir: PathBuf,
}

impl LoadedConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, NodeError> {
        let path = path.as_ref();
        let text =
            fs::read_to_string(path).map_err(|e| NodeError::Config(format!("cannot read {}: {e}", path.display())))?;
        let config: NodeConfig =
            serde_json::from_str(&text).map_err(|e| NodeError::Config(format!("{}: {e}", path.display())))?;
        let base_dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        let base_dir = if base_dir.as_os_str().is_empty() { PathBuf::from(".") } else { base_dir };
        Ok(Self { config, base_dir })
    }

    pub fn path(&self, p: &Path) -> PathBuf {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base_dir.join(p)
        }
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.path(&self.config.keys_dir)
    }

    pub fn key_file(&self, id: &EntityId) -> PathBuf {
        self.keys_dir().join(key_file_name(id))
    }

    pub fn authority_key_file(&self) -> PathBuf {
        self.keys_dir().join(AUTHORITY_KEY_FILE)
    }

    /// Socket path. Unix socket paths are limited to ~104 bytes (macOS) / 108
    /// (Linux). When the configured path is longer, node and clients both use
    /// `/tmp/chitala-<uid>/<hash>.sock`, where `/tmp/chitala-<uid>` must be a real
    /// directory (not a symlink) owned by the owner of the domain directory with
    /// mode 0700 — otherwise another local user could pre-create the path and
    /// impersonate the node (v10 §1).
    pub fn socket(&self) -> Result<PathBuf, NodeError> {
        let p = self.path(&self.config.socket);
        let name = p.file_name().ok_or_else(|| NodeError::Config("socket path has no file name".into()))?;
        let dir = fs::canonicalize(p.parent().unwrap_or(Path::new(".")))
            .map_err(|e| NodeError::Config(format!("socket directory: {e}")))?;
        let abs = dir.join(name);
        if abs.as_os_str().len() < MAX_SOCKET_PATH {
            return Ok(abs);
        }
        private_socket_path(&self.base_dir, &abs)
    }

    pub fn authority_public_key(&self) -> Result<PublicKey, NodeError> {
        parse_public_key(&self.config.authority_public_key)
    }

    /// The adapter host binary: `adapter_host` from the config, else
    /// `$CHITALA_ADAPTER_HOST`, else `chitala-adapter-host` next to the running binary.
    pub fn adapter_host_program(&self) -> Result<PathBuf, NodeError> {
        if let Some(p) = &self.config.adapter_host {
            return Ok(self.path(p));
        }
        if let Some(p) = std::env::var_os("CHITALA_ADAPTER_HOST") {
            return Ok(PathBuf::from(p));
        }
        let exe = std::env::current_exe()?;
        let name = format!("chitala-adapter-host{}", std::env::consts::EXE_SUFFIX);
        let candidate = exe.parent().map(|d| d.join(&name)).filter(|p| p.is_file());
        candidate.ok_or_else(|| {
            NodeError::Config(format!(
                "{name} not found next to {}; build it (`cargo build --workspace`) or set adapter_host in the config",
                exe.display()
            ))
        })
    }

    pub fn node_public_key(&self) -> Result<PublicKey, NodeError> {
        parse_public_key(&self.config.node_public_key)
    }

    /// A client for this domain's node with the node key pinned.
    pub fn client(&self) -> Result<crate::NodeClient, NodeError> {
        Ok(crate::NodeClient::new(self.socket()?, self.node_public_key()?))
    }
}

pub const AUTHORITY_KEY_FILE: &str = "domain-authority.key";
/// Longest socket path used as configured (leaves room under SUN_LEN).
pub const MAX_SOCKET_PATH: usize = 100;

#[cfg(unix)]
fn private_socket_path(base_dir: &Path, configured: &Path) -> Result<PathBuf, NodeError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let owner = fs::metadata(base_dir)?.uid();
    let private = PathBuf::from(format!("/tmp/chitala-{owner}"));
    match fs::DirBuilder::new().mode(0o700).create(&private) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(&private)?;
    if !m.file_type().is_dir() || m.uid() != owner || m.permissions().mode() & 0o077 != 0 {
        return Err(NodeError::Config(format!(
            "{} is not a private directory (mode 700, owner uid {owner}); refusing to place the node socket there",
            private.display()
        )));
    }
    let digest = Sha256::digest(configured.as_os_str().as_encoded_bytes());
    Ok(private.join(format!("{}.sock", hex::encode(&digest[..8]))))
}

#[cfg(not(unix))]
fn private_socket_path(_base_dir: &Path, configured: &Path) -> Result<PathBuf, NodeError> {
    Err(NodeError::Config(format!("socket path {} is too long", configured.display())))
}

/// `person:alice` → `person-alice.key`
pub fn key_file_name(id: &EntityId) -> String {
    format!("{}-{}.key", id.kind(), id.local())
}

pub fn parse_public_key(hex_str: &str) -> Result<PublicKey, NodeError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| NodeError::Key(format!("bad public key hex: {e}")))?;
    bytes.try_into().map_err(|_| NodeError::Key("public key must be 32 bytes".into()))
}

/// Read a private key. Like ssh, a key file readable by group or others is
/// refused: a leaked key is a stolen identity (v10 §10).
pub fn read_key(path: &Path) -> Result<Keypair, NodeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).map_err(|e| NodeError::Key(format!("cannot read {}: {e}", path.display())))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(NodeError::Key(format!(
                "{} has permissions {mode:03o}; private keys must not be accessible by group/others (chmod 600)",
                path.display()
            )));
        }
    }
    let text = fs::read_to_string(path).map_err(|e| NodeError::Key(format!("cannot read {}: {e}", path.display())))?;
    let seed = hex::decode(text.trim()).map_err(|_| NodeError::Key(format!("{} is not a hex key", path.display())))?;
    let seed: [u8; 32] =
        seed.try_into().map_err(|_| NodeError::Key(format!("{} must hold 32 bytes", path.display())))?;
    Ok(Keypair::from_seed(&seed))
}

/// Write a private key with owner-only permissions. Refuses to overwrite.
pub fn write_key(path: &Path, key: &Keypair) -> Result<(), NodeError> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| NodeError::Key(format!("cannot create {}: {e}", path.display())))?;
    f.write_all(format!("{}\n", hex::encode(key.seed())).as_bytes())?;
    Ok(())
}

/// Write `contents` to `path` atomically (temp file + rename), owner-only.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), NodeError> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}
