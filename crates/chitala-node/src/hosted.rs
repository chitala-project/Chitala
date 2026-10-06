//! The hosted platform binding (Linux, macOS; spec 18): turns a config *file*
//! into a [`Domain`] and a [`NodeEnv`] on `chitala-platform-host`.
//!
//! Locations in the config are paths relative to the config file's directory
//! (or absolute):
//!
//! - `keys_dir` → a software key store (`<name>.key` files, owner-only);
//! - `audit_log`, `state_file`, `policy_file` → objects of a file storage that
//!   refuses symlinks and private data others can reach;
//! - `socket` → a Unix socket (moved into a private directory when the path is
//!   too long for one);
//! - `adapter_host` → the `chitala-adapter-host` executable, run as a process
//!   with an empty environment.
//!
//! This is the only module of the node that knows about the host operating
//! system; `scripts/core-purity.py` holds the rest of the crate to the PAL.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chitala_identity::{KeyId, Keypair, PublicKey};
use chitala_model::EntityId;
use chitala_platform::{Endpoint, Entropy, NoDevices, Platform, PlatformError, SoftwareKeyStore, StoragePath};
use chitala_platform_host::{FsStorage, OsEntropy, ProcessHost, SystemTimeSource, UnixIpc, UreqNetwork};

use crate::config::{Domain, NodeConfig, NodeEnv, StoredObject};
use crate::setup::{InitSummary, CONFIG_FILE, TOKENS_DIR};
use crate::{Node, NodeClient, NodeError};

/// Wall-clock time of the host, in ms since the Unix epoch (CLI, tools).
pub fn now_ms() -> u64 {
    use chitala_platform::TimeSource;
    SystemTimeSource::new().wall_ms()
}

fn platform_error(what: &Path) -> impl Fn(PlatformError) -> NodeError + '_ {
    move |e| NodeError::Platform(format!("{}: {e}", what.display()))
}

/// `dir/name` → (`dir`, `name`): a storage root and one object in it.
fn split(path: &Path) -> Result<(PathBuf, String), NodeError> {
    let bad = || NodeError::Config(format!("{}: not a file name", path.display()));
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(bad)?.to_string();
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Ok((dir, name))
}

/// One file as an object of a hosted storage rooted at its directory.
pub fn stored_file(path: &Path) -> Result<StoredObject, NodeError> {
    let (dir, name) = split(path)?;
    let storage = FsStorage::new(&dir).map_err(platform_error(&dir))?;
    let name = StoragePath::new(name).map_err(platform_error(path))?;
    Ok(StoredObject::new(Arc::new(storage), name))
}

/// A config file plus the directory its relative paths refer to.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: NodeConfig,
    pub base_dir: PathBuf,
}

impl LoadedConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, NodeError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| NodeError::Config(format!("cannot read {}: {e}", path.display())))?;
        let mut config: NodeConfig =
            serde_json::from_str(&text).map_err(|e| NodeError::Config(format!("{}: {e}", path.display())))?;
        let (base_dir, _) = split(path)?;
        // the matter.js sidecar and its fabric, as the adapter host reaches them
        if let Some(m) = config.matter.as_mut() {
            for location in [&mut m.sidecar, &mut m.storage] {
                let p = Path::new(location.as_str());
                if !p.is_absolute() {
                    *location = base_dir.join(p).to_string_lossy().into_owned();
                }
            }
        }
        Ok(Self { config, base_dir })
    }

    /// A location from the config as a host path.
    pub fn path(&self, location: &str) -> PathBuf {
        let p = Path::new(location);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base_dir.join(p)
        }
    }

    /// The hosted platform of this domain.
    pub fn platform(&self) -> Result<Platform, NodeError> {
        let entropy: Arc<dyn Entropy> = Arc::new(OsEntropy);
        let storage = Arc::new(FsStorage::new(&self.base_dir).map_err(platform_error(&self.base_dir))?);
        let keys_dir = self.path(&self.config.keys_dir);
        let (keys_root, keys_name) = split(&keys_dir)?;
        let key_storage = Arc::new(FsStorage::new(&keys_root).map_err(platform_error(&keys_root))?);
        let keys = SoftwareKeyStore::new(
            key_storage,
            Arc::clone(&entropy),
            StoragePath::new(keys_name).map_err(platform_error(&keys_dir))?,
        )
        .map_err(platform_error(&keys_dir))?;
        let (socket_dir, _) = split(&self.path(&self.config.socket))?;
        let ipc = UnixIpc::new(&socket_dir).map_err(platform_error(&socket_dir))?;
        Ok(Platform {
            name: "hosted-unix",
            time: Arc::new(SystemTimeSource::new()),
            entropy,
            keys: Arc::new(keys),
            storage,
            ipc: Arc::new(ipc),
            exec: Arc::new(ProcessHost),
            network: Arc::new(UreqNetwork),
            devices: Arc::new(NoDevices),
        })
    }

    /// The node's endpoint: the socket's file name in its directory.
    pub fn endpoint(&self) -> Result<Endpoint, NodeError> {
        let socket = self.path(&self.config.socket);
        let (_, name) = split(&socket)?;
        Endpoint::new(name).map_err(platform_error(&socket))
    }

    /// The domain on the hosted platform (clients and the node).
    pub fn domain(&self) -> Result<Domain, NodeError> {
        Ok(Domain { config: self.config.clone(), platform: self.platform()?, endpoint: self.endpoint()? })
    }

    /// What the node additionally needs: its stored objects, the adapter host
    /// executable and the Home Assistant token from the node's environment.
    pub fn node_env(&self) -> Result<NodeEnv, NodeError> {
        let cfg = &self.config;
        let home_assistant_env = match &cfg.home_assistant {
            Some(ha) => std::env::var(&ha.token_env).map(|t| vec![(ha.token_env.clone(), t)]).unwrap_or_default(),
            None => Vec::new(),
        };
        let program = self.adapter_host_program()?;
        Ok(NodeEnv {
            audit_log: stored_file(&self.path(&cfg.audit_log))?,
            state_file: stored_file(&self.path(&cfg.state_file))?,
            policy_file: cfg.policy_file.as_deref().map(|p| stored_file(&self.path(p))).transpose()?,
            adapter_host: program
                .to_str()
                .ok_or_else(|| NodeError::Config(format!("{}: not valid UTF-8", program.display())))?
                .to_string(),
            home_assistant_env,
        })
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

    /// Where the CLI and the MCP broker keep the tokens `holder` was given.
    pub fn token_file(&self, holder: &EntityId) -> PathBuf {
        self.base_dir.join(TOKENS_DIR).join(format!("{}-{}.token", holder.kind(), holder.local()))
    }

    pub fn keypair(&self, id: &EntityId) -> Result<Keypair, NodeError> {
        self.domain()?.keypair(id)
    }

    pub fn client(&self) -> Result<NodeClient, NodeError> {
        self.domain()?.client()
    }

    pub fn authority_public_key(&self) -> Result<PublicKey, NodeError> {
        crate::config::parse_public_key(&self.config.authority_public_key)
    }

    pub fn node_public_key(&self) -> Result<PublicKey, NodeError> {
        crate::config::parse_public_key(&self.config.node_public_key)
    }
}

/// Build the node of a config file on the hosted platform.
pub fn node_from_config(loaded: &LoadedConfig) -> Result<Node, NodeError> {
    crate::start_node(&loaded.domain()?, &loaded.node_env()?)
}

/// `chitala init DIR`: the sample domain in a directory. Returns the config file.
pub fn init_domain(dir: &Path) -> Result<(PathBuf, InitSummary), NodeError> {
    let storage = Arc::new(FsStorage::new(dir).map_err(platform_error(dir))?);
    let keys = SoftwareKeyStore::new(
        storage.clone(),
        Arc::new(OsEntropy),
        StoragePath::new(chitala_platform_host::KEYS_DIR).map_err(platform_error(dir))?,
    )
    .map_err(platform_error(dir))?;
    let summary = crate::setup::init_domain(storage.as_ref(), &keys)?;
    Ok((storage.root().join(CONFIG_FILE), summary))
}

/// Verify an audit log file with the trusted node keys.
pub fn verify_audit_file(
    path: &Path,
    trusted: &HashMap<KeyId, PublicKey>,
) -> Result<chitala_audit::VerifyReport, NodeError> {
    // an investigation must not create anything
    if std::fs::symlink_metadata(path).is_err() {
        return Err(NodeError::Config(format!("{} does not exist", path.display())));
    }
    crate::verify_audit(&stored_file(path)?, trusted)
}
