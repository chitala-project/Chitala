//! Chitala Home/Site Node (spec `specs/11-node-ipc.md`).
//!
//! - [`node::Node`]   — the trust chain: Reference Monitor → adapters → twin → bus → audit.
//! - [`config`]       — config file, key files.
//! - [`ipc`]          — Unix-socket JSON-lines server and client.
//! - [`request`]      — client-side request signing.
//! - [`setup`]        — `chitala init`: a sample domain with virtual devices.

#![forbid(unsafe_code)]

pub mod config;
pub mod executor;
pub mod ipc;
pub mod node;
pub mod request;
pub mod setup;

use std::collections::BTreeMap;

use std::sync::Arc;
use std::time::Duration;

use chitala_adapters::host::HostInit;
use chitala_audit::{AuditLog, Signer};
use chitala_model::DeviceDescriptor;
use chitala_monitor::MonitorConfig;

pub use config::{LoadedConfig, NodeConfig};
pub use ipc::{NodeClient, Response, Submit};
pub use node::{load_domain_state, Clock, DomainState, Node, NodeParts, PendingDevice, PolicySource, Step};
pub use request::{now_ms, Requester};

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("config: {0}")]
    Config(String),
    #[error("key: {0}")]
    Key(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Policy(#[from] chitala_policy::PolicyError),
    #[error(transparent)]
    Audit(#[from] chitala_audit::AuditError),
    #[error("adapter: {0}")]
    Adapter(String),
    /// Persistent state and audit log disagree (rollback, truncation, deletion).
    #[error("integrity: {0}")]
    Integrity(String),
}

/// A system clock more than this far behind the last audited event refuses to start.
pub const MAX_CLOCK_REGRESSION_MS: u64 = 60_000;

/// Build a node from a loaded config file (keys, audit log, state, adapters).
pub fn node_from_config(loaded: &LoadedConfig) -> Result<Node, NodeError> {
    node_from_config_with_wall(loaded, chitala_adapters::clock::system_wall())
}

/// [`node_from_config`] with an explicit wall-clock source (tests).
pub fn node_from_config_with_wall(
    loaded: &LoadedConfig,
    wall: chitala_adapters::clock::WallSource,
) -> Result<Node, NodeError> {
    let cfg = &loaded.config;
    let authority_key = config::read_key(&loaded.authority_key_file())?;
    if authority_key.public_key() != loaded.authority_public_key()? {
        return Err(NodeError::Key("authority key file does not match authority_public_key in the config".into()));
    }
    let node_key = config::read_key(&loaded.key_file(&cfg.node_id))?;
    if node_key.public_key() != loaded.node_public_key()? {
        return Err(NodeError::Key("node key file does not match node_public_key in the config".into()));
    }

    let mut principals = Vec::new();
    for p in &cfg.principals {
        principals.push((p.id.clone(), config::parse_public_key(&p.public_key)?, p.roles.clone()));
    }

    let executor = start_adapter_hosts(loaded)?;

    let policy = match &cfg.policy_file {
        Some(p) => node::PolicySource::Cedar(std::fs::read_to_string(loaded.path(p))?),
        None => node::PolicySource::Default,
    };
    // Anti-rollback (v13 §7): the audit log must still contain the head recorded
    // in the state file, and must not have seen a newer authority epoch than the
    // state file holds. Either failure means a file was replaced, truncated or
    // deleted; the node refuses to start rather than silently forgetting
    // revocations or quarantines.
    let state_path = loaded.path(&cfg.state_file);
    let state = node::load_domain_state(&state_path)?;
    let signer = Signer { id: cfg.node_id.clone(), key: node_key.clone() };
    let (audit, report) =
        AuditLog::open_anchored(loaded.path(&cfg.audit_log), Some(signer), state.audit_anchor.as_ref()).map_err(
            |e| NodeError::Integrity(format!("{e}; refusing to start (see specs/11-node-ipc.md \"Recovery\")")),
        )?;
    // Time (v16 §4, threat model R3): the clock may not have been set back before
    // the last audited event — that would let expired tokens and requests live
    // again. From here on the trusted clock never goes backwards.
    let wall_now = wall();
    if wall_now.saturating_add(MAX_CLOCK_REGRESSION_MS) < report.max_ts_ms {
        return Err(NodeError::Integrity(format!(
            "the system clock ({wall_now}) is {} s behind the last audited event ({}): clock rolled back? \
             fix the system time; refusing to start",
            (report.max_ts_ms - wall_now) / 1000,
            report.max_ts_ms
        )));
    }
    let trusted_clock = Arc::new(chitala_adapters::clock::TrustedClock::new(wall, report.max_ts_ms));
    if report.max_epoch > state.epoch {
        return Err(NodeError::Integrity(format!(
            "{} is at epoch {} but the audit log records epoch {}: the state file was rolled back or deleted; refusing to start",
            state_path.display(),
            state.epoch,
            report.max_epoch
        )));
    }

    Node::new(NodeParts {
        domain: cfg.domain.clone(),
        node_id: cfg.node_id.clone(),
        node_key,
        authority_key,
        principals,
        devices: cfg.devices.clone(),
        executor,
        policy,
        audit,
        state,
        state_path: Some(state_path),
        containment: cfg.containment,
        monitor: MonitorConfig::default(),
        clock: trusted_clock.as_clock(),
        clock_watch: Some(trusted_clock),
    })
}

/// How long the node waits for an adapter host before declaring it hung.
fn host_timeout(adapter: &str) -> Duration {
    match adapter {
        // HTTP to Home Assistant: 3 s connect + 10 s per call, execute + observe
        "home-assistant" => Duration::from_secs(30),
        _ => Duration::from_secs(5),
    }
}

/// One adapter host process per adapter type (a Home Assistant failure cannot
/// take the virtual devices down with it). Each host gets an empty environment;
/// the Home Assistant host additionally gets its token variable and nothing else.
pub fn start_adapter_hosts(loaded: &LoadedConfig) -> Result<Arc<dyn executor::Executor>, NodeError> {
    let cfg = &loaded.config;
    let program = loaded.adapter_host_program()?;
    let mut groups: BTreeMap<&str, Vec<DeviceDescriptor>> = BTreeMap::new();
    for d in &cfg.devices {
        groups.entry(d.adapter.as_str()).or_default().push(d.clone());
    }
    let mut routed = executor::Routed::new();
    for (adapter, devices) in groups {
        let mut env = Vec::new();
        let home_assistant = if adapter == "home-assistant" {
            let ha =
                cfg.home_assistant.clone().ok_or_else(|| NodeError::Config("home_assistant section missing".into()))?;
            if let Ok(token) = std::env::var(&ha.token_env) {
                env.push((ha.token_env.clone(), token));
            }
            Some(ha)
        } else {
            None
        };
        let ids: Vec<_> = devices.iter().map(|d| d.id.clone()).collect();
        let init = HostInit { node_public_key: cfg.node_public_key.clone(), devices, home_assistant };
        let host = executor::ChildHost::start(program.clone(), init, env, host_timeout(adapter))
            .map_err(|e| NodeError::Adapter(format!("{adapter}: {e}")))?;
        routed.add(Arc::new(host), &ids);
    }
    Ok(Arc::new(routed))
}
