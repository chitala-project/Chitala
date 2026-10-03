//! Chitala Home/Site Node (spec `specs/11-node-ipc.md`).
//!
//! - [`node::Node`]   — the trust chain: Reference Monitor → adapters → twin → bus → audit.
//! - [`config`]       — config file, key files.
//! - [`ipc`]          — Unix-socket JSON-lines server and client.
//! - [`request`]      — client-side request signing.
//! - [`setup`]        — `chitala init`: a sample domain with virtual devices.

#![forbid(unsafe_code)]

pub mod config;
pub mod ipc;
pub mod node;
pub mod request;
pub mod setup;

use std::collections::BTreeMap;

use chitala_adapters::home_assistant::HomeAssistantAdapter;
use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::DeviceAdapter;
use chitala_audit::{AuditLog, Signer};
use chitala_monitor::MonitorConfig;

pub use config::{LoadedConfig, NodeConfig};
pub use ipc::{NodeClient, Response, Submit};
pub use node::{load_domain_state, Clock, DomainState, Node, NodeParts};
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

/// Build a node from a loaded config file (keys, audit log, state, adapters).
pub fn node_from_config(loaded: &LoadedConfig) -> Result<Node, NodeError> {
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

    let mut adapters: Vec<Box<dyn DeviceAdapter>> = Vec::new();
    let mut mock = MockAdapter::new();
    let mut ha_entities = BTreeMap::new();
    for d in &cfg.devices {
        match d.adapter.as_str() {
            "mock" => {
                let kind = VirtualKind::from_capabilities(&d.capabilities)
                    .ok_or_else(|| NodeError::Config(format!("{}: cannot infer a virtual device type", d.id)))?;
                mock.add(d.id.clone(), kind);
            }
            "home-assistant" => {
                let ha = cfg
                    .home_assistant
                    .as_ref()
                    .ok_or_else(|| NodeError::Config("home_assistant section missing".into()))?;
                let entity = ha
                    .entities
                    .get(&d.id)
                    .ok_or_else(|| NodeError::Config(format!("{}: no Home Assistant entity mapping", d.id)))?;
                ha_entities.insert(d.id.clone(), entity.clone());
            }
            other => return Err(NodeError::Config(format!("{}: unknown adapter {other:?}", d.id))),
        }
    }
    adapters.push(Box::new(mock));
    if let (Some(ha), false) = (&cfg.home_assistant, ha_entities.is_empty()) {
        let a = HomeAssistantAdapter::new(&ha.base_url, &ha.token_env, ha_entities, ha.allow_insecure_http)
            .map_err(|e| NodeError::Adapter(e.to_string()))?;
        adapters.push(Box::new(a));
    }

    let policy_src = match &cfg.policy_file {
        Some(p) => Some(std::fs::read_to_string(loaded.path(p))?),
        None => None,
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
        adapters,
        policy_src,
        audit,
        state,
        state_path: Some(state_path),
        containment: cfg.containment,
        monitor: MonitorConfig::default(),
        clock: Box::new(now_ms),
    })
}
