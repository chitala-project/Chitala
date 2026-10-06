//! Chitala Home/Site Node (spec `specs/11-node-ipc.md`).
//!
//! - [`node::Node`]   — the trust chain: Reference Monitor → adapters → twin → bus → audit.
//! - [`config`]       — the config, and the [`Domain`] / [`NodeEnv`] a platform makes of it.
//! - [`ipc`]          — JSON-lines server and client over the platform's IPC transport.
//! - [`executor`]     — adapter hosts as isolated platform components.
//! - [`request`]      — client-side request signing.
//! - [`setup`]        — `chitala init`: a sample domain with virtual devices.
//! - [`hosted`]       — the binding to the hosted platform (Linux, macOS): config
//!   files, key files, Unix sockets, processes.
//!
//! Everything except [`hosted`] reaches the machine only through the Platform
//! Abstraction Layer (spec 18): it does not know what a file, a permission bit,
//! a socket, a process or a pipe is (`scripts/core-purity.py` checks this).

#![forbid(unsafe_code)]

pub mod config;
pub mod executor;
pub mod history;
#[cfg(feature = "hosted")]
pub mod hosted;
pub mod ipc;
pub mod node;
pub mod request;
pub mod setup;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use chitala_audit::{AuditLog, Signer};
use chitala_boundary::TrustedExecutionBoundary;
use chitala_model::DeviceDescriptor;
use chitala_monitor::MonitorConfig;
use chitala_platform::{ComponentSpec, TrustedClock, Visibility};

pub use config::{Domain, NodeConfig, NodeEnv, StoredObject};
#[cfg(feature = "hosted")]
pub use hosted::{node_from_config, LoadedConfig};
pub use ipc::{NodeClient, Response, Submit};
pub use node::{load_domain_state, Clock, DomainState, Node, NodeParts, Observer, PendingDevice, PolicySource, Step};
pub use request::Requester;

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("config: {0}")]
    Config(String),
    #[error("key: {0}")]
    Key(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("platform: {0}")]
    Platform(String),
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

/// A platform clock more than this far behind the last audited event refuses to start.
pub const MAX_CLOCK_REGRESSION_MS: u64 = 60_000;

/// Start the node of `domain` on its platform: keys from the key store, state
/// and audit log from storage, adapter hosts from the execution host, time from
/// the platform clock.
pub fn start_node(domain: &Domain, env: &NodeEnv) -> Result<Node, NodeError> {
    // one node per domain, decided before anything is written, read for
    // writing or started: a second node stops here, having touched nothing
    // (concurrency audit R2)
    let claim = env.state_file.claim()?;
    let cfg = &domain.config;
    let authority_key = domain.authority_keypair()?;
    if authority_key.public_key() != domain.authority_public_key()? {
        return Err(NodeError::Key("the authority key does not match authority_public_key in the config".into()));
    }
    let node_key = domain.keypair(&cfg.node_id)?;
    if node_key.public_key() != domain.node_public_key()? {
        return Err(NodeError::Key("the node key does not match node_public_key in the config".into()));
    }

    let mut principals = Vec::new();
    for p in &cfg.principals {
        principals.push((p.id.clone(), config::parse_public_key(&p.public_key)?, p.roles.clone()));
    }

    // The only producer of physical commands, with a fresh order key; the
    // adapter hosts started next accept that key and nothing else.
    let boundary = TrustedExecutionBoundary::new(Arc::clone(&domain.platform.entropy));
    let executor = start_adapter_hosts(domain, env, &boundary)?;

    let policy = match &env.policy_file {
        Some(f) => {
            let bytes =
                f.read(Visibility::Shared)?.ok_or_else(|| NodeError::Config(format!("{} is missing", f.path)))?;
            let text = String::from_utf8(bytes).map_err(|_| NodeError::Config(format!("{} is not UTF-8", f.path)))?;
            node::PolicySource::Cedar(text)
        }
        None => node::PolicySource::Default,
    };
    // Anti-rollback (v13 §7): the audit log must still contain the head recorded
    // in the state, and must not have seen a newer authority epoch than the
    // state holds. Either failure means stored data was replaced, truncated or
    // deleted; the node refuses to start rather than silently forgetting
    // revocations or quarantines.
    let state = node::load_domain_state(&env.state_file)?;
    let signer = Signer { id: cfg.node_id.clone(), key: node_key.clone() };
    let (audit, report) = AuditLog::open_anchored(
        env.audit_log.storage.as_ref(),
        &env.audit_log.path,
        Some(signer),
        state.audit_anchor.as_ref(),
    )
    .map_err(|e| NodeError::Integrity(format!("{e}; refusing to start (see specs/11-node-ipc.md \"Recovery\")")))?;
    // Time (v16 §4, threat model R3): the clock may not have been set back before
    // the last audited event — that would let expired tokens and requests live
    // again. From here on the trusted clock never goes backwards.
    let time = Arc::clone(&domain.platform.time);
    let wall_now = time.wall_ms();
    if wall_now.saturating_add(MAX_CLOCK_REGRESSION_MS) < report.max_ts_ms {
        return Err(NodeError::Integrity(format!(
            "the platform clock ({wall_now}) is {} s behind the last audited event ({}): clock rolled back? \
             fix the system time; refusing to start",
            (report.max_ts_ms - wall_now) / 1000,
            report.max_ts_ms
        )));
    }
    let trusted_clock = Arc::new(TrustedClock::new(time, report.max_ts_ms));
    if report.max_epoch > state.epoch {
        return Err(NodeError::Integrity(format!(
            "{} is at epoch {} but the audit log records epoch {}: the domain state was rolled back or deleted; refusing to start",
            env.state_file.path,
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
        agency: cfg
            .principals
            .iter()
            .filter(|p| !p.serves.is_empty())
            .map(|p| (p.id.clone(), p.serves.clone()))
            .collect(),
        devices: cfg.devices.clone(),
        resources: cfg.resources.clone(),
        safety: Default::default(),
        executor,
        policy,
        audit,
        state,
        state_file: Some(env.state_file.clone()),
        containment: cfg.containment,
        monitor: MonitorConfig::default(),
        entropy: Arc::clone(&domain.platform.entropy),
        clock: trusted_clock.as_clock(),
        clock_watch: Some(trusted_clock),
        boundary,
    })
    .map(|node| node.holding(claim))
}

/// Verify a stored audit log with the trusted node keys (`chitala audit
/// verify`, investigations): independent of the node that wrote it (v16 §7).
pub fn verify_audit(
    stored: &StoredObject,
    trusted: &HashMap<chitala_identity::KeyId, chitala_identity::PublicKey>,
) -> Result<chitala_audit::VerifyReport, NodeError> {
    chitala_audit::verify_stored(stored.storage.as_ref(), &stored.path, trusted)
        .map_err(|e| NodeError::Integrity(e.to_string()))?
        .ok_or_else(|| NodeError::Config(format!("{} does not exist", stored.path)))
}

/// How long the node waits for an adapter host before declaring it hung.
fn host_timeout(adapter: &str) -> Duration {
    match adapter {
        // HTTP to Home Assistant: 3 s connect + 10 s per call, execute + observe
        "home-assistant" => Duration::from_secs(30),
        // a matter.js invoke gives a silent device 13.5 s; the backend waits
        // 20 s for it, then reads the device (12 s at most)
        chitala_adapters::direct_matter::ADAPTER => Duration::from_secs(45),
        _ => Duration::from_secs(5),
    }
}

/// One adapter host component per adapter type (a Home Assistant failure cannot
/// take the virtual devices down with it). Each host gets an empty environment;
/// the Home Assistant host additionally gets its token variable and nothing else.
/// Every host accepts orders of `boundary` only.
pub fn start_adapter_hosts(
    domain: &Domain,
    env: &NodeEnv,
    boundary: &TrustedExecutionBoundary,
) -> Result<Arc<dyn executor::Executor>, NodeError> {
    let cfg = &domain.config;
    let mut groups: BTreeMap<&str, Vec<DeviceDescriptor>> = BTreeMap::new();
    for d in &cfg.devices {
        groups.entry(d.adapter.as_str()).or_default().push(d.clone());
    }
    let mut routed = executor::Routed::new();
    for (adapter, devices) in groups {
        let mut component = ComponentSpec { program: env.adapter_host.clone(), env: Vec::new() };
        let home_assistant = if adapter == "home-assistant" {
            let ha =
                cfg.home_assistant.clone().ok_or_else(|| NodeError::Config("home_assistant section missing".into()))?;
            component.env = env.home_assistant_env.iter().filter(|(k, _)| k == &ha.token_env).cloned().collect();
            Some(ha)
        } else {
            None
        };
        let matter = (adapter == chitala_adapters::direct_matter::ADAPTER)
            .then(|| cfg.matter.clone().ok_or_else(|| NodeError::Config("matter section missing".into())))
            .transpose()?;
        let ids: Vec<_> = devices.iter().map(|d| d.id.clone()).collect();
        let spec = executor::HostSpec {
            component,
            devices,
            home_assistant,
            matter,
            order_key: boundary.order_key(),
            timeout: host_timeout(adapter),
        };
        let host = executor::ComponentHost::start(
            Arc::clone(&domain.platform.exec),
            Arc::clone(&domain.platform.time),
            Arc::clone(&domain.platform.entropy),
            spec,
        )
        .map_err(|e| NodeError::Adapter(format!("{adapter}: {e}")))?;
        routed.add(Arc::new(host), &ids);
    }
    Ok(Arc::new(routed))
}
