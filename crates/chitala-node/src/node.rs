//! The Home/Site Node (Blueprint v9 "Chitala Home/Site Server", v17 §3–4).
//!
//! `Node::handle` is the whole trust chain of milestone 0.0.1:
//!
//! ```text
//! signed CSME → Reference Monitor → (deny → audit + SecurityDenied event + containment)
//!                                 → (allow → audit → adapter / domain operation → twin → event → audit)
//! ```
//!
//! An allowed action is only executed after its decision record is durably in the
//! audit log ("no evidence, no action"). Domain operations — delegation,
//! revocation, security-state changes — are capabilities like any other and go
//! through the same monitor.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;

use chitala_adapters::{AdapterError, DeviceAdapter, Simulation};
use chitala_audit::{redact_payload, Anchor, AuditLog};
use chitala_bus::{EventBus, Filter, Subscription};
use chitala_identity::{IdentityRegistry, Keypair, PublicKey};
use chitala_model::{
    payload, CapabilityId, CapabilityRegistry, DenyCode, DeviceDescriptor, EntityId, EntityKind, Event, EventKind,
    ExecCode, ParamValue, Payload, SecurityState, TargetKind,
};
use chitala_monitor::{
    device_state, evaluate_policy, Authorized, Decision, Denial, Monitor, MonitorConfig, TargetInfo, Targets, World,
};
use chitala_policy::{DeviceAttrs, PolicyEngine};
use chitala_state::TwinStore;
use chitala_token::{bytes_from_base64, Grant, RevocationList, Right, TokenAuthority, TokenVerifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::config::{write_atomic, ContainmentConfig};
use crate::ipc::{request_digest, sign_reply, ExecError, Response, PROTOCOL};
use crate::NodeError;

pub type Clock = Box<dyn Fn() -> u64 + Send>;

/// Everything needed to build a node; produced from a config file or in memory.
pub struct NodeParts {
    pub domain: EntityId,
    pub node_id: EntityId,
    /// Signs replies (v10 manager authentication). Separate from the authority key.
    pub node_key: Keypair,
    pub authority_key: Keypair,
    pub principals: Vec<(EntityId, PublicKey, Vec<String>)>,
    pub devices: Vec<DeviceDescriptor>,
    pub adapters: Vec<Box<dyn DeviceAdapter>>,
    /// Cedar source; the embedded default policy when `None`.
    pub policy_src: Option<String>,
    pub audit: AuditLog,
    /// Persisted authority state (see [`load_domain_state`]); default for a new domain.
    pub state: DomainState,
    pub state_path: Option<PathBuf>,
    pub containment: ContainmentConfig,
    pub monitor: MonitorConfig,
    pub clock: Clock,
}

/// A token the domain issued, kept so revocation can follow the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedRecord {
    pub holder: EntityId,
    pub issuer: EntityId,
    pub rights: Vec<Right>,
    pub expires_at_ms: u64,
    pub depth: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// Authority state that must survive restarts (revocations, containment).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainState {
    /// Bumped on every authority change (v13 §7 policy/trust epoch).
    pub epoch: u64,
    pub revocations: RevocationList,
    /// Principals not in TRUSTED.
    pub principal_states: BTreeMap<EntityId, SecurityState>,
    pub issued: BTreeMap<String, IssuedRecord>,
    /// Audit head when this state was written. On start-up the audit log must
    /// still contain it, and the log may not record a higher epoch than this
    /// state: together they detect a rolled-back state file (un-revoking tokens)
    /// and a deleted or truncated audit log (v13 §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_anchor: Option<Anchor>,
}

/// Read the domain state file; a missing file is a new domain.
pub fn load_domain_state(path: &std::path::Path) -> Result<DomainState, NodeError> {
    if !path.exists() {
        return Ok(DomainState::default());
    }
    serde_json::from_str(&std::fs::read_to_string(path)?)
        .map_err(|e| NodeError::Config(format!("{}: {e}", path.display())))
}

struct Containment {
    cfg: ContainmentConfig,
    denials: HashMap<EntityId, VecDeque<u64>>,
}

impl Containment {
    /// Codes that indicate probing for authority rather than an honest mistake.
    /// `E_PRINCIPAL_STATE` counts too: a contained principal that keeps reaching
    /// above its risk ceiling is still probing.
    fn counts(code: DenyCode) -> bool {
        use DenyCode::*;
        matches!(
            code,
            PrincipalState
                | TokenMissing
                | TokenInvalid
                | TokenRevoked
                | TokenDenied
                | PolicyDenied
                | UnknownTarget
                | UnknownCapability
                | UnsupportedByTarget
                | RiskMismatch
                | Replay
                | RateLimited
        )
    }

    /// Record a denial; returns the state the actor should now be in, if any.
    fn record(&mut self, actor: &EntityId, now: u64) -> Option<(SecurityState, usize)> {
        let w = self.denials.entry(actor.clone()).or_default();
        w.push_back(now);
        while matches!(w.front(), Some(t) if *t + self.cfg.window_ms <= now) {
            w.pop_front();
        }
        let n = w.len();
        let state = if n >= self.cfg.quarantine_after as usize {
            SecurityState::Quarantined
        } else if n >= self.cfg.restricted_after as usize {
            SecurityState::Restricted
        } else if n >= self.cfg.suspicious_after as usize {
            SecurityState::Suspicious
        } else {
            return None;
        };
        Some((state, n))
    }
}

struct Directory<'a> {
    domain: &'a EntityId,
    domain_caps: &'a [CapabilityId],
    devices: &'a BTreeMap<EntityId, DeviceDescriptor>,
    identities: &'a IdentityRegistry,
}

impl Targets for Directory<'_> {
    fn target(&self, id: &EntityId) -> Option<TargetInfo> {
        if id == self.domain {
            return Some(TargetInfo {
                id: id.clone(),
                kind: TargetKind::Domain,
                capabilities: self.domain_caps.to_vec(),
                device: None,
            });
        }
        self.devices.get(id).map(|d| TargetInfo {
            id: id.clone(),
            kind: TargetKind::Device,
            capabilities: d.capabilities.clone(),
            device: Some(DeviceAttrs {
                security_class: d.security_class,
                room: d.room.clone(),
                state: device_state(self.identities, id),
            }),
        })
    }
}

macro_rules! directory {
    ($s:ident) => {
        Directory { domain: &$s.domain, domain_caps: &$s.domain_caps, devices: &$s.devices, identities: &$s.identities }
    };
}

macro_rules! world {
    ($s:ident, $dir:ident, $now:expr) => {
        World {
            identities: &$s.identities,
            registry: &$s.registry,
            targets: &$dir,
            tokens: &$s.verifier,
            revocations: &$s.state.revocations,
            policy: &$s.policy,
            now_ms: $now,
        }
    };
}

pub struct Node {
    domain: EntityId,
    node_id: EntityId,
    node_key: Keypair,
    identities: IdentityRegistry,
    registry: CapabilityRegistry,
    domain_caps: Vec<CapabilityId>,
    policy: PolicyEngine,
    authority: TokenAuthority,
    verifier: TokenVerifier,
    devices: BTreeMap<EntityId, DeviceDescriptor>,
    adapters: Vec<Box<dyn DeviceAdapter>>,
    monitor: Monitor,
    twins: TwinStore,
    bus: EventBus,
    audit: AuditLog,
    state: DomainState,
    state_path: Option<PathBuf>,
    containment: Containment,
    clock: Clock,
}

fn exec(code: ExecCode, message: impl Into<String>) -> ExecError {
    ExecError { code, message: message.into() }
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// The state a capability asks for, used as the twin's desired state.
fn desired_from(cap: &str, p: &Payload) -> Payload {
    let get = |k: &str| p.get(k).cloned();
    match cap {
        "light.turn_on" | "switch.turn_on" => payload([("on", true)]),
        "light.turn_off" | "switch.turn_off" => payload([("on", false)]),
        "light.set_brightness" => get("brightness_pct").map(|v| payload([("brightness_pct", v)])).unwrap_or_default(),
        "climate.set_target_temperature" => {
            get("celsius").map(|v| payload([("target_celsius", v)])).unwrap_or_default()
        }
        "lock.lock" => payload([("locked", true)]),
        "lock.unlock" => payload([("locked", false)]),
        _ => Payload::new(),
    }
}

impl Node {
    pub fn new(parts: NodeParts) -> Result<Self, NodeError> {
        let registry = CapabilityRegistry::core_v0_1();
        let policy = match &parts.policy_src {
            Some(src) => PolicyEngine::new(&registry, src)?,
            None => PolicyEngine::with_default_policies(&registry)?,
        };
        let mut identities = IdentityRegistry::new();
        for (id, pk, roles) in &parts.principals {
            let roles: Vec<&str> = roles.iter().map(String::as_str).collect();
            identities.enroll(id.clone(), *pk, &roles).map_err(|e| NodeError::Config(e.to_string()))?;
        }
        let state = parts.state;
        for (id, s) in &state.principal_states {
            // a principal removed from the config simply disappears
            let _ = identities.set_state(id, *s);
        }

        let mut devices = BTreeMap::new();
        for d in parts.devices {
            for c in &d.capabilities {
                match registry.get(c) {
                    Some(def) if def.target == TargetKind::Device => {}
                    _ => return Err(NodeError::Config(format!("{}: {c} is not a device capability", d.id))),
                }
            }
            if !parts.adapters.iter().any(|a| a.name() == d.adapter && a.manages(&d.id)) {
                return Err(NodeError::Config(format!("{}: no adapter {:?} manages it", d.id, d.adapter)));
            }
            if devices.insert(d.id.clone(), d).is_some() {
                return Err(NodeError::Config("duplicate device id".into()));
            }
        }
        let domain_caps = registry.iter().filter(|d| d.target == TargetKind::Domain).map(|d| d.id.clone()).collect();
        let authority = TokenAuthority::new(&parts.authority_key);
        let verifier = authority.verifier();

        let mut node = Self {
            domain: parts.domain,
            node_id: parts.node_id,
            node_key: parts.node_key,
            identities,
            registry,
            domain_caps,
            policy,
            authority,
            verifier,
            devices,
            adapters: parts.adapters,
            monitor: Monitor::new(parts.monitor),
            twins: TwinStore::default(),
            bus: EventBus::new(),
            audit: parts.audit,
            state,
            state_path: parts.state_path,
            containment: Containment { cfg: parts.containment, denials: HashMap::new() },
            clock: parts.clock,
        };
        let now = node.now();
        node.monitor.reject_issued_before(now);
        let ids: Vec<EntityId> = node.devices.keys().cloned().collect();
        for id in &ids {
            node.refresh(id, now);
        }
        let f = json!({
            "event": "start",
            "domain": node.domain.to_string(),
            "epoch": node.state.epoch,
            "policy_fp": node.policy.fingerprint(),
            "registry": format!("{}/{}", node.registry.name(), node.registry.version()),
            "devices": ids.len(),
            "principals": node.identities.principals().count(),
        });
        node.audit.append(now, "node", obj(f))?;
        Ok(node)
    }

    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    pub fn domain(&self) -> &EntityId {
        &self.domain
    }
    pub fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }
    pub fn identities(&self) -> &IdentityRegistry {
        &self.identities
    }
    pub fn twins(&self) -> &TwinStore {
        &self.twins
    }
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }
    pub fn domain_state(&self) -> &DomainState {
        &self.state
    }
    pub fn authority_public_key(&self) -> PublicKey {
        self.authority.public_key()
    }
    pub fn verifier(&self) -> &TokenVerifier {
        &self.verifier
    }
    pub fn subscribe(&self, filter: Filter) -> Subscription {
        self.bus.subscribe(filter)
    }

    /// Pre-authentication announcement: protocol versions and domain only
    /// (v4 §5 minimal metadata before authentication), signed by the node.
    pub fn hello(&self) -> Value {
        let mut v = json!({
            "protocol": PROTOCOL,
            "csme_versions": [chitala_csme::CSME_VERSION],
            "registry": format!("{}/{}", self.registry.name(), self.registry.version()),
            "domain": self.domain.to_string(),
        });
        sign_reply(&mut v, &self.node_id, &self.node_key);
        v
    }

    pub fn node_public_key(&self) -> PublicKey {
        self.node_key.public_key()
    }

    /// Write a signed audit checkpoint (e.g. on shutdown).
    pub fn checkpoint(&mut self) -> Result<(), NodeError> {
        let now = self.now();
        self.audit.checkpoint(now)?;
        Ok(())
    }

    // ───────────────────────────── request path ─────────────────────────────

    /// Judge and execute one request; the reply is bound to the request bytes and
    /// signed with the node key.
    pub fn handle(&mut self, bytes: &[u8]) -> Response {
        serde_json::from_value(self.handle_signed(bytes)).unwrap_or_default()
    }

    /// [`Node::handle`] as the signed JSON object sent over IPC.
    pub fn handle_signed(&mut self, bytes: &[u8]) -> Value {
        let mut r = self.decide_and_execute(bytes);
        r.request = Some(request_digest(bytes));
        let mut v = serde_json::to_value(&r).unwrap_or(Value::Null);
        sign_reply(&mut v, &self.node_id, &self.node_key);
        v
    }

    fn decide_and_execute(&mut self, bytes: &[u8]) -> Response {
        let now = self.now();
        let decision = {
            let dir = directory!(self);
            let world = world!(self, dir, now);
            self.monitor.check(&world, bytes)
        };
        match decision {
            Decision::Deny(d) => self.on_deny(d, now),
            Decision::Allow(a) => self.on_allow(a, now),
        }
    }

    fn on_deny(&mut self, d: Denial, now: u64) -> Response {
        let mid = d.message_id.map(hex::encode);
        let reason: String = d.reason.chars().take(300).collect();
        let mut f = obj(json!({
            "decision": "deny",
            "code": d.code.as_str(),
            "stage": d.stage.as_str(),
            "reason": reason,
            "authenticated": d.authenticated,
            "policy_fp": self.policy.fingerprint(),
            "epoch": self.state.epoch,
        }));
        let opt = |v: Option<String>| v.map(Value::String).unwrap_or(Value::Null);
        f.insert("actor".into(), opt(d.actor.as_ref().map(ToString::to_string)));
        f.insert("mid".into(), opt(mid.clone()));
        f.insert("target".into(), opt(d.target.as_ref().map(ToString::to_string)));
        f.insert("capability".into(), opt(d.capability.as_ref().map(ToString::to_string)));
        f.insert("token".into(), opt(d.token_id.clone()));
        f.insert("policy".into(), json!(d.policy_reasons));
        let seq = self.audit.append(now, "decision", f).ok().map(|a| a.seq);

        let mut data = payload([("code", d.code.as_str()), ("stage", d.stage.as_str())]);
        data.insert("authenticated".into(), d.authenticated.into());
        if let Some(c) = &d.capability {
            data.insert("capability".into(), ParamValue::Text(c.to_string()));
        }
        if let Some(t) = &d.target {
            data.insert("target".into(), ParamValue::Text(t.to_string()));
        }
        let source = d.actor.clone().unwrap_or_else(|| self.node_id.clone());
        self.publish(EventKind::SecurityDenied, source, data, mid.clone(), now);

        if let Some(actor) = d.actor.as_ref().filter(|a| d.authenticated && a.kind() != EntityKind::Person) {
            if Containment::counts(d.code) {
                self.contain(actor, now);
            }
        }

        Response {
            decision: "deny".into(),
            mid,
            code: Some(d.code),
            stage: Some(d.stage.as_str().into()),
            reason: d.authenticated.then_some(d.reason),
            result: None,
            error: None,
            audit_seq: seq,
            ..Default::default()
        }
    }

    /// Automatic containment of a non-human principal (v8 §9).
    fn contain(&mut self, actor: &EntityId, now: u64) {
        let Some((target, n)) = self.containment.record(actor, now) else { return };
        let Some(from) = self.identities.get(actor).map(|p| p.state) else { return };
        let on_ladder = matches!(from, SecurityState::Trusted | SecurityState::Suspicious | SecurityState::Restricted);
        if on_ladder && target > from && from.can_transition(target) {
            let reason = format!("{n} authority denials within {} ms", self.containment.cfg.window_ms);
            let by = self.node_id.clone();
            self.apply_state(actor, from, target, &by, &reason, now);
        }
    }

    fn on_allow(&mut self, a: Box<Authorized>, now: u64) -> Response {
        let mid = a.message_id_hex();
        let mut f = obj(json!({
            "decision": "allow",
            "mid": mid,
            "actor": a.actor().to_string(),
            "target": a.target().to_string(),
            "capability": a.capability().to_string(),
            "risk": a.def().risk.label(),
            "policy": a.policy_reasons(),
            "policy_fp": self.policy.fingerprint(),
            "epoch": self.state.epoch,
            "payload": redact_payload(a.payload()),
        }));
        if let Some(t) = a.token() {
            f.insert("token".into(), json!({"id": t.revocation_id, "issuer": t.issuer.to_string(), "depth": t.depth}));
        }
        // no evidence, no action
        let decision_seq = match self.audit.append(now, "decision", f) {
            Ok(x) => x.seq,
            Err(e) => {
                return Response {
                    decision: "allow".into(),
                    mid: Some(mid),
                    code: None,
                    stage: None,
                    reason: None,
                    result: None,
                    error: Some(exec(ExecCode::Internal, format!("audit unavailable, action not executed: {e}"))),
                    audit_seq: None,
                    ..Default::default()
                }
            }
        };

        let outcome = match a.def().target {
            TargetKind::Device => self.exec_device(&a, now),
            TargetKind::Domain => self.exec_domain(&a, now),
        };

        let mut f = obj(json!({ "mid": mid, "decision_seq": decision_seq }));
        match &outcome {
            Ok(_) => {
                f.insert("outcome".into(), json!("ok"));
            }
            Err(e) => {
                f.insert("outcome".into(), json!("error"));
                f.insert("code".into(), json!(e.code.as_str()));
                f.insert("message".into(), json!(e.message.chars().take(300).collect::<String>()));
            }
        }
        if let Some(t) = self.twins.get(a.target()) {
            f.insert("state_version".into(), json!(t.version));
        }
        let seq = self.audit.append(now, "execution", f).ok().map(|x| x.seq);

        let (result, error) = match outcome {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e)),
        };
        Response {
            decision: "allow".into(),
            mid: Some(mid),
            code: None,
            stage: None,
            reason: None,
            result,
            error,
            audit_seq: seq.or(Some(decision_seq)),
            ..Default::default()
        }
    }

    // ───────────────────────────── devices ─────────────────────────────

    fn adapter_for(&mut self, device: &EntityId) -> Option<&mut Box<dyn DeviceAdapter>> {
        let name = self.devices.get(device)?.adapter.clone();
        self.adapters.iter_mut().find(|a| a.name() == name && a.manages(device))
    }

    /// Observe a device and fold the observation into its twin.
    fn refresh(&mut self, device: &EntityId, now: u64) -> Option<AdapterError> {
        let Some(adapter) = self.adapter_for(device) else {
            return Some(AdapterError::Failed("no adapter".into()));
        };
        let name = adapter.name().to_string();
        match adapter.observe(device) {
            Ok(state) => {
                self.twins.ensure(device);
                if let Some(change) = self.twins.apply_reported(device, state, &name, now) {
                    let mut data = change.changed;
                    data.insert("version".into(), ParamValue::Int(change.version as i64));
                    self.publish(EventKind::StateChanged, device.clone(), data, None, now);
                }
                None
            }
            Err(e) => {
                self.twins.ensure(device);
                Some(e)
            }
        }
    }

    fn exec_device(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let device = a.target().clone();
        if a.capability().as_str() == "device.read_state" {
            let err = self.refresh(&device, now);
            let mut view = self.twins.view(&device, now);
            if let Some(e) = err {
                view["observe_error"] = json!(e.to_string());
            }
            return Ok(view);
        }
        self.twins.set_desired(&device, &desired_from(a.capability().as_str(), a.payload()), now);
        let mid = a.message_id_hex();
        let adapter =
            self.adapter_for(&device).ok_or_else(|| exec(ExecCode::Adapter, format!("no adapter for {device}")))?;
        let name = adapter.name().to_string();
        match adapter.execute(a) {
            Ok(state) => {
                if let Some(change) = self.twins.apply_reported(&device, state, &name, now) {
                    let mut data = change.changed;
                    data.insert("version".into(), ParamValue::Int(change.version as i64));
                    self.publish(EventKind::StateChanged, device.clone(), data, Some(mid), now);
                }
                Ok(self.twins.view(&device, now))
            }
            Err(e) => {
                let data = payload([("code", e.code().as_str().to_string()), ("message", e.to_string())]);
                self.publish(EventKind::AdapterError, device.clone(), data, Some(mid), now);
                let _ = self.refresh(&device, now);
                Err(exec(e.code(), e.to_string()))
            }
        }
    }

    /// Apply a simulated physical change to a virtual device (demo, tests).
    pub fn simulate(&mut self, device: &EntityId, change: Simulation) -> Result<(), NodeError> {
        let now = self.now();
        let adapter = self.adapter_for(device).ok_or_else(|| NodeError::Config(format!("unknown device {device}")))?;
        adapter.simulate(device, &change).map_err(|e| NodeError::Adapter(e.to_string()))?;
        self.refresh(device, now);
        Ok(())
    }

    // ───────────────────────────── domain operations ─────────────────────────────

    fn exec_domain(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        match a.capability().as_str() {
            "domain.list_devices" => Ok(self.list_devices()),
            "domain.delegate" => self.delegate(a, now),
            "domain.revoke_token" => self.revoke(a, now),
            "domain.set_principal_state" => self.set_state(a, now),
            other => Err(exec(ExecCode::Internal, format!("{other} is not implemented by this node"))),
        }
    }

    fn list_devices(&self) -> Value {
        let list: Vec<Value> = self
            .devices
            .values()
            .map(|d| {
                json!({
                    "id": d.id.to_string(),
                    "name": d.name,
                    "room": d.room,
                    "security_class": d.security_class.label(),
                    "adapter": d.adapter,
                    "capabilities": d.capabilities.iter().map(ToString::to_string).collect::<Vec<_>>(),
                })
            })
            .collect();
        json!({ "devices": list })
    }

    fn delegate(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let p = a.payload();
        let text = |k: &str| match p.get(k) {
            Some(ParamValue::Text(t)) => Ok(t.as_str()),
            _ => Err(exec(ExecCode::InvalidArgument, format!("missing {k}"))),
        };
        let bad = |e: &dyn std::fmt::Display| exec(ExecCode::InvalidArgument, e.to_string());
        let holder = EntityId::parse(text("holder")?).map_err(|e| bad(&e))?;
        let target = EntityId::parse(text("target")?).map_err(|e| bad(&e))?;
        let capability = CapabilityId::parse(text("capability")?).map_err(|e| bad(&e))?;
        let ttl_s = p.get("ttl_s").and_then(ParamValue::as_int).unwrap_or(0).max(0) as u64;
        let parent_text = match p.get("parent_token") {
            Some(ParamValue::Text(t)) => Some(t.clone()),
            _ => None,
        };
        let actor = a.actor().clone();
        if holder == actor {
            return Err(exec(ExecCode::DelegationDenied, "a principal cannot delegate to itself"));
        }
        let holder_p =
            self.identities.get(&holder).cloned().ok_or_else(|| {
                exec(ExecCode::InvalidArgument, format!("{holder} is not enrolled in {}", self.domain))
            })?;
        let actor_p = self.identities.get(&actor).cloned().ok_or_else(|| exec(ExecCode::Internal, "actor vanished"))?;
        let def = self
            .registry
            .get(&capability)
            .cloned()
            .ok_or_else(|| exec(ExecCode::InvalidArgument, format!("unknown capability {capability}")))?;
        let grant = Grant {
            holder: holder.clone(),
            issuer: actor.clone(),
            rights: vec![Right::new(target.clone(), capability.clone())],
            not_after_ms: now.saturating_add(ttl_s.saturating_mul(1000)),
        };

        let (issued, parent_id) = {
            let dir = directory!(self);
            let info = dir
                .target(&target)
                .filter(|t| t.kind == def.target && t.capabilities.contains(&capability))
                .ok_or_else(|| exec(ExecCode::InvalidArgument, format!("{target} does not offer {capability}")))?;
            let world = world!(self, dir, now);
            let internal = |e: &dyn std::fmt::Display| exec(ExecCode::Internal, e.to_string());

            // the holder must be able to use the right at all (Security Constitution)
            let hd = evaluate_policy(&world, &holder_p, &info, &def, true).map_err(|e| internal(&e))?;
            if !hd.allowed {
                return Err(exec(
                    ExecCode::DelegationDenied,
                    format!("{holder} may never use {capability} on {target} (forbidden by {})", hd.reasons.join(", ")),
                ));
            }
            match parent_text {
                Some(t) => {
                    let parent = bytes_from_base64(&t)
                        .and_then(|b| self.verifier.verify(&b))
                        .map_err(|e| exec(ExecCode::DelegationDenied, format!("parent token: {e}")))?;
                    if self.state.revocations.is_revoked(&parent) {
                        return Err(exec(ExecCode::DelegationDenied, "parent token has been revoked"));
                    }
                    let issued = self
                        .authority
                        .delegate(&parent, &actor, &grant, now)
                        .map_err(|e| exec(ExecCode::DelegationDenied, e.to_string()))?;
                    (issued, Some(parent.revocation_id))
                }
                None => {
                    let ad = evaluate_policy(&world, &actor_p, &info, &def, false).map_err(|e| internal(&e))?;
                    if !ad.allowed {
                        return Err(exec(
                            ExecCode::DelegationDenied,
                            format!("{actor} does not hold {capability} on {target}; present a parent_token"),
                        ));
                    }
                    let issued = self
                        .authority
                        .issue(&grant, now)
                        .map_err(|e| exec(ExecCode::DelegationDenied, e.to_string()))?;
                    (issued, None)
                }
            }
        };

        self.state.issued.retain(|_, r| r.expires_at_ms > now);
        self.state.issued.insert(
            issued.revocation_id.clone(),
            IssuedRecord {
                holder: holder.clone(),
                issuer: actor.clone(),
                rights: grant.rights.clone(),
                expires_at_ms: issued.expires_at_ms,
                depth: issued.depth,
                parent: parent_id.clone(),
            },
        );
        self.state.epoch += 1;
        self.save_state();
        let f = json!({
            "op": "issue",
            "token": issued.revocation_id,
            "holder": holder.to_string(),
            "issuer": actor.to_string(),
            "right": format!("{target}/{capability}"),
            "depth": issued.depth,
            "expires_at_ms": issued.expires_at_ms,
            "parent": parent_id,
            "epoch": self.state.epoch,
        });
        self.audit_signed(now, "authority", obj(f));
        let data = payload([
            ("op", "issue".to_string()),
            ("token", issued.revocation_id.clone()),
            ("holder", holder.to_string()),
        ]);
        self.publish(EventKind::AuthorityChanged, actor, data, Some(a.message_id_hex()), now);
        Ok(json!({
            "token": issued.base64,
            "revocation_id": issued.revocation_id,
            "expires_at_ms": issued.expires_at_ms,
            "depth": issued.depth,
            "holder": holder.to_string(),
            "target": target.to_string(),
            "capability": capability.to_string(),
        }))
    }

    fn revoke(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let rid = match a.payload().get("revocation_id") {
            Some(ParamValue::Text(t)) => t.trim().to_ascii_lowercase(),
            _ => return Err(exec(ExecCode::InvalidArgument, "missing revocation_id")),
        };
        if rid.len() != 128 || !rid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(exec(ExecCode::InvalidArgument, "revocation_id must be 128 hex digits"));
        }
        let actor = a.actor().clone();
        let privileged =
            self.identities.get(&actor).map(|p| p.roles.iter().any(|r| r == "owner" || r == "admin")).unwrap_or(false);
        // the issuer of the token or of any ancestor may revoke it
        let mut in_chain = false;
        let mut cursor = self.state.issued.get(&rid);
        let mut hops = 0;
        while let Some(r) = cursor {
            if r.issuer == actor {
                in_chain = true;
                break;
            }
            hops += 1;
            cursor = r.parent.as_ref().filter(|_| hops < 8).and_then(|p| self.state.issued.get(p));
        }
        if !(privileged || in_chain) {
            return Err(exec(
                ExecCode::NotPermitted,
                "only an issuer in the delegation chain, an owner or an admin may revoke this token",
            ));
        }
        let newly = self.state.revocations.revoke(&rid);
        if newly {
            self.state.epoch += 1;
            self.save_state();
            let f = json!({"op": "revoke", "token": rid, "by": actor.to_string(), "epoch": self.state.epoch});
            self.audit_signed(now, "authority", obj(f));
            let data = payload([("op", "revoke".to_string()), ("token", rid.clone())]);
            self.publish(EventKind::AuthorityChanged, actor, data, Some(a.message_id_hex()), now);
        }
        Ok(json!({ "revoked": rid, "already_revoked": !newly }))
    }

    fn set_state(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let p = a.payload();
        let principal = match p.get("principal") {
            Some(ParamValue::Text(t)) => {
                EntityId::parse(t).map_err(|e| exec(ExecCode::InvalidArgument, e.to_string()))?
            }
            _ => return Err(exec(ExecCode::InvalidArgument, "missing principal")),
        };
        let to = match p.get("state") {
            Some(ParamValue::Text(t)) => SecurityState::ALL
                .iter()
                .copied()
                .find(|s| s.label().eq_ignore_ascii_case(t.trim()))
                .ok_or_else(|| exec(ExecCode::InvalidArgument, format!("unknown security state {t:?}")))?,
            _ => return Err(exec(ExecCode::InvalidArgument, "missing state")),
        };
        if &principal == a.actor() {
            return Err(exec(ExecCode::NotPermitted, "a principal cannot change its own security state"));
        }
        let from = self
            .identities
            .get(&principal)
            .map(|p| p.state)
            .ok_or_else(|| exec(ExecCode::InvalidArgument, format!("{principal} is not enrolled")))?;
        if !from.can_transition(to) {
            return Err(exec(ExecCode::InvalidArgument, format!("transition {from} → {to} is not allowed")));
        }
        let by = a.actor().clone();
        self.apply_state(&principal, from, to, &by, "manual", now);
        Ok(json!({ "principal": principal.to_string(), "from": from.label(), "to": to.label() }))
    }

    fn apply_state(
        &mut self,
        principal: &EntityId,
        from: SecurityState,
        to: SecurityState,
        by: &EntityId,
        reason: &str,
        now: u64,
    ) {
        if self.identities.set_state(principal, to).is_err() {
            return;
        }
        if to == SecurityState::Trusted {
            self.state.principal_states.remove(principal);
        } else {
            self.state.principal_states.insert(principal.clone(), to);
        }
        self.state.epoch += 1;
        self.save_state();
        let f = json!({
            "principal": principal.to_string(),
            "from": from.label(),
            "to": to.label(),
            "by": by.to_string(),
            "reason": reason,
            "epoch": self.state.epoch,
        });
        self.audit_signed(now, "security_state", obj(f));
        let data = payload([
            ("from", from.label().to_string()),
            ("to", to.label().to_string()),
            ("by", by.to_string()),
            ("reason", reason.to_string()),
        ]);
        self.publish(EventKind::SecurityStateChanged, principal.clone(), data, None, now);
    }

    // ───────────────────────────── plumbing ─────────────────────────────

    /// Authority and security-state records are signed immediately: they are the
    /// evidence an investigator needs most (v16 §7).
    fn audit_signed(&mut self, now: u64, kind: &str, fields: Map<String, Value>) {
        if self.audit.append(now, kind, fields).is_ok() {
            let _ = self.audit.checkpoint(now);
        }
    }

    fn publish(&self, kind: EventKind, source: EntityId, data: Payload, caused_by: Option<String>, now: u64) {
        self.bus.publish(Event { id: random_id(), kind, source, ts_ms: now, data, caused_by });
    }

    /// Persist authority state *before* the matching audit record is written: a
    /// crash in between leaves the state ahead of the log, which start-up
    /// accepts; the opposite order would look like a rollback.
    fn save_state(&mut self) {
        self.state.audit_anchor = self.audit.anchor();
        let Some(path) = &self.state_path else { return };
        let text = serde_json::to_vec_pretty(&self.state).expect("domain state serializes");
        if let Err(e) = write_atomic(path, &text) {
            let now = self.now();
            let f = json!({"event": "state_write_failed", "error": e.to_string()});
            let _ = self.audit.append(now, "node", obj(f));
        }
    }
}
