//! The adapter host: adapters in their own process (spec `specs/10-twin-and-events.md`
//! §"Adapter isolation", Blueprint A.3).
//!
//! The node starts one host per adapter type as an isolated platform component
//! (on hosted platforms a process, spoken to over its stdin/stdout — a private
//! channel no other process can join). JSON lines, one request → one reply:
//!
//! ```text
//! → {"op":"init","node_public_key":"<hex>","devices":[…],"home_assistant":{…}}
//! ← {"ok":true,"devices":["device:…"]}
//! → {"op":"execute","device":"device:…","order":"<hex signed ExecOrder>"}
//! ← {"ok":true,"state":{"on":true}}
//! ← {"ok":false,"code":"X_DEVICE_REFUSED","message":"…"}
//! → {"op":"observe","device":"device:…"}
//! → {"op":"simulate","device":"device:…","change":{"door_open":true}}
//! ```
//!
//! The host holds no private key: it verifies orders with the node's *public*
//! key ([`crate::OrderGate`]). The node, in turn, treats every reply as untrusted
//! data ([`parse_reply`]): bounded size, bounded state, typed values only.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;

use chitala_identity::PublicKey;
use chitala_model::{DeviceDescriptor, EntityId, ParamValue, Payload};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::home_assistant::{HomeAssistantAdapter, HomeAssistantConfig};
use crate::mock::{MockAdapter, VirtualKind};
use crate::{AdapterError, Clock, DeviceAdapter, OrderGate, Simulation};

/// Longest line accepted in either direction.
pub const MAX_LINE: usize = 64 * 1024;
/// Bounds on a device state reported by a host.
pub const MAX_STATE_ENTRIES: usize = 64;
pub const MAX_STATE_KEY: usize = 64;
pub const MAX_STATE_TEXT: usize = 256;
pub const MAX_MESSAGE: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInit {
    /// Hex Ed25519 public key of the node; orders must be signed with it.
    pub node_public_key: String,
    pub devices: Vec<DeviceDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_assistant: Option<HomeAssistantConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimChange {
    Offline(bool),
    DoorOpen(bool),
    FailNext { code: String, message: String },
}

impl From<&Simulation> for SimChange {
    fn from(s: &Simulation) -> Self {
        match s {
            Simulation::Offline(b) => SimChange::Offline(*b),
            Simulation::DoorOpen(b) => SimChange::DoorOpen(*b),
            Simulation::FailNext(e) => {
                SimChange::FailNext { code: e.code().as_str().to_string(), message: e.message().to_string() }
            }
        }
    }
}

impl From<SimChange> for Simulation {
    fn from(s: SimChange) -> Self {
        match s {
            SimChange::Offline(b) => Simulation::Offline(b),
            SimChange::DoorOpen(b) => Simulation::DoorOpen(b),
            SimChange::FailNext { code, message } => Simulation::FailNext(AdapterError::from_code(&code, message)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum HostRequest {
    Init(HostInit),
    Execute { device: EntityId, order: String },
    Observe { device: EntityId },
    Simulate { device: EntityId, change: SimChange },
}

pub struct AdapterHost {
    gate: OrderGate,
    adapters: Vec<Box<dyn DeviceAdapter>>,
}

fn parse_key(hex_str: &str) -> Result<PublicKey, AdapterError> {
    hex::decode(hex_str.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| AdapterError::Failed("node_public_key must be 32 bytes of hex".into()))
}

impl AdapterHost {
    pub fn new(node_key: PublicKey, adapters: Vec<Box<dyn DeviceAdapter>>, clock: Clock) -> Self {
        Self { gate: OrderGate::new(node_key, clock), adapters }
    }

    /// Build the adapters for `init.devices`; every device must be served.
    pub fn from_init(init: HostInit, clock: Clock) -> Result<Self, AdapterError> {
        let node_key = parse_key(&init.node_public_key)?;
        let mut mock = MockAdapter::new();
        let mut ha_entities = BTreeMap::new();
        for d in &init.devices {
            match d.adapter.as_str() {
                "mock" => {
                    let kind = VirtualKind::from_capabilities(&d.capabilities)
                        .ok_or_else(|| AdapterError::Failed(format!("{}: cannot infer a virtual device type", d.id)))?;
                    mock.add(d.id.clone(), kind);
                }
                "home-assistant" => {
                    let ha = init
                        .home_assistant
                        .as_ref()
                        .ok_or_else(|| AdapterError::Failed("home_assistant section missing".into()))?;
                    let entity = ha
                        .entities
                        .get(&d.id)
                        .ok_or_else(|| AdapterError::Failed(format!("{}: no Home Assistant entity mapping", d.id)))?;
                    ha_entities.insert(d.id.clone(), entity.clone());
                }
                other => return Err(AdapterError::Failed(format!("{}: unknown adapter {other:?}", d.id))),
            }
        }
        let mut adapters: Vec<Box<dyn DeviceAdapter>> = vec![Box::new(mock)];
        if let (Some(ha), false) = (&init.home_assistant, ha_entities.is_empty()) {
            adapters.push(Box::new(HomeAssistantAdapter::new(
                &ha.base_url,
                &ha.token_env,
                ha_entities,
                ha.allow_insecure_http,
            )?));
        }
        Ok(Self::new(node_key, adapters, clock))
    }

    pub fn manages(&self, device: &EntityId) -> bool {
        self.adapters.iter().any(|a| a.manages(device))
    }

    fn adapter(&mut self, device: &EntityId) -> Result<&mut Box<dyn DeviceAdapter>, AdapterError> {
        self.adapters
            .iter_mut()
            .find(|a| a.manages(device))
            .ok_or_else(|| AdapterError::Failed(format!("{device} is not served by this adapter host")))
    }

    /// Admit the order (node signature, freshness, single use), then execute it.
    pub fn execute(&mut self, device: &EntityId, order: &[u8]) -> Result<Payload, AdapterError> {
        let order = self.gate.admit(order)?;
        if order.target() != device {
            return Err(AdapterError::Rejected(format!("order is for {}, not {device}", order.target())));
        }
        self.adapter(device)?.execute(&order)
    }

    pub fn observe(&mut self, device: &EntityId) -> Result<Payload, AdapterError> {
        self.adapter(device)?.observe(device)
    }

    pub fn simulate(&mut self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        self.adapter(device)?.simulate(device, change)
    }

    /// Handle one request line; returns the reply line.
    pub fn handle_line(&mut self, line: &str) -> String {
        let result = match serde_json::from_str::<HostRequest>(line.trim()) {
            Ok(HostRequest::Execute { device, order }) => match hex::decode(order.trim()) {
                Ok(bytes) => self.execute(&device, &bytes).map(Some),
                Err(_) => Err(AdapterError::Rejected("order must be hex".into())),
            },
            Ok(HostRequest::Observe { device }) => self.observe(&device).map(Some),
            Ok(HostRequest::Simulate { device, change }) => self.simulate(&device, &change.into()).map(|_| None),
            Ok(HostRequest::Init(_)) => Err(AdapterError::Failed("already initialised".into())),
            Err(e) => Err(AdapterError::Failed(format!("bad request: {e}"))),
        };
        reply_line(result)
    }
}

fn reply_line(result: Result<Option<Payload>, AdapterError>) -> String {
    match result {
        Ok(Some(state)) => json!({"ok": true, "state": state}).to_string(),
        Ok(None) => json!({"ok": true}).to_string(),
        Err(e) => json!({"ok": false, "code": e.code().as_str(), "message": e.message()}).to_string(),
    }
}

fn bounded(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// A reply that does not follow the protocol: the host itself is broken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed adapter host reply: {0}")]
pub struct Malformed(pub String);

/// Node side: validate one reply line from a host. The host is less trusted than
/// the core, so its output is untrusted data — this is a fuzz target.
///
/// `Err(Malformed)` means the host broke the protocol; `Ok(Err(_))` is an error
/// the host reported for the device.
pub fn parse_reply(line: &str) -> Result<Result<Option<Payload>, AdapterError>, Malformed> {
    let bad = |why: &str| Malformed(why.to_string());
    if line.len() > MAX_LINE {
        return Err(bad("too long"));
    }
    let v: Value = serde_json::from_str(line).map_err(|_| bad("not JSON"))?;
    match v.get("ok") {
        Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) => {
            let code = v.get("code").and_then(Value::as_str).unwrap_or("X_ADAPTER");
            let message = bounded(v.get("message").and_then(Value::as_str).unwrap_or(""), MAX_MESSAGE);
            return Ok(Err(AdapterError::from_code(code, message)));
        }
        _ => return Err(bad("missing ok")),
    }
    let Some(state) = v.get("state") else { return Ok(Ok(None)) };
    let obj = state.as_object().ok_or_else(|| bad("state is not an object"))?;
    if obj.len() > MAX_STATE_ENTRIES {
        return Err(bad("state too large"));
    }
    let mut p = Payload::new();
    for (k, val) in obj {
        if k.is_empty() || k.chars().count() > MAX_STATE_KEY || k.chars().any(char::is_control) {
            return Err(bad("bad state key"));
        }
        let pv = match val {
            Value::Bool(b) => ParamValue::Bool(*b),
            Value::Number(n) => ParamValue::Int(n.as_i64().ok_or_else(|| bad("state numbers must be integers"))?),
            Value::String(s) if s.chars().count() <= MAX_STATE_TEXT => ParamValue::Text(s.clone()),
            _ => return Err(bad("state values must be bool, integer or short text")),
        };
        p.insert(k.clone(), pv);
    }
    Ok(Ok(Some(p)))
}

fn read_bounded_line(reader: &mut impl BufRead) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    let n = reader.take(MAX_LINE as u64 + 1).read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if n > MAX_LINE {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
    }
    Ok(Some(line))
}

/// The host keeps time the same way as the node: wall clock in, never backwards.
fn system_clock() -> Clock {
    let source = Arc::new(chitala_platform_host::SystemTimeSource::new());
    Arc::new(chitala_platform::TrustedClock::new(source, 0)).as_clock()
}

/// Entry point of the `chitala-adapter-host` binary. Returns the exit code.
pub fn run_stdio() -> i32 {
    let stdin = std::io::stdin();
    run(&mut BufReader::new(stdin.lock()), &mut std::io::stdout(), system_clock())
}

/// Serve the line protocol on any byte channel (the stdio of a process, or the
/// channel of an in-memory component). Returns the exit code.
pub fn run(reader: &mut impl BufRead, out: &mut impl Write, clock: Clock) -> i32 {
    let init = match read_bounded_line(reader) {
        Ok(Some(line)) => serde_json::from_str::<HostRequest>(line.trim()),
        _ => return 2,
    };
    let mut host = match init {
        Ok(HostRequest::Init(init)) => match AdapterHost::from_init(init, clock) {
            Ok(h) => h,
            Err(e) => {
                let _ = writeln!(out, "{}", reply_line(Err(e)));
                return 1;
            }
        },
        _ => {
            let _ = writeln!(out, "{}", reply_line(Err(AdapterError::Failed("first message must be init".into()))));
            return 2;
        }
    };
    if writeln!(out, "{}", json!({"ok": true})).and_then(|_| out.flush()).is_err() {
        return 1;
    }
    loop {
        match read_bounded_line(reader) {
            Ok(Some(line)) => {
                let reply = host.handle_line(&line);
                if writeln!(out, "{reply}").and_then(|_| out.flush()).is_err() {
                    return 1;
                }
            }
            Ok(None) => return 0,
            Err(_) => return 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{fixed_clock, node_key, order, NOW};
    use chitala_model::{payload, SecurityClass};

    fn init() -> HostInit {
        HostInit {
            node_public_key: hex::encode(node_key().public_key()),
            devices: vec![
                DeviceDescriptor {
                    id: EntityId::parse("device:light").unwrap(),
                    name: "Light".into(),
                    adapter: "mock".into(),
                    capabilities: VirtualKind::Light.capabilities(),
                    security_class: SecurityClass::Sc2,
                    room: None,
                },
                DeviceDescriptor {
                    id: EntityId::parse("device:door").unwrap(),
                    name: "Door".into(),
                    adapter: "mock".into(),
                    capabilities: VirtualKind::Lock.capabilities(),
                    security_class: SecurityClass::Sc3,
                    room: None,
                },
            ],
            home_assistant: None,
        }
    }

    fn id(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }

    #[test]
    fn executes_only_admitted_orders_for_the_named_device() {
        let (clock, _) = fixed_clock(NOW);
        let mut host = AdapterHost::from_init(init(), clock).unwrap();
        assert!(host.manages(&id("device:light")));
        let o = order(&id("device:light"), "light.turn_on", Payload::new()).sign(&node_key());
        assert_eq!(host.execute(&id("device:light"), &o).unwrap().get("on"), Some(&ParamValue::Bool(true)));
        assert!(matches!(host.execute(&id("device:light"), &o), Err(AdapterError::Rejected(_))), "replay");
        // an order for the light cannot be redirected to the door
        let o = order(&id("device:light"), "lock.unlock", Payload::new()).sign(&node_key());
        assert!(matches!(host.execute(&id("device:door"), &o), Err(AdapterError::Rejected(_))));
    }

    #[test]
    fn line_protocol_round_trip() {
        let (clock, _) = fixed_clock(NOW);
        let mut host = AdapterHost::from_init(init(), clock).unwrap();
        let o = order(&id("device:light"), "light.set_brightness", payload([("brightness_pct", 30i64)]));
        let req = serde_json::to_string(&HostRequest::Execute {
            device: id("device:light"),
            order: hex::encode(o.sign(&node_key())),
        })
        .unwrap();
        let state = parse_reply(&host.handle_line(&req)).unwrap().unwrap().unwrap();
        assert_eq!(state.get("brightness_pct"), Some(&ParamValue::Int(30)));
        let sim = serde_json::to_string(&HostRequest::Simulate {
            device: id("device:door"),
            change: SimChange::from(&Simulation::DoorOpen(true)),
        })
        .unwrap();
        assert_eq!(parse_reply(&host.handle_line(&sim)), Ok(Ok(None)));
        let refused = order(&id("device:door"), "lock.lock", Payload::new()).sign(&node_key());
        let req =
            serde_json::to_string(&HostRequest::Execute { device: id("device:door"), order: hex::encode(refused) })
                .unwrap();
        assert!(matches!(parse_reply(&host.handle_line(&req)), Ok(Err(AdapterError::Refused(_)))));
        // a request the host cannot parse is a well-formed error reply, not a broken host
        assert!(matches!(parse_reply(&host.handle_line("not json")), Ok(Err(AdapterError::Failed(_)))));
    }

    #[test]
    fn replies_are_untrusted_data() {
        assert!(parse_reply("").is_err());
        assert!(parse_reply(r#"{"state":{}}"#).is_err(), "ok is required");
        assert!(parse_reply(r#"{"ok":true,"state":{"x":1.5}}"#).is_err());
        assert!(parse_reply(r#"{"ok":true,"state":{"x":{"y":1}}}"#).is_err());
        assert!(parse_reply(&format!(r#"{{"ok":true,"state":{{"x":"{}"}}}}"#, "a".repeat(MAX_STATE_TEXT + 1))).is_err());
        let many: String = (0..=MAX_STATE_ENTRIES).map(|i| format!(r#""k{i}":1"#)).collect::<Vec<_>>().join(",");
        assert!(parse_reply(&format!(r#"{{"ok":true,"state":{{{many}}}}}"#)).is_err());
        let e =
            parse_reply(&format!(r#"{{"ok":false,"code":"X_DEVICE_REFUSED","message":"{}\u0007"}}"#, "m".repeat(999)))
                .unwrap()
                .unwrap_err();
        assert!(matches!(&e, AdapterError::Refused(m) if m.len() == MAX_MESSAGE));
        let ok = parse_reply(r#"{"ok":true,"state":{"on":true,"pct":3,"mode":"cool"}}"#);
        assert_eq!(ok.unwrap().unwrap().unwrap().len(), 3);
    }

    #[test]
    fn init_rejects_unknown_adapters_and_bad_keys() {
        let (clock, _) = fixed_clock(NOW);
        let mut bad = init();
        bad.devices[0].adapter = "zigbee".into();
        assert!(AdapterHost::from_init(bad, clock.clone()).is_err());
        let mut bad = init();
        bad.node_public_key = "abc".into();
        assert!(AdapterHost::from_init(bad, clock).is_err());
    }
}
