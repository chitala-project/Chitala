//! Home Assistant bridge (spec 25): the WebSocket API first, REST to bootstrap
//! and as a fallback.
//!
//! Lets Chitala control devices that already live in a Home Assistant install
//! without changing their firmware (v5 §11 "hardware without native Chitala support").
//!
//! The adapter has two roles only: it **executes** orders the Trusted
//! Execution Boundary signed, and it **observes**. It grants no authority,
//! interprets no policy, and never sends a command twice: a command whose
//! fate is unknown is reported as indeterminate, and Chitala's outcome
//! verification observes the world to decide (spec 22).
//! Such devices cannot authenticate Chitala's command path themselves, so they
//! should be declared `SC0`/`SC1` in the node config — the default policy then
//! forbids high-risk commands on SC0 targets.
//!
//! The long-lived HA access token is read from an environment variable and never
//! stored in the config, printed or logged (v14 §6).
//!
//! Lights, plugs and locks are mapped by the Home Capability Profile (spec 24):
//! the services that execute each capability and the normalised state of each
//! Home Assistant state, with nothing guessed. Climate entities keep a mapping
//! of their own, outside profile v0.1.
//!
//! The bridge itself (HTTP and TLS) is the `home-assistant` feature, part of
//! the hosted build; the config and the service mapping are always here.

use std::collections::BTreeMap;

use chitala_model::{CapabilityId, EntityId, ParamValue, Payload};
use serde_json::{json, Value};

use crate::profile::HomeProfile;
use crate::AdapterError;
#[cfg(feature = "home-assistant")]
use crate::{DeviceAdapter, VerifiedOrder};

/// Home Assistant section of the node config (also sent to the adapter host).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HomeAssistantConfig {
    pub base_url: String,
    /// Name of the environment variable holding the HA access token.
    pub token_env: String,
    /// Chitala device id → HA entity id.
    pub entities: BTreeMap<EntityId, String>,
    /// Allow `http://` to a non-loopback host (token sent unencrypted).
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// Keep a WebSocket link for pushed states and service calls (default);
    /// `false` uses only the REST API.
    #[serde(default = "websocket_default")]
    pub websocket: bool,
}

fn websocket_default() -> bool {
    true
}

/// The entity a Chitala device is mapped to must be of the kind its
/// capabilities say: a lock's entity in the `lock` domain, and so on (spec 24).
/// A mapping to the wrong kind of entity is refused when the host starts.
pub fn check_entity(device: &chitala_model::DeviceDescriptor, entity: &str) -> Result<(), AdapterError> {
    let domain = entity.split('.').next().unwrap_or_default();
    let fits = match HomeProfile::v0_1().for_capabilities(&device.capabilities) {
        Some(class) => class.home_assistant.domain == domain,
        // outside profile v0.1
        None => {
            domain == "climate" && device.capabilities.iter().any(|c| c.as_str() == "climate.set_target_temperature")
        }
    };
    if fits && entity.len() > domain.len() + 1 {
        Ok(())
    } else {
        Err(AdapterError::Failed(format!("{}: {entity:?} is not a Home Assistant entity of its kind", device.id)))
    }
}

/// An entity Home Assistant has that the Home profile knows how to drive,
/// proposed for the configuration. Discovery proposes; people decide what
/// Chitala governs and who may act on it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Discovered {
    pub entity_id: String,
    pub class: String,
    pub name: Option<String>,
    pub capabilities: Vec<CapabilityId>,
    /// The normalised state, or why there is none.
    pub state: Result<Payload, String>,
}

/// The entities among Home Assistant's states that a profile class covers.
pub fn discover_in(states: &Value) -> Vec<Discovered> {
    let profile = HomeProfile::v0_1();
    states
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| {
            let entity = s.get("entity_id")?.as_str()?;
            let class = profile.for_entity(entity)?;
            let dims = brightness_supported(s);
            Some(Discovered {
                entity_id: entity.chars().take(128).collect(),
                class: class.class.clone(),
                name: s["attributes"]["friendly_name"].as_str().map(|n| n.chars().take(64).collect()),
                capabilities: class
                    .capabilities()
                    .filter(|c| dims || c.as_str() != "light.set_brightness")
                    .cloned()
                    .collect(),
                state: class.ha_state(s).map_err(|e| e.to_string()),
            })
        })
        .collect()
}

/// Home Assistant's own rule: a light dims when one of its color modes is
/// anything but `onoff`. A light that declares no color modes is not assumed
/// to dim.
fn brightness_supported(state: &Value) -> bool {
    state["attributes"]["supported_color_modes"]
        .as_array()
        .is_some_and(|modes| modes.iter().filter_map(Value::as_str).any(|m| m != "onoff" && m != "unknown"))
}

#[cfg(feature = "home-assistant")]
#[path = "ha_link.rs"]
pub mod link;

#[cfg(feature = "home-assistant")]
pub struct HomeAssistantAdapter {
    base_url: String,
    token: String,
    /// Chitala device id → HA entity id (`light.living_room`).
    entities: BTreeMap<EntityId, String>,
    agent: ureq::Agent,
    /// The WebSocket link, when enabled: pushed states and service calls.
    link: Option<link::Link>,
    /// Shared with the link: a rejected token is not presented again at once.
    gate: link::AuthGate,
}

#[cfg(feature = "home-assistant")]
impl std::fmt::Debug for HomeAssistantAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HomeAssistantAdapter")
            .field("base_url", &self.base_url)
            .field("token", &"[REDACTED]")
            .field("entities", &self.entities)
            .field("link", &self.link)
            .finish()
    }
}

/// The HA service call for a canonical capability: `(domain/service, body)`.
/// Lights, plugs and locks follow the Home profile; `None` when nothing maps
/// the capability for this entity.
pub fn service_call(capability: &CapabilityId, entity_id: &str, p: &Payload) -> Option<(String, Value)> {
    if let Some(class) = HomeProfile::v0_1().for_entity(entity_id) {
        return class.ha_call(capability, entity_id, p);
    }
    // outside profile v0.1
    match (entity_id.split('.').next(), capability.as_str()) {
        (Some("climate"), "climate.set_target_temperature") => {
            let celsius = p.get("celsius").and_then(ParamValue::as_int)?;
            Some(("climate/set_temperature".into(), json!({ "entity_id": entity_id, "temperature": celsius })))
        }
        _ => None,
    }
}

/// Only `https://`, or `http://` to a loopback host, unless explicitly allowed.
pub fn check_transport(base_url: &str, allow_insecure_http: bool) -> Result<(), AdapterError> {
    let lower = base_url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    let Some(rest) = lower.strip_prefix("http://") else {
        return Err(AdapterError::Failed(format!("unsupported URL scheme in {base_url:?}")));
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or_default()
    } else {
        authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority)
    };
    let loopback = host == "localhost" || host == "::1" || host.starts_with("127.");
    if loopback || allow_insecure_http {
        Ok(())
    } else {
        Err(AdapterError::Failed(format!(
            "{base_url} is plain HTTP to a non-loopback host: the access token would cross the network unencrypted; \
             use https:// or set allow_insecure_http for an isolated network"
        )))
    }
}

/// Map an HA state object to the canonical reported state of a Chitala device.
/// `unavailable` and `unknown` are failed observations, not states (spec 24):
/// a witness that cannot be observed must never look like one that reports
/// something else (spec 22).
pub fn state_to_payload(entity_id: &str, state: &Value) -> Result<Payload, AdapterError> {
    if let Some(class) = HomeProfile::v0_1().for_entity(entity_id) {
        return class.ha_state(state);
    }
    let s = state.get("state").and_then(Value::as_str).unwrap_or("unknown");
    if s == "unavailable" || s == "unknown" {
        return Err(AdapterError::Unavailable(format!("Home Assistant reports {entity_id} as {s}")));
    }
    let attr = |k: &str| state.get("attributes").and_then(|a| a.get(k)).and_then(Value::as_f64);
    match entity_id.split('.').next() {
        // outside profile v0.1
        Some("climate") => {
            let mut p = Payload::new();
            if let Some(t) = attr("temperature") {
                p.insert("target_celsius".into(), (t.round() as i64).into());
            }
            if let Some(t) = attr("current_temperature") {
                p.insert("current_celsius".into(), (t.round() as i64).into());
            }
            Ok(p)
        }
        _ => Err(AdapterError::Failed(format!("{entity_id}: this kind of entity is not supported"))),
    }
}

#[cfg(feature = "home-assistant")]
impl HomeAssistantAdapter {
    /// `token_env` names the environment variable that holds the HA access token.
    ///
    /// Plain `http://` would send that token in clear over the LAN, so it is only
    /// accepted for loopback hosts unless `allow_insecure_http` is set explicitly
    /// (v7 §10: authenticated + encrypted by default; plaintext only for isolated
    /// legacy profiles). The WebSocket link starts in the background.
    pub fn new(
        base_url: &str,
        token_env: &str,
        entities: BTreeMap<EntityId, String>,
        allow_insecure_http: bool,
    ) -> Result<Self, AdapterError> {
        Self::with_link(base_url, token_env, entities, allow_insecure_http, Some(link::Timing::default()))
    }

    /// [`HomeAssistantAdapter::new`] with the link's timing, or without a link
    /// (`None`: REST only).
    pub fn with_link(
        base_url: &str,
        token_env: &str,
        entities: BTreeMap<EntityId, String>,
        allow_insecure_http: bool,
        timing: Option<link::Timing>,
    ) -> Result<Self, AdapterError> {
        check_transport(base_url, allow_insecure_http)?;
        let token = std::env::var(token_env)
            .map_err(|_| AdapterError::Failed(format!("environment variable {token_env} is not set")))?;
        // no idle connections: a pooled connection gone stale is the one case
        // in which an HTTP client resends a request on its own
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(10))
            .max_idle_connections(0)
            .build();
        let base_url = base_url.trim_end_matches('/').to_string();
        let link = timing.map(|t| {
            let ws = match base_url.split_once("://") {
                Some(("https", rest)) => format!("wss://{rest}/api/websocket"),
                Some((_, rest)) => format!("ws://{rest}/api/websocket"),
                None => format!("ws://{base_url}/api/websocket"),
            };
            link::Link::start(ws, token.clone(), entities.values().cloned().collect(), t)
        });
        let gate = link.as_ref().map_or_else(|| link::AuthGate::new(&link::Timing::default()), |l| l.gate().clone());
        Ok(Self { base_url, token, entities, agent, link, gate })
    }

    /// The WebSocket link, if any (for diagnostics and tests).
    pub fn link(&self) -> Option<&link::Link> {
        self.link.as_ref()
    }

    fn entity(&self, device: &EntityId) -> Result<&str, AdapterError> {
        self.entities
            .get(device)
            .map(String::as_str)
            .ok_or_else(|| AdapterError::Failed(format!("{device} is not mapped to a Home Assistant entity")))
    }

    /// While the gate is closed nothing is sent ([`link::AuthGate`]).
    fn gate_open(&self) -> Result<(), AdapterError> {
        self.gate.check().map_err(|wait| {
            AdapterError::Failed(format!(
                "Home Assistant rejected the access token; it is presented again in {} s (nothing was sent)",
                wait.as_secs() + 1
            ))
        })
    }

    /// A read: any user's token may read, so a rejection here means the token
    /// itself is not accepted.
    fn get(&self, path: &str) -> Result<Value, AdapterError> {
        self.gate_open()?;
        let response = self
            .agent
            .get(&format!("{}{path}", self.base_url))
            .set("Authorization", &format!("Bearer {}", self.token))
            .call();
        match response {
            Ok(r) => {
                self.gate.accepted();
                r.into_json().map_err(|e| AdapterError::Failed(format!("bad JSON from Home Assistant: {e}")))
            }
            Err(e) => {
                if matches!(e, ureq::Error::Status(401, _)) {
                    self.gate.rejected();
                }
                Err(Self::http_err(e, false))
            }
        }
    }

    /// One REST service call. A request that may have reached Home Assistant
    /// and whose answer is unknown is indeterminate, never retried.
    fn post_service(&self, path: &str, body: Value) -> Result<(), AdapterError> {
        self.gate_open()?;
        self.agent
            .post(&format!("{}/api/services/{path}", self.base_url))
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(body)
            .map(|_| ())
            .map_err(|e| Self::http_err(e, true))
    }

    fn http_err(e: ureq::Error, command: bool) -> AdapterError {
        match e {
            ureq::Error::Status(code, _) if code == 401 || code == 403 => {
                AdapterError::Failed(format!("Home Assistant rejected the access token (HTTP {code})"))
            }
            // Home Assistant refused the request before running it
            ureq::Error::Status(code, _) if code < 500 => {
                AdapterError::Failed(format!("Home Assistant refused the request (HTTP {code})"))
            }
            ureq::Error::Status(code, _) if command => AdapterError::Indeterminate(format!(
                "Home Assistant failed the call (HTTP {code}); the command may have executed"
            )),
            ureq::Error::Status(code, _) => AdapterError::Unavailable(format!("Home Assistant returned HTTP {code}")),
            ureq::Error::Transport(t)
                if matches!(t.kind(), ureq::ErrorKind::ConnectionFailed | ureq::ErrorKind::Dns) =>
            {
                AdapterError::Unavailable(format!("Home Assistant unreachable: {}", t.kind()))
            }
            ureq::Error::Transport(t) if command => AdapterError::Indeterminate(format!(
                "the connection to Home Assistant broke ({}); the command may have executed",
                t.kind()
            )),
            ureq::Error::Transport(t) => AdapterError::Unavailable(format!("Home Assistant unreachable: {}", t.kind())),
        }
    }

    /// The entities Home Assistant has that the Home profile can drive.
    pub fn discover(&self) -> Result<Vec<Discovered>, AdapterError> {
        Ok(discover_in(&self.get("/api/states")?))
    }
}

#[cfg(feature = "home-assistant")]
impl DeviceAdapter for HomeAssistantAdapter {
    fn name(&self) -> &str {
        "home-assistant"
    }

    fn manages(&self, device: &EntityId) -> bool {
        self.entities.contains_key(device)
    }

    /// The state pushed on the live link, else one REST read. If neither
    /// answers, the observation fails: nothing is made up.
    fn observe(&mut self, device: &EntityId) -> Result<Payload, AdapterError> {
        let entity = self.entity(device)?.to_string();
        if let Some(state) = self.link.as_ref().and_then(|l| l.state(&entity)) {
            return state_to_payload(&entity, &state);
        }
        let state = self.get(&format!("/api/states/{entity}"))?;
        state_to_payload(&entity, &state)
    }

    /// One transport per order, one attempt: the live link, else REST. A call
    /// the link never wrote may still go by REST; one it wrote is never sent
    /// again.
    fn execute(&mut self, action: VerifiedOrder) -> Result<Payload, AdapterError> {
        let entity = self.entity(action.target())?.to_string();
        let (path, body) = service_call(action.capability(), &entity, action.payload())
            .ok_or_else(|| AdapterError::Failed(format!("no Home Assistant mapping for {}", action.capability())))?;
        let by_link = match self.link.as_ref().filter(|l| l.live()) {
            None => None,
            Some(l) => {
                let (domain, service) = path.split_once('/').unwrap_or((path.as_str(), ""));
                let mut data = body.clone();
                if let Some(m) = data.as_object_mut() {
                    m.remove("entity_id");
                }
                match l.call(domain, service, data, &entity) {
                    Ok(()) => Some(Ok(())),
                    Err(link::CallError::NotSent(_)) => None,
                    Err(link::CallError::Indeterminate(why)) => Some(Err(AdapterError::Indeterminate(why))),
                    Err(link::CallError::Refused(why)) => Some(Err(AdapterError::Failed(why))),
                }
            }
        };
        match by_link {
            Some(r) => r?,
            None => self.post_service(&path, body)?,
        }
        // Home Assistant ran it; if the entity cannot be observed now, there is
        // no state to vouch for: its fate is unknown, never made up
        self.observe(action.target()).map_err(|e| {
            AdapterError::Indeterminate(format!("Home Assistant ran the call, but the entity cannot be observed: {e}"))
        })
    }
}

#[cfg(all(test, feature = "home-assistant"))]
#[path = "ha_tests.rs"]
mod ha_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_model::payload;

    fn cap(s: &str) -> CapabilityId {
        CapabilityId::parse(s).unwrap()
    }

    #[test]
    fn service_mapping() {
        let (path, body) =
            service_call(&cap("light.set_brightness"), "light.lr", &payload([("brightness_pct", 40i64)])).unwrap();
        assert_eq!(path, "light/turn_on");
        assert_eq!(body, json!({"entity_id": "light.lr", "brightness_pct": 40}));
        // Home Assistant turns a light off at brightness 0
        let (path, body) =
            service_call(&cap("light.set_brightness"), "light.lr", &payload([("brightness_pct", 0i64)])).unwrap();
        assert_eq!((path.as_str(), body["brightness_pct"].as_i64()), ("light/turn_on", Some(0)));
        // a capability on the wrong kind of entity maps to nothing
        assert!(service_call(&cap("lock.unlock"), "light.lr", &Payload::new()).is_none());
        let (path, body) =
            service_call(&cap("climate.set_target_temperature"), "climate.x", &payload([("celsius", 22i64)])).unwrap();
        assert_eq!((path.as_str(), body["temperature"].as_i64()), ("climate/set_temperature", Some(22)));
        assert!(service_call(&cap("device.read_state"), "light.lr", &Payload::new()).is_none());
    }

    #[test]
    fn state_mapping() {
        let p = state_to_payload("light.lr", &json!({"state": "on", "attributes": {"brightness": 128}})).unwrap();
        assert_eq!(p, payload([("on", ParamValue::Bool(true)), ("brightness_pct", ParamValue::Int(50))]));
        let p = state_to_payload("lock.front", &json!({"state": "unlocked"})).unwrap();
        assert_eq!(p, payload([("locked", false)]));
        // a lock still unlocking has not unlocked: no `locked` key (spec 24)
        let p = state_to_payload("lock.front", &json!({"state": "unlocking"})).unwrap();
        assert_eq!(p, payload([("moving", true)]));
        let p = state_to_payload(
            "climate.x",
            &json!({"state": "cool", "attributes": {"temperature": 23.5, "current_temperature": 27.2}}),
        )
        .unwrap();
        assert_eq!(p.get("target_celsius"), Some(&ParamValue::Int(24)));
        // not a state: a failed observation
        assert!(matches!(
            state_to_payload("light.lr", &json!({"state": "unavailable"})),
            Err(AdapterError::Unavailable(_))
        ));
        assert!(matches!(
            state_to_payload("climate.x", &json!({"state": "unknown"})),
            Err(AdapterError::Unavailable(_))
        ));
        assert!(state_to_payload("vacuum.x", &json!({"state": "docked"})).is_err());
    }

    #[test]
    fn token_comes_from_env_and_is_never_printed() {
        let var = "CHITALA_TEST_HA_TOKEN_DO_NOT_SET";
        assert!(HomeAssistantAdapter::with_link("https://ha.local:8123", var, BTreeMap::new(), false, None).is_err());
        std::env::set_var("CHITALA_TEST_HA_TOKEN", "super-secret-token");
        let a = HomeAssistantAdapter::with_link(
            "https://ha.local:8123/",
            "CHITALA_TEST_HA_TOKEN",
            BTreeMap::new(),
            false,
            None,
        )
        .unwrap();
        let dbg = format!("{a:?}");
        assert!(!dbg.contains("super-secret-token"));
        assert_eq!(a.base_url, "https://ha.local:8123");
    }

    #[test]
    fn plaintext_http_only_to_loopback_or_when_explicitly_allowed() {
        assert!(check_transport("https://ha.example", false).is_ok());
        assert!(check_transport("http://localhost:8123", false).is_ok());
        assert!(check_transport("http://127.0.0.1:8123", false).is_ok());
        assert!(check_transport("http://[::1]:8123", false).is_ok());
        assert!(check_transport("http://192.168.1.10:8123", false).is_err());
        assert!(check_transport("http://localhost.evil.com", false).is_err());
        assert!(check_transport("http://192.168.1.10:8123", true).is_ok());
        assert!(check_transport("ftp://x", true).is_err());
    }
}
