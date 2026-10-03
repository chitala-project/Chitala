//! Home Assistant REST bridge (`/api/services`, `/api/states`).
//!
//! Lets Chitala control devices that already live in a Home Assistant install
//! without changing their firmware (v5 §11 "Phần cứng không có Chitala native").
//! Such devices cannot authenticate Chitala's command path themselves, so they
//! should be declared `SC0`/`SC1` in the node config — the default policy then
//! forbids high-risk commands on SC0 targets.
//!
//! The long-lived HA access token is read from an environment variable and never
//! stored in the config, printed or logged (v14 §6).

use std::collections::BTreeMap;
use std::time::Duration;

use chitala_model::{CapabilityId, EntityId, ParamValue, Payload};
use serde_json::{json, Value};

use crate::{AdapterError, DeviceAdapter, VerifiedOrder};

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
}

pub struct HomeAssistantAdapter {
    base_url: String,
    token: String,
    /// Chitala device id → HA entity id (`light.living_room`).
    entities: BTreeMap<EntityId, String>,
    agent: ureq::Agent,
}

impl std::fmt::Debug for HomeAssistantAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HomeAssistantAdapter")
            .field("base_url", &self.base_url)
            .field("token", &"[REDACTED]")
            .field("entities", &self.entities)
            .finish()
    }
}

/// The HA service call for a canonical capability: `(domain/service, body)`.
pub fn service_call(capability: &CapabilityId, entity_id: &str, p: &Payload) -> Option<(String, Value)> {
    let int = |k: &str| p.get(k).and_then(ParamValue::as_int);
    let (path, extra) = match capability.as_str() {
        "light.turn_on" => ("light/turn_on", json!({})),
        "light.turn_off" => ("light/turn_off", json!({})),
        "light.set_brightness" => match int("brightness_pct")? {
            0 => ("light/turn_off", json!({})),
            b => ("light/turn_on", json!({ "brightness_pct": b })),
        },
        "switch.turn_on" => ("switch/turn_on", json!({})),
        "switch.turn_off" => ("switch/turn_off", json!({})),
        "climate.set_target_temperature" => ("climate/set_temperature", json!({ "temperature": int("celsius")? })),
        "lock.lock" => ("lock/lock", json!({})),
        "lock.unlock" => ("lock/unlock", json!({})),
        _ => return None,
    };
    let mut body = extra;
    body["entity_id"] = Value::String(entity_id.to_string());
    Some((path.to_string(), body))
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
pub fn state_to_payload(entity_id: &str, state: &Value) -> Payload {
    let s = state.get("state").and_then(Value::as_str).unwrap_or("unknown");
    let attr = |k: &str| state.get("attributes").and_then(|a| a.get(k));
    let mut p = Payload::new();
    if s == "unavailable" || s == "unknown" {
        p.insert("available".into(), false.into());
        return p;
    }
    match entity_id.split('.').next() {
        Some("light") => {
            p.insert("on".into(), (s == "on").into());
            if let Some(b) = attr("brightness").and_then(Value::as_f64) {
                p.insert("brightness_pct".into(), ((b * 100.0 / 255.0).round() as i64).into());
            }
        }
        Some("switch") => {
            p.insert("on".into(), (s == "on").into());
        }
        Some("climate") => {
            if let Some(t) = attr("temperature").and_then(Value::as_f64) {
                p.insert("target_celsius".into(), (t.round() as i64).into());
            }
            if let Some(t) = attr("current_temperature").and_then(Value::as_f64) {
                p.insert("current_celsius".into(), (t.round() as i64).into());
            }
        }
        Some("lock") => {
            p.insert("locked".into(), (s == "locked").into());
        }
        _ => {
            p.insert("state".into(), ParamValue::Text(s.chars().take(64).collect()));
        }
    }
    p
}

impl HomeAssistantAdapter {
    /// `token_env` names the environment variable that holds the HA access token.
    ///
    /// Plain `http://` would send that token in clear over the LAN, so it is only
    /// accepted for loopback hosts unless `allow_insecure_http` is set explicitly
    /// (v7 §10: authenticated + encrypted by default; plaintext only for isolated
    /// legacy profiles).
    pub fn new(
        base_url: &str,
        token_env: &str,
        entities: BTreeMap<EntityId, String>,
        allow_insecure_http: bool,
    ) -> Result<Self, AdapterError> {
        check_transport(base_url, allow_insecure_http)?;
        let token = std::env::var(token_env)
            .map_err(|_| AdapterError::Failed(format!("environment variable {token_env} is not set")))?;
        let agent =
            ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(3)).timeout(Duration::from_secs(10)).build();
        Ok(Self { base_url: base_url.trim_end_matches('/').to_string(), token, entities, agent })
    }

    fn entity(&self, device: &EntityId) -> Result<&str, AdapterError> {
        self.entities
            .get(device)
            .map(String::as_str)
            .ok_or_else(|| AdapterError::Failed(format!("{device} is not mapped to a Home Assistant entity")))
    }

    fn http_err(e: ureq::Error) -> AdapterError {
        match e {
            ureq::Error::Status(code, _) if code == 401 || code == 403 => {
                AdapterError::Failed(format!("Home Assistant rejected the access token (HTTP {code})"))
            }
            ureq::Error::Status(code, _) => AdapterError::Failed(format!("Home Assistant returned HTTP {code}")),
            ureq::Error::Transport(t) => AdapterError::Unavailable(format!("Home Assistant unreachable: {}", t.kind())),
        }
    }
}

impl DeviceAdapter for HomeAssistantAdapter {
    fn name(&self) -> &str {
        "home-assistant"
    }

    fn manages(&self, device: &EntityId) -> bool {
        self.entities.contains_key(device)
    }

    fn observe(&mut self, device: &EntityId) -> Result<Payload, AdapterError> {
        let entity = self.entity(device)?.to_string();
        let state: Value = self
            .agent
            .get(&format!("{}/api/states/{entity}", self.base_url))
            .set("Authorization", &format!("Bearer {}", self.token))
            .call()
            .map_err(Self::http_err)?
            .into_json()
            .map_err(|e| AdapterError::Failed(format!("bad JSON from Home Assistant: {e}")))?;
        Ok(state_to_payload(&entity, &state))
    }

    fn execute(&mut self, action: &VerifiedOrder) -> Result<Payload, AdapterError> {
        let entity = self.entity(action.target())?.to_string();
        let (path, body) = service_call(action.capability(), &entity, action.payload())
            .ok_or_else(|| AdapterError::Failed(format!("no Home Assistant mapping for {}", action.capability())))?;
        self.agent
            .post(&format!("{}/api/services/{path}", self.base_url))
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(body)
            .map_err(Self::http_err)?;
        self.observe(action.target())
    }
}

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
        let (path, _) =
            service_call(&cap("light.set_brightness"), "light.lr", &payload([("brightness_pct", 0i64)])).unwrap();
        assert_eq!(path, "light/turn_off");
        let (path, body) =
            service_call(&cap("climate.set_target_temperature"), "climate.x", &payload([("celsius", 22i64)])).unwrap();
        assert_eq!((path.as_str(), body["temperature"].as_i64()), ("climate/set_temperature", Some(22)));
        assert!(service_call(&cap("device.read_state"), "light.lr", &Payload::new()).is_none());
    }

    #[test]
    fn state_mapping() {
        let p = state_to_payload("light.lr", &json!({"state": "on", "attributes": {"brightness": 128}}));
        assert_eq!(p, payload([("on", ParamValue::Bool(true)), ("brightness_pct", ParamValue::Int(50))]));
        let p = state_to_payload("lock.front", &json!({"state": "unlocked"}));
        assert_eq!(p, payload([("locked", false)]));
        let p = state_to_payload(
            "climate.x",
            &json!({"state": "cool", "attributes": {"temperature": 23.5, "current_temperature": 27.2}}),
        );
        assert_eq!(p.get("target_celsius"), Some(&ParamValue::Int(24)));
        let p = state_to_payload("light.lr", &json!({"state": "unavailable"}));
        assert_eq!(p, payload([("available", false)]));
    }

    #[test]
    fn token_comes_from_env_and_is_never_printed() {
        let var = "CHITALA_TEST_HA_TOKEN_DO_NOT_SET";
        assert!(HomeAssistantAdapter::new("https://ha.local:8123", var, BTreeMap::new(), false).is_err());
        std::env::set_var("CHITALA_TEST_HA_TOKEN", "super-secret-token");
        let a = HomeAssistantAdapter::new("https://ha.local:8123/", "CHITALA_TEST_HA_TOKEN", BTreeMap::new(), false)
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
