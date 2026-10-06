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
use crate::{DeviceAdapter, Observed, Provenance, VerifiedOrder};
#[cfg(feature = "home-assistant")]
use std::time::{Duration, Instant};

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
    /// The Matter server's WebSocket API (`ws://127.0.0.1:5580/ws`), on this
    /// machine only: Matter devices are read there for evidence of what an
    /// order did (finding F10). Without it their outcomes stay unconfirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matter_server: Option<String>,
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
    /// The integration that provides it (`matter`, `zha`, …); `None` for an
    /// entity outside the entity registry.
    pub platform: Option<String>,
    /// The device it belongs to: the entities of one device share it.
    pub device: Option<DeviceInfo>,
    /// Home Assistant's `device_class` (a switch's `outlet` or `switch`).
    pub device_class: Option<String>,
    /// What can confirm its state after a command (finding F9b).
    pub evidence: Evidence,
}

/// What can confirm an entity's state after a command (spec 25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// The device itself: a Matter device asked through Home Assistant
    /// (which needs an administrator's token).
    Device,
    /// Home Assistant's word only: a lower assurance, not physical proof.
    HomeAssistant,
}

/// A device in Home Assistant's device registry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
}

/// An entity of a class the profile drives that discovery leaves out, and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Excluded {
    pub entity_id: String,
    pub reason: String,
}

/// What discovery found.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Discovery {
    pub proposed: Vec<Discovered>,
    pub excluded: Vec<Excluded>,
}

fn bounded(v: &Value, max: usize) -> Option<String> {
    v.as_str().map(|s| s.chars().filter(|c| !c.is_control()).take(max).collect())
}

/// Why discovery leaves out an entity, by its entity registry entry: a
/// device's configuration or diagnostic entity (`entity_category`), which is
/// not the device's own control, or an entity disabled in Home Assistant.
/// A Matter lock's privacy-mode switch is in the `switch` domain, yet it is
/// no plug (v0.3 step ③A, finding F7).
fn left_out(entry: &Value) -> Option<String> {
    if let Some(category) = bounded(&entry["entity_category"], 32) {
        return Some(format!("a {category} entity of its device (entity_category: {category})"));
    }
    bounded(&entry["disabled_by"], 32).map(|by| format!("disabled in Home Assistant (by {by})"))
}

/// The entities among Home Assistant's `states` that a profile class covers,
/// told apart by its entity registry (`config/entity_registry/list`) and
/// device registry (`config/device_registry/list`). An entity outside the
/// entity registry has no category: it is proposed.
pub fn discover_in(states: &Value, entities: &Value, devices: &Value) -> Discovery {
    let profile = HomeProfile::v0_1();
    let registry: BTreeMap<&str, &Value> =
        entities.as_array().into_iter().flatten().filter_map(|e| Some((e["entity_id"].as_str()?, e))).collect();
    let devices: BTreeMap<&str, &Value> =
        devices.as_array().into_iter().flatten().filter_map(|d| Some((d["id"].as_str()?, d))).collect();
    let mut found = Discovery { proposed: Vec::new(), excluded: Vec::new() };
    for s in states.as_array().into_iter().flatten() {
        let Some(entity) = s.get("entity_id").and_then(Value::as_str) else { continue };
        let Some(class) = profile.for_entity(entity) else { continue };
        let entity_id: String = entity.chars().take(128).collect();
        let entry = registry.get(entity).copied();
        if let Some(reason) = entry.and_then(left_out) {
            found.excluded.push(Excluded { entity_id, reason });
            continue;
        }
        let platform = entry.and_then(|e| bounded(&e["platform"], 32));
        let device = entry.and_then(|e| e["device_id"].as_str()).and_then(|id| devices.get(id)).map(|d| DeviceInfo {
            id: d["id"].as_str().unwrap_or_default().chars().take(64).collect(),
            name: bounded(&d["name_by_user"], 64).or_else(|| bounded(&d["name"], 64)),
            manufacturer: bounded(&d["manufacturer"], 64),
            model: bounded(&d["model"], 64),
        });
        let dims = brightness_supported(s);
        found.proposed.push(Discovered {
            entity_id,
            class: class.class.clone(),
            name: bounded(&s["attributes"]["friendly_name"], 64),
            capabilities: class
                .capabilities()
                .filter(|c| dims || c.as_str() != "light.set_brightness")
                .cloned()
                .collect(),
            state: class.ha_state(s).map_err(|e| e.to_string()),
            evidence: if platform.as_deref() == Some("matter") { Evidence::Device } else { Evidence::HomeAssistant },
            platform,
            device,
            device_class: bounded(&s["attributes"]["device_class"], 32),
        });
    }
    found
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
#[path = "matter_evidence.rs"]
pub mod matter_evidence;

/// How long an observation for evidence waits for a read of a Matter device
/// before it calls the state unconfirmed; the read goes on, and a later
/// observation takes its values (findings F9b, F10).
#[cfg(feature = "home-assistant")]
pub const REACH_WAIT: Duration = crate::device_read::READ_WAIT;
/// A Matter device that did not answer a read is not read again before this.
#[cfg(feature = "home-assistant")]
pub const REACH_RETRY: Duration = crate::device_read::READ_RETRY;

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
    /// Reads Matter devices for evidence, when configured (finding F10).
    matter: Option<matter_evidence::MatterEvidence>,
    /// Matter endpoints → reads of them.
    reads: BTreeMap<matter_evidence::Target, crate::device_read::DeviceRead<matter_evidence::Values>>,
}

/// What stands behind a Home Assistant entity's state.
#[cfg(feature = "home-assistant")]
enum Backing {
    /// A Matter device's endpoint, which the Matter server can read.
    Matter(matter_evidence::Target),
    /// Another integration's entity, or one outside the entity registry:
    /// Home Assistant's word is all there is (spec 25, a lower assurance).
    Other,
    /// Not known: no entity registry read yet, or a Matter entity whose
    /// node cannot be told.
    Unknown,
}

/// The WebSocket API's URL for `base_url`.
#[cfg(feature = "home-assistant")]
fn ws_url(base_url: &str) -> String {
    match base_url.split_once("://") {
        Some(("https", rest)) => format!("wss://{rest}/api/websocket"),
        Some((_, rest)) => format!("ws://{rest}/api/websocket"),
        None => format!("ws://{base_url}/api/websocket"),
    }
}

#[cfg(feature = "home-assistant")]
fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
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

/// How old a state Home Assistant answered over REST is: its clock at the
/// answer (`Date`, whole seconds, so up to 999 ms later than it says) minus the
/// last time the integration wrote the state (`last_reported`, else
/// `last_updated`). `None` without both.
pub fn rest_age_ms(state: &Value, date_ms: Option<u64>) -> Option<u64> {
    let written = ["last_reported", "last_updated"]
        .iter()
        .filter_map(|k| state.get(*k).and_then(Value::as_str).and_then(ha_time_ms))
        .max()?;
    Some(date_ms?.saturating_sub(written) + 999)
}

/// A Home Assistant timestamp (UTC, `2026-10-05T10:00:00.123456+00:00`) in
/// ms since the epoch.
pub fn ha_time_ms(s: &str) -> Option<u64> {
    let s = s.strip_suffix("+00:00").or_else(|| s.strip_suffix('Z'))?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.splitn(3, '-').map(str::parse::<u32>);
    let (y, m, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.splitn(3, ':').map(str::parse::<u64>);
    let (h, mi, sec) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    if h > 23 || mi > 59 || sec > 60 || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let ms = format!("{frac:0<3}")[..3].parse::<u64>().ok()?;
    Some(days_from_civil(y, m, day)? * 86_400_000 + h * 3_600_000 + mi * 60_000 + sec * 1000 + ms)
}

/// An HTTP date (`Sun, 05 Oct 2026 12:00:00 GMT`) in ms since the epoch.
pub fn http_date_ms(s: &str) -> Option<u64> {
    let mut it = s.split_whitespace();
    let (_, day, mon, year, hms, zone) = (it.next()?, it.next()?, it.next()?, it.next()?, it.next()?, it.next()?);
    if zone != "GMT" {
        return None;
    }
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let m = MONTHS.iter().position(|x| *x == mon)? as u32 + 1;
    let mut t = hms.splitn(3, ':').map(str::parse::<u64>);
    let (h, mi, sec) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    Some(
        days_from_civil(year.parse().ok()?, m, day.parse().ok()?)? * 86_400_000
            + h * 3_600_000
            + mi * 60_000
            + sec * 1000,
    )
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: u32, m: u32, d: u32) -> Option<u64> {
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = i64::from(if m <= 2 { y - 1 } else { y });
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).ok()
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
        let link = timing
            .map(|t| link::Link::start(ws_url(&base_url), token.clone(), entities.values().cloned().collect(), t));
        let gate = link.as_ref().map_or_else(|| link::AuthGate::new(&link::Timing::default()), |l| l.gate().clone());
        Ok(Self { base_url, token, entities, agent, link, gate, matter: None, reads: BTreeMap::new() })
    }

    /// Read Matter devices for evidence through the Matter server at `url`
    /// (on this machine only), each read within `timeout` (finding F10).
    pub fn with_matter_evidence(mut self, url: &str, timeout: Duration) -> Result<Self, AdapterError> {
        self.matter = Some(matter_evidence::MatterEvidence::new(url, timeout)?);
        Ok(self)
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
        self.get_dated(path).map(|(v, _)| v)
    }

    /// [`Self::get`], with Home Assistant's own clock at the answer (its `Date`
    /// header, in ms since the epoch), when it sends one.
    fn get_dated(&self, path: &str) -> Result<(Value, Option<u64>), AdapterError> {
        self.gate_open()?;
        let response = self
            .agent
            .get(&format!("{}{path}", self.base_url))
            .set("Authorization", &format!("Bearer {}", self.token))
            .call();
        match response {
            Ok(r) => {
                self.gate.accepted();
                let date = r.header("Date").and_then(http_date_ms);
                let v =
                    r.into_json().map_err(|e| AdapterError::Failed(format!("bad JSON from Home Assistant: {e}")))?;
                Ok((v, date))
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

    /// The entities Home Assistant has that the Home profile can drive: its
    /// states over REST, and its entity and device registries over the
    /// WebSocket API (any user's token may read them). Without the registries
    /// discovery cannot tell a device's own control from its configuration
    /// entities, so it fails rather than guess (finding F7).
    pub fn discover(&self) -> Result<Discovery, AdapterError> {
        // a rejected token was turned away by this REST read already
        let states = self.get("/api/states")?;
        let commands = [
            serde_json::json!({"type": "config/entity_registry/list"}),
            serde_json::json!({"type": "config/device_registry/list"}),
        ];
        let registries = link::query(&ws_url(&self.base_url), &self.token, link::Timing::default(), &commands)
            .map_err(|e| {
                AdapterError::Failed(format!(
                    "discovery needs Home Assistant's entity registry, read over its WebSocket API: {e}"
                ))
            })?;
        Ok(discover_in(&states, &registries[0], &registries[1]))
    }

    fn backing(&self, entity: &str) -> Backing {
        match self.link.as_ref().and_then(|l| l.registered(entity)) {
            None => Backing::Unknown,
            Some(Some(r)) if r.platform == "matter" => r
                .unique_id
                .as_deref()
                .and_then(matter_evidence::Target::of_unique_id)
                .map_or(Backing::Unknown, Backing::Matter),
            Some(_) => Backing::Other,
        }
    }

    /// For evidence: the Matter device's own state, read through the Matter
    /// server (F10), and when the read began. Values that came back are taken
    /// once; otherwise a read begins (one at a time, not again for
    /// [`REACH_RETRY`] after a failure) and is waited for up to
    /// [`REACH_WAIT`]. Only the attributes the profile maps are read.
    fn read_device(&mut self, entity: &str, target: matter_evidence::Target) -> Option<(Instant, Payload)> {
        let provider = self.matter.clone()?;
        let class = HomeProfile::v0_1().for_entity(entity)?;
        let attributes: Vec<(u32, u32)> = class
            .matter
            .attributes
            .iter()
            .filter_map(|a| Some((crate::profile::hex_id(&a.cluster)?, crate::profile::hex_id(&a.attribute)?)))
            .collect();
        let (began, values) =
            self.reads.entry(target).or_default().take(REACH_WAIT, move || provider.read(target, &attributes))?;
        class.matter_state(&values).ok().map(|state| (began, state))
    }

    /// Whether Home Assistant's state of an entity, `age_ms` old, is tied to
    /// its device now. For another integration Home Assistant's word stands, a
    /// lower assurance (spec 25). For a Matter device it never is: Home
    /// Assistant re-emits a dead lock's cached value with a new timestamp
    /// (F9b), and nothing it offers ties its state to the device (F10). Only a
    /// read of the device itself is evidence there ([`Self::read_device`]).
    fn provenance(backing: &Backing, age_ms: Option<u64>) -> Provenance {
        match backing {
            Backing::Other => age_ms.map_or(Provenance::Uncertain, |age_ms| Provenance::ConfirmedCurrent { age_ms }),
            Backing::Matter(_) | Backing::Unknown => Provenance::Uncertain,
        }
    }

    /// The state pushed on the live link, else one REST read. If neither
    /// answers, the observation fails: nothing is made up.
    ///
    /// How old the state is: for one the link heard pushed, since it heard it;
    /// for a REST read, Home Assistant's clock at the answer minus the last
    /// time its integration wrote the state (both by Home Assistant's clock,
    /// so no skew between the two machines counts). A state from the link's
    /// bootstrap has no age anyone can tell (finding F9). Whether it is tied to
    /// the device now: [`Self::provenance`] (F9b, F10).
    ///
    /// With `evidence`, a Matter device is read itself first: its own state,
    /// confirmed as of when the read began.
    fn observe_as(&mut self, device: &EntityId, evidence: bool) -> Result<Observed, AdapterError> {
        let entity = self.entity(device)?.to_string();
        let backing = self.backing(&entity);
        if let (true, Backing::Matter(target)) = (evidence, &backing) {
            if let Some((began, state)) = self.read_device(&entity, *target) {
                let age_ms = ms(began.elapsed());
                return Ok(Observed {
                    state,
                    age_ms: Some(age_ms),
                    provenance: Provenance::ConfirmedCurrent { age_ms },
                });
            }
        }
        if let Some((state, heard)) = self.link.as_ref().and_then(|l| l.heard(&entity)) {
            let age_ms = heard.map(|h| ms(h.elapsed()));
            let provenance = Self::provenance(&backing, age_ms);
            return state_to_payload(&entity, &state).map(|state| Observed { state, age_ms, provenance });
        }
        if self.link.as_ref().and_then(|l| l.has(&entity)) == Some(false) {
            return Err(AdapterError::Unavailable(format!("Home Assistant has no entity {entity}")));
        }
        let (state, date) = self.get_dated(&format!("/api/states/{entity}"))?;
        let age_ms = rest_age_ms(&state, date);
        let provenance = Self::provenance(&backing, age_ms);
        state_to_payload(&entity, &state).map(|state| Observed { state, age_ms, provenance })
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

    /// The state pushed on the live link, else one REST read, how old it is
    /// and whether it is tied to the device now; no device is asked.
    fn observe(&mut self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.observe_as(device, false)
    }

    /// As `observe`, but a Matter device is asked to answer, so its state can
    /// be confirmed current (F9b).
    fn observe_evidence(&mut self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.observe_as(device, true)
    }

    /// One transport per order, one attempt: the live link, else REST. A call
    /// the link never wrote may still go by REST; one it wrote is never sent
    /// again.
    fn execute(&mut self, action: VerifiedOrder) -> Result<Payload, AdapterError> {
        let entity = self.entity(action.target())?.to_string();
        let (path, body) = service_call(action.capability(), &entity, action.payload())
            .ok_or_else(|| AdapterError::Failed(format!("no Home Assistant mapping for {}", action.capability())))?;
        // Home Assistant would answer success and do nothing (F2): refused
        // only on the live connection's own word that the entity is not there
        if self.link.as_ref().and_then(|l| l.has(&entity)) == Some(false) {
            return Err(AdapterError::Failed(format!(
                "Home Assistant has no entity {entity} (by its live connection); nothing was sent"
            )));
        }
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
        self.observe(action.target()).map(|o| o.state).map_err(|e| {
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
