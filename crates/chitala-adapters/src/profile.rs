//! The Home Capability Profile (spec `specs/24-home-profile.md`).
//!
//! The profile normalises the devices of a home — lights, plugs, locks — so
//! that every backend reports the same state for the same thing and executes
//! the same capability the same way. The normative profile lives in
//! `specs/profiles/home-v0.1.json` and is embedded here verbatim.
//!
//! Each device class declares:
//!
//! - the capabilities it requires and may offer (all in the core registry);
//! - its normalised state: keys, types, ranges, which keys are required;
//! - how Home Assistant executes and reports it (domain, services, states,
//!   attributes);
//! - how Matter does (device types, cluster commands, attributes).
//!
//! One rule governs normalisation: **what cannot be known is left out, never
//! guessed.** A lock that is moving or jammed reports no `locked` key, and an
//! entity Home Assistant calls `unavailable` or `unknown` is an observation
//! error, not a state. Outcome verification (spec 22) relies on it: a lock
//! still unlocking must never verify an unlock.
//!
//! The profile lives outside the Trusted Core. Backends only execute and
//! observe; they never decide authority.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use chitala_model::{
    CapabilityId, CapabilityKind, CapabilityRegistry, Expected, ParamType, ParamValue, Payload, TargetKind,
};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::AdapterError;

/// The normative Home Capability Profile v0.1.
pub const HOME_PROFILE_V0_1: &str = include_str!("../../../specs/profiles/home-v0.1.json");

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    profile: String,
    profile_version: String,
    status: String,
    registry: String,
    classes: Vec<DeviceClass>,
}

/// A loaded, self-consistent profile.
#[derive(Debug, Clone)]
pub struct HomeProfile {
    name: String,
    version: String,
    registry: String,
    classes: Vec<DeviceClass>,
}

/// One kind of device: a light, a plug, a lock.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceClass {
    pub class: String,
    pub description: String,
    /// The resource kinds (spec 14) such a device is usually bound to.
    pub resource_kinds: Vec<String>,
    pub required: Vec<CapabilityId>,
    pub optional: Vec<CapabilityId>,
    pub state: BTreeMap<String, StateKey>,
    /// Guidance for a domain's configuration: risk floors, a safe state.
    pub recommended: Recommended,
    pub home_assistant: HaMapping,
    pub matter: MatterMapping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateType {
    Boolean,
    Integer,
    Text,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateKey {
    #[serde(rename = "type")]
    pub ty: StateType,
    #[serde(default)]
    pub required: bool,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub max_len: Option<usize>,
    pub description: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recommended {
    /// Capability → the risk floor a domain should usually set (spec 14).
    #[serde(default)]
    pub risk_floor: BTreeMap<CapabilityId, String>,
    /// The action a resource of this class should declare as its safe state (spec 22).
    pub safe_state: Option<CapabilityId>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaMapping {
    /// The Home Assistant entity domain (`light`, `switch`, `lock`).
    pub domain: String,
    /// Capability → the service of `domain` that executes it.
    pub services: BTreeMap<CapabilityId, HaService>,
    /// Home Assistant state → the normalised state it means.
    pub states: BTreeMap<String, Payload>,
    /// Attribute → the normalised key it scales to.
    pub attributes: BTreeMap<String, Scale>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaService {
    pub service: String,
    /// Service data: literals, or `{"param": name}` for the action's parameters.
    #[serde(default)]
    pub data: BTreeMap<String, Expected>,
}

/// A linear map of a number from one range onto an integer key's range.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scale {
    pub key: String,
    pub from: [f64; 2],
    pub to: [i64; 2],
}

impl Scale {
    fn apply(&self, x: f64) -> i64 {
        let [a, b] = self.from;
        let [lo, hi] = self.to;
        let y = lo as f64 + (x - a) * (hi - lo) as f64 / (b - a);
        (y.round() as i64).clamp(lo, hi)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatterMapping {
    /// Matter device type ids (hex) of such devices.
    pub device_types: Vec<String>,
    /// Capability → the cluster command that executes it.
    pub commands: BTreeMap<CapabilityId, MatterCommand>,
    pub attributes: Vec<MatterAttribute>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatterCommand {
    pub cluster: String,
    pub command: String,
    /// Not yet confirmed against a Matter controller (v0.3 step 5).
    #[serde(default)]
    pub provisional: bool,
    /// The command must be sent as a Timed Invoke: without one, the device
    /// answers `NEEDS_TIMED_INTERACTION` (0xC6) and does nothing. Door Lock's
    /// `LockDoor` and `UnlockDoor` are (checked at runtime in v0.3 step ③A).
    #[serde(default)]
    pub timed: bool,
}

/// One attribute of a cluster and the normalised state it gives: a boolean
/// key, a scaled integer key, or a fragment per enumeration value.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatterAttribute {
    pub cluster: String,
    pub attribute: String,
    pub boolean: Option<String>,
    pub scale: Option<Scale>,
    pub values: Option<BTreeMap<String, Payload>>,
    /// Enumeration values not yet confirmed against a Matter controller.
    #[serde(default)]
    pub provisional_values: Vec<String>,
}

/// A Matter id written as `0x…`.
pub fn hex_id(s: &str) -> Option<u32> {
    u32::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

fn type_of(v: &ParamValue) -> StateType {
    match v {
        ParamValue::Bool(_) => StateType::Boolean,
        ParamValue::Int(_) => StateType::Integer,
        ParamValue::Text(_) => StateType::Text,
    }
}

fn json_of(v: &ParamValue) -> Value {
    match v {
        ParamValue::Bool(b) => Value::Bool(*b),
        ParamValue::Int(i) => Value::from(*i),
        ParamValue::Text(t) => Value::String(t.clone()),
    }
}

impl DeviceClass {
    /// Keys, types and ranges of `p` against the class's state; with
    /// `complete`, the required keys must be there too.
    fn check_state(&self, p: &Payload, complete: bool) -> Result<(), String> {
        for (k, v) in p {
            let Some(key) = self.state.get(k) else {
                return Err(format!("{} state has no key {k:?}", self.class));
            };
            if type_of(v) != key.ty {
                return Err(format!("{}.{k} is a {:?}, not a {}", self.class, key.ty, v.type_name()));
            }
            match v {
                ParamValue::Int(i) if key.min.is_some_and(|m| *i < m) || key.max.is_some_and(|m| *i > m) => {
                    return Err(format!("{}.{k} = {i} is out of range", self.class));
                }
                ParamValue::Text(t) if key.max_len.is_some_and(|m| t.chars().count() > m) => {
                    return Err(format!("{}.{k} is too long", self.class));
                }
                _ => {}
            }
        }
        if complete {
            if let Some((k, _)) = self.state.iter().find(|(k, s)| s.required && !p.contains_key(*k)) {
                return Err(format!("{} state lacks {k:?}", self.class));
            }
        }
        Ok(())
    }

    /// Whether `p` is a complete, valid state of this class.
    pub fn conforms(&self, p: &Payload) -> Result<(), String> {
        self.check_state(p, true)
    }

    pub fn capabilities(&self) -> impl Iterator<Item = &CapabilityId> {
        self.required.iter().chain(&self.optional)
    }

    /// The Home Assistant service call for `capability` on `entity_id`:
    /// `("domain/service", body)`. `None` when the class does not map it or a
    /// parameter is missing.
    pub fn ha_call(&self, capability: &CapabilityId, entity_id: &str, params: &Payload) -> Option<(String, Value)> {
        let s = self.home_assistant.services.get(capability)?;
        let mut body = Map::new();
        for (k, e) in &s.data {
            let v = match e {
                Expected::Value(v) => v.clone(),
                Expected::Param { param } => params.get(param)?.clone(),
            };
            body.insert(k.clone(), json_of(&v));
        }
        body.insert("entity_id".into(), Value::String(entity_id.to_string()));
        Some((format!("{}/{}", self.home_assistant.domain, s.service), Value::Object(body)))
    }

    /// The normalised state of a Home Assistant state object. `unavailable`
    /// and `unknown` are not states but failed observations; a state the
    /// profile does not know is not guessed at.
    pub fn ha_state(&self, state: &Value) -> Result<Payload, AdapterError> {
        let s = state
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| AdapterError::Failed("Home Assistant returned no state".into()))?;
        if s == "unavailable" || s == "unknown" {
            return Err(AdapterError::Unavailable(format!("Home Assistant reports the entity as {s}")));
        }
        let mut p = self.home_assistant.states.get(s).cloned().ok_or_else(|| {
            let s: String = s.chars().take(32).collect();
            AdapterError::Failed(format!("{} state {s:?} is not in the Home profile", self.home_assistant.domain))
        })?;
        for (attr, scale) in &self.home_assistant.attributes {
            if let Some(x) = state.get("attributes").and_then(|a| a.get(attr)).and_then(Value::as_f64) {
                p.insert(scale.key.clone(), scale.apply(x).into());
            }
        }
        self.conforms(&p).map_err(AdapterError::Failed)?;
        Ok(p)
    }

    /// The normalised state of one endpoint's Matter attribute reports
    /// `(cluster, attribute, value)`. A null value is unknown and left out; an
    /// enumeration value the profile does not know is not guessed at.
    pub fn matter_state(&self, reports: &[(u32, u32, Value)]) -> Result<Payload, AdapterError> {
        let mut p = Payload::new();
        for a in &self.matter.attributes {
            let (cluster, attribute) = (hex_id(&a.cluster), hex_id(&a.attribute));
            let Some((_, _, v)) = reports.iter().find(|(c, at, _)| Some(*c) == cluster && Some(*at) == attribute)
            else {
                continue;
            };
            if v.is_null() {
                continue;
            }
            let bad = || AdapterError::Failed(format!("unexpected value {v} for {}/{}", a.cluster, a.attribute));
            if let Some(key) = &a.boolean {
                p.insert(key.clone(), v.as_bool().ok_or_else(bad)?.into());
            } else if let Some(scale) = &a.scale {
                p.insert(scale.key.clone(), scale.apply(v.as_f64().ok_or_else(bad)?).into());
            } else if let Some(values) = &a.values {
                let n = v.as_u64().ok_or_else(bad)?;
                p.extend(values.get(&n.to_string()).ok_or_else(bad)?.clone());
            }
        }
        if p.is_empty() {
            return Err(AdapterError::Unavailable(format!("the device reported no {} state", self.class)));
        }
        self.conforms(&p).map_err(AdapterError::Failed)?;
        Ok(p)
    }

    fn validate(&self) -> Result<(), String> {
        let c = &self.class;
        for (k, s) in &self.state {
            if k.is_empty() || s.description.is_empty() {
                return Err(format!("{c}: every state key has a name and a description"));
            }
        }
        if self.required.is_empty() {
            return Err(format!("{c} requires no capability"));
        }
        let known = |cap: &CapabilityId| self.capabilities().any(|x| x == cap);
        for cap in self.home_assistant.services.keys().chain(self.matter.commands.keys()) {
            if !known(cap) {
                return Err(format!("{c} maps {cap}, which it neither requires nor offers"));
            }
        }
        for cap in &self.required {
            if !self.home_assistant.services.contains_key(cap) || !self.matter.commands.contains_key(cap) {
                return Err(format!("{c}: {cap} needs a Home Assistant service and a Matter command"));
            }
        }
        for (s, fragment) in &self.home_assistant.states {
            self.check_state(fragment, false).map_err(|e| format!("Home Assistant state {s:?}: {e}"))?;
        }
        for scale in self.home_assistant.attributes.values() {
            self.check_state(&[(scale.key.clone(), ParamValue::Int(scale.to[0]))].into(), false)?;
        }
        for t in &self.matter.device_types {
            hex_id(t).ok_or_else(|| format!("{c}: bad device type {t:?}"))?;
        }
        for (cap, m) in &self.matter.commands {
            if hex_id(&m.cluster).is_none() || hex_id(&m.command).is_none() {
                return Err(format!("{c}: bad Matter ids for {cap}"));
            }
        }
        for a in &self.matter.attributes {
            if hex_id(&a.cluster).is_none() || hex_id(&a.attribute).is_none() {
                return Err(format!("{c}: bad Matter attribute ids"));
            }
            match (&a.boolean, &a.scale, &a.values) {
                (Some(k), None, None) => self.check_state(&[(k.clone(), ParamValue::Bool(false))].into(), false)?,
                (None, Some(s), None) => {
                    self.check_state(&[(s.key.clone(), ParamValue::Int(s.to[0]))].into(), false)?
                }
                (None, None, Some(values)) => {
                    for (n, fragment) in values {
                        n.parse::<u64>().map_err(|_| format!("{c}: enumeration value {n:?} is not a number"))?;
                        self.check_state(fragment, false)?;
                    }
                }
                _ => return Err(format!("{c}: a Matter attribute is a boolean, a scale or values")),
            }
        }
        Ok(())
    }
}

impl HomeProfile {
    pub fn from_json(src: &str) -> Result<Self, String> {
        let f: ProfileFile = serde_json::from_str(src).map_err(|e| e.to_string())?;
        if f.status.is_empty() {
            return Err("the profile has no status".into());
        }
        let mut names = std::collections::BTreeSet::new();
        let mut domains = std::collections::BTreeSet::new();
        for c in &f.classes {
            if !names.insert(&c.class) || !domains.insert(&c.home_assistant.domain) {
                return Err(format!("class {} or its Home Assistant domain is declared twice", c.class));
            }
            c.validate()?;
        }
        Ok(Self { name: f.profile, version: f.profile_version, registry: f.registry, classes: f.classes })
    }

    /// The embedded Home Capability Profile v0.1.
    pub fn v0_1() -> &'static HomeProfile {
        static PROFILE: OnceLock<HomeProfile> = OnceLock::new();
        PROFILE.get_or_init(|| HomeProfile::from_json(HOME_PROFILE_V0_1).expect("the embedded profile is valid"))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn classes(&self) -> &[DeviceClass] {
        &self.classes
    }

    pub fn class(&self, name: &str) -> Option<&DeviceClass> {
        self.classes.iter().find(|c| c.class == name)
    }

    /// The class of a Home Assistant entity, by its domain (`lock.front_door`).
    pub fn for_entity(&self, entity_id: &str) -> Option<&DeviceClass> {
        let domain = entity_id.split('.').next()?;
        self.classes.iter().find(|c| c.home_assistant.domain == domain)
    }

    /// The class of a device that offers `capabilities`: the one whose
    /// required capabilities it all offers.
    pub fn for_capabilities(&self, capabilities: &[CapabilityId]) -> Option<&DeviceClass> {
        self.classes.iter().find(|c| c.required.iter().all(|r| capabilities.contains(r)))
    }

    /// The profile against a capability registry: every capability exists and
    /// targets devices, every action declares an outcome (spec 22), and every
    /// key an outcome expects is a state key of the class, of the same type.
    pub fn check(&self, registry: &CapabilityRegistry) -> Result<(), String> {
        if registry.name() != self.registry {
            return Err(format!("the profile is for registry {}, not {}", self.registry, registry.name()));
        }
        for c in &self.classes {
            for cap in c.capabilities() {
                let def = registry.get(cap).ok_or_else(|| format!("{}: {cap} is not in the registry", c.class))?;
                if def.target != TargetKind::Device {
                    return Err(format!("{}: {cap} does not target devices", c.class));
                }
                if def.kind != CapabilityKind::Action {
                    continue;
                }
                let outcome = def.outcome.as_ref().ok_or_else(|| format!("{cap} declares no outcome"))?;
                for (k, e) in &outcome.state {
                    let ty = match e {
                        Expected::Value(v) => type_of(v),
                        Expected::Param { param } => {
                            match def.params.iter().find(|p| &p.name == param).map(|p| &p.ty) {
                                Some(ParamType::Integer { .. }) => StateType::Integer,
                                Some(ParamType::Boolean) => StateType::Boolean,
                                _ => StateType::Text,
                            }
                        }
                    };
                    match c.state.get(k) {
                        Some(s) if s.ty == ty => {}
                        _ => {
                            return Err(format!(
                                "{}: the outcome of {cap} expects {k:?}, not a {ty:?} key of the class",
                                c.class
                            ))
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_model::payload;
    use serde_json::json;

    fn cap(s: &str) -> CapabilityId {
        CapabilityId::parse(s).unwrap()
    }

    #[test]
    fn the_profile_fits_the_core_registry() {
        let p = HomeProfile::v0_1();
        assert_eq!((p.name(), p.version()), ("chitala-home", "0.1.0"));
        assert_eq!(p.classes().iter().map(|c| c.class.as_str()).collect::<Vec<_>>(), ["light", "plug", "lock"]);
        p.check(&CapabilityRegistry::core_v0_1()).unwrap();
        assert_eq!(p.class("lock").unwrap().recommended.safe_state, Some(cap("lock.lock")));
        assert_eq!(p.for_entity("switch.kettle").unwrap().class, "plug");
        assert_eq!(p.for_capabilities(&[cap("lock.lock"), cap("lock.unlock")]).unwrap().class, "lock");
        assert!(p.for_capabilities(&[cap("lock.lock")]).is_none(), "a lock must also unlock");
    }

    #[test]
    fn home_assistant_states_are_normalised_without_guessing() {
        let lock = HomeProfile::v0_1().class("lock").unwrap();
        let st = |s: &str| lock.ha_state(&json!({"state": s}));
        assert_eq!(st("locked").unwrap(), payload([("locked", true)]));
        assert_eq!(st("unlocked").unwrap(), payload([("locked", false)]));
        // still moving, or jammed: no `locked` at all, so no outcome verifies early
        assert_eq!(st("unlocking").unwrap(), payload([("moving", true)]));
        assert_eq!(st("locking").unwrap(), payload([("moving", true)]));
        assert_eq!(st("jammed").unwrap(), payload([("fault", "jammed")]));
        assert_eq!(st("open").unwrap(), payload([("locked", false), ("open", true)]));
        // not a state: a failed observation
        assert!(matches!(st("unavailable"), Err(AdapterError::Unavailable(_))));
        assert!(matches!(st("unknown"), Err(AdapterError::Unavailable(_))));
        assert!(matches!(st("half-open"), Err(AdapterError::Failed(_))));

        let light = HomeProfile::v0_1().class("light").unwrap();
        let p = light.ha_state(&json!({"state": "on", "attributes": {"brightness": 128}})).unwrap();
        assert_eq!(p, payload([("on", ParamValue::Bool(true)), ("brightness_pct", ParamValue::Int(50))]));
        let p = light.ha_state(&json!({"state": "off", "attributes": {"brightness": null}})).unwrap();
        assert_eq!(p, payload([("on", false)]));
    }

    #[test]
    fn home_assistant_service_calls_come_from_the_profile() {
        let p = HomeProfile::v0_1();
        let (path, body) =
            p.class("lock").unwrap().ha_call(&cap("lock.unlock"), "lock.front", &Payload::new()).unwrap();
        assert_eq!((path.as_str(), body), ("lock/unlock", json!({"entity_id": "lock.front"})));
        let light = p.class("light").unwrap();
        let (path, body) =
            light.ha_call(&cap("light.set_brightness"), "light.lr", &payload([("brightness_pct", 40i64)])).unwrap();
        assert_eq!((path.as_str(), body), ("light/turn_on", json!({"entity_id": "light.lr", "brightness_pct": 40})));
        assert!(light.ha_call(&cap("light.set_brightness"), "light.lr", &Payload::new()).is_none());
        assert!(light.ha_call(&cap("lock.unlock"), "light.lr", &Payload::new()).is_none());
    }

    /// v0.3 step ③A, against the Matter SDK's lock-app with chip-tool: Door
    /// Lock's `LockDoor` (0x00) and `UnlockDoor` (0x01) are right, and need a
    /// Timed Invoke (without one: `NEEDS_TIMED_INTERACTION`, nothing happens).
    /// On/Off commands do not.
    #[test]
    fn door_lock_commands_are_confirmed_and_timed() {
        let p = HomeProfile::v0_1();
        let lock = &p.class("lock").unwrap().matter.commands;
        for (cap, id) in [("lock.lock", 0x00), ("lock.unlock", 0x01)] {
            let c = &lock[&CapabilityId::parse(cap).unwrap()];
            assert_eq!((hex_id(&c.cluster), hex_id(&c.command)), (Some(0x0101), Some(id)), "{cap}");
            assert!(c.timed && !c.provisional, "{cap}");
        }
        let light = &p.class("light").unwrap().matter.commands;
        assert!(light.values().all(|c| !c.timed));
    }

    #[test]
    fn matter_attributes_are_normalised_without_guessing() {
        let p = HomeProfile::v0_1();
        let lock = p.class("lock").unwrap();
        let state = |n: Value| lock.matter_state(&[(0x0101, 0x0000, n)]);
        assert_eq!(state(json!(1)).unwrap(), payload([("locked", true)]));
        assert_eq!(state(json!(2)).unwrap(), payload([("locked", false)]));
        assert_eq!(state(json!(0)).unwrap(), payload([("fault", "not_fully_locked")]));
        assert!(matches!(state(json!(9)), Err(AdapterError::Failed(_))), "an unknown value is not guessed");
        assert!(matches!(state(Value::Null), Err(AdapterError::Unavailable(_))), "null is unknown");
        let light = p.class("light").unwrap();
        let s = light.matter_state(&[(0x0006, 0x0000, json!(true)), (0x0008, 0x0000, json!(254))]).unwrap();
        assert_eq!(s, payload([("on", ParamValue::Bool(true)), ("brightness_pct", ParamValue::Int(100))]));
        // a light that does not say whether it is on is no light state
        assert!(light.matter_state(&[(0x0008, 0x0000, json!(127))]).is_err());
        let plug = p.class("plug").unwrap();
        assert_eq!(plug.matter_state(&[(0x0006, 0x0000, json!(false))]).unwrap(), payload([("on", false)]));
        assert_eq!(hex_id(&plug.matter.device_types[0]), Some(0x010A));
    }

    /// The virtual devices of the mock adapter report states of their class,
    /// before and after every action they offer.
    #[test]
    fn the_virtual_devices_conform_to_the_profile() {
        use crate::mock::{MockAdapter, VirtualKind};
        use crate::testkit::authorize;
        use crate::DeviceAdapter;
        let p = HomeProfile::v0_1();
        for (kind, class) in [(VirtualKind::Light, "light"), (VirtualKind::Switch, "plug"), (VirtualKind::Lock, "lock")]
        {
            let class = p.class(class).unwrap();
            let id = chitala_model::EntityId::parse("device:v").unwrap();
            let mut a = MockAdapter::new();
            a.add(id.clone(), kind);
            assert!(kind.capabilities().iter().all(|c| class.capabilities().any(|x| x == c)), "{kind:?}");
            assert_eq!(p.for_capabilities(&kind.capabilities()).map(|c| c.class.as_str()), Some(class.class.as_str()));
            class.conforms(&a.observe(&id).unwrap().state).unwrap();
            for c in class.required.iter() {
                let state = a.execute(authorize(&id, c.as_str(), Payload::new())).unwrap();
                class.conforms(&state).unwrap();
            }
        }
    }

    #[test]
    fn a_broken_profile_is_refused() {
        let good: Value = serde_json::from_str(HOME_PROFILE_V0_1).unwrap();
        let broken = |f: &dyn Fn(&mut Value)| {
            let mut v = good.clone();
            f(&mut v);
            HomeProfile::from_json(&v.to_string())
        };
        assert!(broken(&|_| {}).is_ok());
        // a state fragment with an undeclared key, or the wrong type
        assert!(broken(&|v| v["classes"][2]["home_assistant"]["states"]["jammed"] = json!({"stuck": true})).is_err());
        assert!(broken(&|v| v["classes"][0]["home_assistant"]["states"]["on"] = json!({"on": "yes"})).is_err());
        // a required capability without a backend
        assert!(broken(&|v| {
            v["classes"][1]["matter"]["commands"].as_object_mut().unwrap().remove("switch.turn_off");
        })
        .is_err());
        // an unknown field
        assert!(broken(&|v| v["classes"][0]["surprise"] = json!(1)).is_err());
        // a class the registry cannot back: its outcome expects a key it does not have
        let p = broken(&|v| {
            v["classes"][2]["state"].as_object_mut().unwrap().remove("locked");
            v["classes"][2]["home_assistant"]["states"] = json!({"jammed": {"fault": "jammed"}});
            v["classes"][2]["matter"]["attributes"] = json!([]);
        })
        .unwrap();
        assert!(p.check(&CapabilityRegistry::core_v0_1()).is_err());
    }
}
