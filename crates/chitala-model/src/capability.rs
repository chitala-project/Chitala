//! Capability registry (spec §04-capability-registry). The normative core registry
//! lives in `specs/registry/capabilities-v0.1.json` and is embedded here verbatim.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::class::RiskClass;
use crate::id::CapabilityId;
use crate::value::{ParamValue, Payload};

pub const CORE_REGISTRY_V0_1: &str = include_str!("../../../specs/registry/capabilities-v0.1.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityKind {
    /// Changes the world; sent as `command`.
    Action,
    /// Reads state; sent as `query`.
    Query,
}

/// What a capability acts on. Device capabilities target a device entity; domain
/// capabilities (delegation, revocation, security state) target the domain itself
/// and go through the same Reference Monitor path (spec §04 "Targets").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    #[default]
    Device,
    Domain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ParamType {
    Integer { min: i64, max: i64 },
    Boolean,
    Text { max_len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamDef {
    pub name: String,
    #[serde(flatten)]
    pub ty: ParamType,
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDef {
    pub id: CapabilityId,
    pub version: u32,
    pub kind: CapabilityKind,
    pub risk: RiskClass,
    #[serde(default)]
    pub target: TargetKind,
    pub description: String,
    #[serde(default)]
    pub params: Vec<ParamDef>,
    /// What the action promises about the world (spec 22): every device action
    /// declares one, so its outcome can be verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<OutcomeDef>,
}

/// Bounds of [`OutcomeDef::within_ms`].
pub const MIN_OUTCOME_WITHIN_MS: u64 = 100;
pub const MAX_OUTCOME_WITHIN_MS: u64 = 60_000;
/// At most this many expected keys per outcome.
pub const MAX_OUTCOME_KEYS: usize = 16;

/// The postcondition of a device action (Blueprint v19 §8 "Outcome", spec 22):
/// the values the resource's state must report once the action has taken
/// effect, and how long the physical world may take to get there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeDef {
    pub state: BTreeMap<String, Expected>,
    pub within_ms: u64,
}

/// One expected value: a literal, or the value of one of the action's
/// parameters (`{"param": "celsius"}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Expected {
    Param { param: String },
    Value(ParamValue),
}

impl OutcomeDef {
    /// The concrete state an action with `params` must lead to. A parameter
    /// the action does not carry contributes nothing (outcomes only refer to
    /// required parameters, so this does not happen for a valid payload).
    pub fn expect(&self, params: &Payload) -> Payload {
        self.state
            .iter()
            .filter_map(|(k, e)| {
                let v = match e {
                    Expected::Value(v) => v.clone(),
                    Expected::Param { param } => params.get(param)?.clone(),
                };
                Some((k.clone(), v))
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// Shape/type problem → `E_PAYLOAD_INVALID`.
    #[error("invalid payload: {0}")]
    Invalid(String),
    /// Value outside the declared envelope → `E_SAFETY_ENVELOPE`.
    #[error("outside safety envelope: {0}")]
    OutOfRange(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryFile {
    registry: String,
    registry_version: String,
    status: String,
    capabilities: Vec<CapabilityDef>,
}

#[derive(Debug, Clone)]
pub struct CapabilityRegistry {
    name: String,
    version: String,
    defs: Vec<CapabilityDef>,
    index: HashMap<CapabilityId, usize>,
}

impl CapabilityRegistry {
    pub fn from_json(src: &str) -> Result<Self, String> {
        let file: RegistryFile = serde_json::from_str(src).map_err(|e| e.to_string())?;
        let mut index = HashMap::new();
        for (i, def) in file.capabilities.iter().enumerate() {
            if index.insert(def.id.clone(), i).is_some() {
                return Err(format!("duplicate capability {}", def.id));
            }
            if def.version == 0 {
                return Err(format!("capability {} has version 0", def.id));
            }
            def.check_outcome()?;
        }
        Ok(Self { name: file.registry, version: file.registry_version, defs: file.capabilities, index })
    }

    pub fn core_v0_1() -> Self {
        Self::from_json(CORE_REGISTRY_V0_1).expect("embedded core registry is valid")
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn get(&self, id: &CapabilityId) -> Option<&CapabilityDef> {
        self.index.get(id).map(|&i| &self.defs[i])
    }

    pub fn iter(&self) -> impl Iterator<Item = &CapabilityDef> {
        self.defs.iter()
    }
}

impl CapabilityDef {
    /// Every device action declares an outcome, and nothing else does; an
    /// outcome expects at least one key and refers only to required parameters.
    fn check_outcome(&self) -> Result<(), String> {
        let device_action = self.kind == CapabilityKind::Action && self.target == TargetKind::Device;
        let Some(o) = &self.outcome else {
            return match device_action {
                true => Err(format!("device action {} declares no outcome", self.id)),
                false => Ok(()),
            };
        };
        if !device_action {
            return Err(format!("{} is not a device action and cannot declare an outcome", self.id));
        }
        if o.state.is_empty() || o.state.len() > MAX_OUTCOME_KEYS {
            return Err(format!("outcome of {} must expect 1..{MAX_OUTCOME_KEYS} keys", self.id));
        }
        if !(MIN_OUTCOME_WITHIN_MS..=MAX_OUTCOME_WITHIN_MS).contains(&o.within_ms) {
            return Err(format!(
                "outcome of {} must settle within [{MIN_OUTCOME_WITHIN_MS}, {MAX_OUTCOME_WITHIN_MS}] ms",
                self.id
            ));
        }
        for e in o.state.values() {
            if let Expected::Param { param } = e {
                if !self.params.iter().any(|p| &p.name == param && p.required) {
                    return Err(format!("outcome of {} refers to {param:?}, not a required parameter", self.id));
                }
            }
        }
        Ok(())
    }

    /// Strict validation: unknown parameters are rejected in v0.1.
    pub fn validate(&self, payload: &Payload) -> Result<(), PayloadError> {
        for name in payload.keys() {
            if !self.params.iter().any(|p| &p.name == name) {
                return Err(PayloadError::Invalid(format!("unknown parameter {name:?}")));
            }
        }
        for p in &self.params {
            match (payload.get(&p.name), &p.ty) {
                (None, _) if p.required => {
                    return Err(PayloadError::Invalid(format!("missing parameter {:?}", p.name)))
                }
                (None, _) => {}
                (Some(ParamValue::Int(v)), ParamType::Integer { min, max }) => {
                    if v < min || v > max {
                        return Err(PayloadError::OutOfRange(format!("{} = {v} not in [{min}, {max}]", p.name)));
                    }
                }
                (Some(ParamValue::Bool(_)), ParamType::Boolean) => {}
                (Some(ParamValue::Text(t)), ParamType::Text { max_len }) => {
                    if t.chars().count() > *max_len {
                        return Err(PayloadError::Invalid(format!("{} longer than {max_len} characters", p.name)));
                    }
                }
                (Some(v), ty) => {
                    return Err(PayloadError::Invalid(format!(
                        "{} has type {}, expected {:?}",
                        p.name,
                        v.type_name(),
                        ty
                    )))
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::payload;

    #[test]
    fn core_registry_loads() {
        let reg = CapabilityRegistry::core_v0_1();
        assert_eq!(reg.version(), "0.1.2");
        let unlock = reg.get(&CapabilityId::parse("lock.unlock").unwrap()).unwrap();
        assert_eq!(unlock.risk, RiskClass::High);
        assert_eq!(unlock.target, TargetKind::Device);
        assert!(reg.iter().count() >= 9);
        let delegate = reg.get(&CapabilityId::parse("domain.delegate").unwrap()).unwrap();
        assert_eq!(delegate.target, TargetKind::Domain);
    }

    #[test]
    fn payload_validation() {
        let reg = CapabilityRegistry::core_v0_1();
        let b = reg.get(&CapabilityId::parse("light.set_brightness").unwrap()).unwrap();
        assert!(b.validate(&payload([("brightness_pct", 40i64)])).is_ok());
        assert!(matches!(b.validate(&payload([("brightness_pct", 140i64)])), Err(PayloadError::OutOfRange(_))));
        assert!(matches!(b.validate(&payload([("brightness_pct", true)])), Err(PayloadError::Invalid(_))));
        assert!(matches!(b.validate(&Payload::new()), Err(PayloadError::Invalid(_))));
        let on = reg.get(&CapabilityId::parse("light.turn_on").unwrap()).unwrap();
        assert!(matches!(on.validate(&payload([("x", 1i64)])), Err(PayloadError::Invalid(_))));
    }

    #[test]
    fn every_device_action_declares_its_outcome() {
        let reg = CapabilityRegistry::core_v0_1();
        for def in reg.iter() {
            let device_action = def.kind == CapabilityKind::Action && def.target == TargetKind::Device;
            assert_eq!(def.outcome.is_some(), device_action, "{}", def.id);
        }
        let set = reg.get(&CapabilityId::parse("climate.set_target_temperature").unwrap()).unwrap();
        let o = set.outcome.as_ref().unwrap();
        assert_eq!(o.expect(&payload([("celsius", 21i64)])), payload([("target_celsius", 21i64)]));
        let lock = reg.get(&CapabilityId::parse("lock.lock").unwrap()).unwrap();
        assert_eq!(lock.outcome.as_ref().unwrap().expect(&Payload::new()), payload([("locked", true)]));
    }

    #[test]
    fn malformed_outcomes_are_refused() {
        let file = |cap: &str| {
            format!(r#"{{"registry":"t","registry_version":"0","status":"experimental","capabilities":[{cap}]}}"#)
        };
        let ok = r#"{"id":"x-t.set","version":1,"kind":"action","risk":"low","description":"","params":[{"name":"v","type":"integer","min":0,"max":9}],"outcome":{"state":{"v":{"param":"v"}},"within_ms":1000}}"#;
        assert!(CapabilityRegistry::from_json(&file(ok)).is_ok());
        for bad in [
            // a device action without an outcome
            r#"{"id":"x-t.set","version":1,"kind":"action","risk":"low","description":""}"#,
            // a query with one
            r#"{"id":"x-t.get","version":1,"kind":"query","risk":"low","description":"","outcome":{"state":{"on":true},"within_ms":1000}}"#,
            // nothing expected
            r#"{"id":"x-t.on","version":1,"kind":"action","risk":"low","description":"","outcome":{"state":{},"within_ms":1000}}"#,
            // an unknown parameter
            r#"{"id":"x-t.on","version":1,"kind":"action","risk":"low","description":"","outcome":{"state":{"v":{"param":"w"}},"within_ms":1000}}"#,
            // too slow
            r#"{"id":"x-t.on","version":1,"kind":"action","risk":"low","description":"","outcome":{"state":{"on":true},"within_ms":600000}}"#,
        ] {
            assert!(CapabilityRegistry::from_json(&file(bad)).is_err(), "{bad}");
        }
    }
}
