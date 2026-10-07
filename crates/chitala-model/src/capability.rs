//! Capability registry (spec §04-capability-registry). The normative core registry
//! lives in `specs/registry/capabilities-v0.1.json` and is embedded here verbatim.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::class::RiskClass;
use crate::deny::ExecCode;
use crate::id::CapabilityId;
use crate::motion::PoseOutcome;
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
    /// The action only ever stops motion (spec 30): Safety never refuses it,
    /// since stopping is never less safe than not stopping.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub halts: bool,
    /// How the node may try the action again as a resource's safe state, in
    /// one recovery (spec 22, SAFE-8); [`SafeStateRetryPolicy::DEFAULT`] if
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_state_retry: Option<SafeStateRetryPolicy>,
}

/// How many times, and after what, the node may run a capability as a
/// resource's safe state in one recovery episode (spec 22, SAFE-8; Project
/// Lead, 2026-10-07). Every attempt is a new order on fresh evidence of
/// danger; none is ever a resend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeStateRetryPolicy {
    pub max_attempts_per_episode: u32,
    /// Another attempt after one that certainly did not reach the device.
    pub allow_after_not_sent: bool,
    /// Another attempt after one that reached the device, or may have, and
    /// did not bring it to safety: only if the action is safe to repeat.
    pub allow_after_executed_but_ineffective: bool,
    /// Every attempt needs a fresh observation that shows danger. Always
    /// true in v0.1: nothing is ever sent blind.
    pub requires_fresh_unsafe_evidence: bool,
    /// The least time between two attempts.
    pub min_interval_ms: u64,
}

/// What became of a safe-state attempt's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptFate {
    /// Certainly not delivered: the device could not be reached, or the
    /// order was refused before it left.
    NotSent,
    /// Delivered: executed, or refused by the device itself.
    Reached,
    /// Nobody can tell whether it executed.
    Unknown,
}

impl AttemptFate {
    /// What became of an order, by how its execution ended: success or a
    /// refusal by the device itself reached it; a device out of reach or an
    /// order refused before it left did not; anything else nobody can tell.
    pub fn of(result: Result<(), ExecCode>) -> Self {
        match result {
            Ok(()) | Err(ExecCode::DeviceRefused) => AttemptFate::Reached,
            Err(ExecCode::DeviceUnavailable | ExecCode::OrderRejected) => AttemptFate::NotSent,
            Err(_) => AttemptFate::Unknown,
        }
    }
}

/// Why no further attempt may be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryRefused {
    /// The episode's attempts are spent.
    Exhausted,
    /// The last attempt reached the device (or may have), and the action is
    /// not one to repeat.
    NotRepeatable,
    /// The last attempt is too recent, or its fate not known yet.
    TooSoon,
}

/// Bounds of [`SafeStateRetryPolicy::max_attempts_per_episode`].
pub const MAX_SAFE_STATE_ATTEMPTS: u32 = 5;

impl SafeStateRetryPolicy {
    /// An actuator the registry says nothing more about: one attempt.
    pub const DEFAULT: Self = Self {
        max_attempts_per_episode: 1,
        allow_after_not_sent: false,
        allow_after_executed_but_ineffective: false,
        requires_fresh_unsafe_evidence: true,
        min_interval_ms: 1_000,
    };

    /// Whether an attempt may follow the `made` ones of this episode, the
    /// last of which ended as `last` (its fate, and when it was made).
    pub fn next(&self, made: u32, last: Option<(Option<AttemptFate>, u64)>, now: u64) -> Result<(), RetryRefused> {
        if made >= self.max_attempts_per_episode {
            return Err(RetryRefused::Exhausted);
        }
        let Some((fate, at)) = last else { return Ok(()) };
        let repeatable = match fate {
            None => return Err(RetryRefused::TooSoon),
            Some(AttemptFate::NotSent) => self.allow_after_not_sent,
            Some(AttemptFate::Reached | AttemptFate::Unknown) => self.allow_after_executed_but_ineffective,
        };
        if !repeatable {
            return Err(RetryRefused::NotRepeatable);
        }
        if now < at.saturating_add(self.min_interval_ms) {
            return Err(RetryRefused::TooSoon);
        }
        Ok(())
    }
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
    #[serde(default)]
    pub state: BTreeMap<String, Expected>,
    /// Keys whose value may be any of several (spec 30: a stopped robot is
    /// at rest, `idle`, `stopped` or `estopped`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub any_of: BTreeMap<String, Vec<ParamValue>>,
    pub within_ms: u64,
    /// A robot's motion (spec 30): the pose it must also end at, from where
    /// it started; the motion's own time is added to `within_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pose: Option<PoseOutcome>,
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
    /// Whether `observed` states every key an action with `params` promised a
    /// value for: whether it can tell anything about the promise at all. A
    /// key a device leaves out is unknown (a jammed lock states no `locked`).
    pub fn stated(&self, params: &Payload, observed: &Payload) -> bool {
        self.expect(params).keys().chain(self.any_of.keys()).all(|k| observed.contains_key(k))
    }

    /// Whether `observed` reports what an action with `params` promised: every
    /// expected value, and one of the allowed values of every `any_of` key.
    /// (A motion's pose is checked against where it started, by the node.)
    pub fn reported(&self, params: &Payload, observed: &Payload) -> bool {
        self.expect(params).iter().all(|(k, v)| observed.get(k) == Some(v))
            && self.any_of.iter().all(|(k, values)| observed.get(k).is_some_and(|v| values.contains(v)))
    }

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
    /// How the node may run it again as a safe state.
    pub fn retry_policy(&self) -> SafeStateRetryPolicy {
        self.safe_state_retry.unwrap_or(SafeStateRetryPolicy::DEFAULT)
    }

    /// Every device action declares an outcome, and nothing else does; an
    /// outcome expects at least one key and refers only to required parameters.
    fn check_outcome(&self) -> Result<(), String> {
        let device_action = self.kind == CapabilityKind::Action && self.target == TargetKind::Device;
        // nothing that takes a parameter can be trusted to only stop
        if self.halts && (!device_action || !self.params.is_empty()) {
            return Err(format!("{} halts, so it is a device action without parameters", self.id));
        }
        if let Some(r) = &self.safe_state_retry {
            if !device_action
                || !(1..=MAX_SAFE_STATE_ATTEMPTS).contains(&r.max_attempts_per_episode)
                || !r.requires_fresh_unsafe_evidence
            {
                return Err(format!(
                    "{}: a safe-state retry policy is for a device action, with 1..{MAX_SAFE_STATE_ATTEMPTS} attempts, on fresh evidence only",
                    self.id
                ));
            }
        }
        let Some(o) = &self.outcome else {
            return match device_action {
                true => Err(format!("device action {} declares no outcome", self.id)),
                false => Ok(()),
            };
        };
        if !device_action {
            return Err(format!("{} is not a device action and cannot declare an outcome", self.id));
        }
        let keys = o.state.len() + o.any_of.len();
        if keys == 0 || keys > MAX_OUTCOME_KEYS {
            return Err(format!("outcome of {} must expect 1..{MAX_OUTCOME_KEYS} keys", self.id));
        }
        for (k, values) in &o.any_of {
            if o.state.contains_key(k) || values.is_empty() || values.len() > MAX_OUTCOME_KEYS {
                return Err(format!(
                    "outcome of {}: {k} must be expected once, with 1..{MAX_OUTCOME_KEYS} values",
                    self.id
                ));
            }
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
        if let Some(pose) = &o.pose {
            for param in pose.motion.params() {
                let integer = |p: &ParamDef| p.name == param && p.required && matches!(p.ty, ParamType::Integer { .. });
                if !self.params.iter().any(integer) {
                    return Err(format!("the pose of {} refers to {param:?}, not a required integer", self.id));
                }
            }
            if pose.tolerance_mm == 0 || pose.tolerance_mdeg == 0 {
                return Err(format!("the pose of {} needs a tolerance: no robot stops on the millimetre", self.id));
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

    /// The Project Lead's table (2026-10-07): after an attempt that never
    /// reached the device, a robot stop may follow; after one that did, a
    /// stop again, a lock never; none past the episode's bound, none too soon.
    #[test]
    fn safe_state_retry_follows_what_became_of_the_last_attempt() {
        let reg = CapabilityRegistry::core_v0_1();
        let policy = |c: &str| reg.get(&CapabilityId::parse(c).unwrap()).unwrap().retry_policy();
        let (stop, lock) = (policy("robot.stop"), policy("lock.lock"));
        let light = policy("light.turn_off");
        assert_eq!((stop.max_attempts_per_episode, lock.max_attempts_per_episode), (3, 1));
        assert_eq!(light, SafeStateRetryPolicy::DEFAULT);
        let at = |fate| Some((Some(fate), 1_000));
        // the first attempt: always, on fresh evidence
        for p in [stop, lock, light] {
            assert_eq!(p.next(0, None, 0), Ok(()));
        }
        assert_eq!(stop.next(1, at(AttemptFate::NotSent), 2_000), Ok(()), "not sent: a new stop");
        assert_eq!(stop.next(1, at(AttemptFate::Reached), 2_000), Ok(()), "a stop is safe to repeat");
        assert_eq!(stop.next(1, at(AttemptFate::Unknown), 2_000), Ok(()));
        assert_eq!(stop.next(1, at(AttemptFate::NotSent), 1_500), Err(RetryRefused::TooSoon));
        assert_eq!(stop.next(1, Some((None, 1_000)), 9_000), Err(RetryRefused::TooSoon), "its fate is not known yet");
        assert_eq!(stop.next(3, at(AttemptFate::NotSent), 9_000), Err(RetryRefused::Exhausted));
        assert_eq!(lock.next(1, at(AttemptFate::NotSent), 9_000), Err(RetryRefused::Exhausted), "a lock: once");
        let twice = SafeStateRetryPolicy { max_attempts_per_episode: 2, ..SafeStateRetryPolicy::DEFAULT };
        assert_eq!(twice.next(1, at(AttemptFate::Reached), 9_000), Err(RetryRefused::NotRepeatable));
        assert_eq!(twice.next(1, at(AttemptFate::Unknown), 9_000), Err(RetryRefused::NotRepeatable), "not blind");
    }

    /// Only an order that certainly did not leave, or never reached its
    /// device, is "not sent"; one whose fate is unknown is never taken for it.
    #[test]
    fn an_attempt_s_fate_is_never_taken_for_better_than_known() {
        assert_eq!(AttemptFate::of(Ok(())), AttemptFate::Reached);
        assert_eq!(AttemptFate::of(Err(ExecCode::DeviceRefused)), AttemptFate::Reached);
        assert_eq!(AttemptFate::of(Err(ExecCode::DeviceUnavailable)), AttemptFate::NotSent);
        assert_eq!(AttemptFate::of(Err(ExecCode::OrderRejected)), AttemptFate::NotSent);
        for unknown in [ExecCode::ExecutionUnknown, ExecCode::Adapter, ExecCode::ReceiptInvalid, ExecCode::Internal] {
            assert_eq!(AttemptFate::of(Err(unknown)), AttemptFate::Unknown, "{unknown:?}");
        }
    }

    #[test]
    fn core_registry_loads() {
        let reg = CapabilityRegistry::core_v0_1();
        assert_eq!(reg.version(), "0.1.6");
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
