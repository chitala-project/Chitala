//! Resource model (spec `specs/14-resource-model.md`, Blueprint v20 "Resource Model").
//!
//! A **resource** is anything in the physical world a Chitala domain governs: a
//! site, a room, a door, a lock, a light, a robot, a vehicle, or a kind nobody
//! has built yet. Principals act; resources are acted upon. Every resource is
//! described by the same primitive:
//!
//! | facet | field | meaning |
//! |-------|-------|---------|
//! | identity | [`ResourceId`] | `resource:<local>`, stable when the thing moves |
//! | kind | [`ResourceKind`] | core kind or a vendor extension `x-<vendor>.<kind>` |
//! | ownership | `owners` | the humans with final authority; inherited from the parent when empty |
//! | parent/child | `parent` | containment or part-of (site ⊃ room ⊃ door ⊃ lock); a tree |
//! | location | [`Location`] | derived: site, nearest space, zone label, boundary |
//! | state reference | [`StateRef`] | where the reported state lives and how fresh it must be |
//! | capability binding | [`CapabilityBinding`] | which device executes which capability, at what minimum risk |
//! | safety envelope | [`ParamLimit`] | parameter limits stricter than the registry |
//! | safe state | [`SafeState`] | the action that brings it back to safety after a failed outcome |
//!
//! An AI intent names a *resource* ("unlock the front door"), never a device.
//! Only the trusted execution boundary resolves the binding to the device that
//! receives the physical command.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use chitala_model::{
    CapabilityId, CapabilityKind, CapabilityRegistry, EntityId, EntityKind, IdError, ParamType, ParamValue, Payload,
    RiskClass, TargetKind,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Longest parent chain (site → building → floor → room → door → lock …).
pub const MAX_DEPTH: usize = 8;
pub const MAX_RESOURCES: usize = 10_000;
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_OWNERS: usize = 16;
pub const MAX_BINDINGS: usize = 32;
/// Default and bounds of [`StateRef::max_age_ms`].
pub const DEFAULT_MAX_STATE_AGE_MS: u64 = 120_000;
pub const MIN_STATE_AGE_MS: u64 = 1_000;
pub const MAX_STATE_AGE_MS: u64 = 3_600_000;

// ───────────────────────────── identity ─────────────────────────────

/// `resource:<local>`: an [`EntityId`] of kind [`EntityKind::Resource`], so tokens,
/// policies and audit records name resources the same way they name principals.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceId(EntityId);

impl ResourceId {
    pub fn new(local: impl Into<String>) -> Result<Self, IdError> {
        Ok(Self(EntityId::new(EntityKind::Resource, local)?))
    }

    pub fn parse(s: &str) -> Result<Self, IdError> {
        Self::from_entity(EntityId::parse(s)?)
    }

    pub fn from_entity(e: EntityId) -> Result<Self, IdError> {
        if e.kind() != EntityKind::Resource {
            return Err(IdError::Malformed(format!("{e} is not a resource id")));
        }
        Ok(Self(e))
    }

    pub fn as_entity(&self) -> &EntityId {
        &self.0
    }

    pub fn local(&self) -> &str {
        self.0.local()
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ResourceId {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for ResourceId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for ResourceId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::from_entity(EntityId::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

// ───────────────────────────── kind ─────────────────────────────

/// What a resource is. The core kinds cover v0.1 homes plus the robots and
/// vehicles of the future profiles; anything else is a vendor extension
/// `x-<vendor>.<kind>` and is governed by exactly the same rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceKind {
    /// A whole property or installation; usually a root.
    Site,
    /// A room, floor, zone or yard.
    Space,
    Door,
    Window,
    Gate,
    Lock,
    Light,
    Switch,
    Climate,
    Sensor,
    Camera,
    Appliance,
    Robot,
    Vehicle,
    Extension(String),
}

const CORE_KINDS: [(&str, ResourceKind); 14] = [
    ("site", ResourceKind::Site),
    ("space", ResourceKind::Space),
    ("door", ResourceKind::Door),
    ("window", ResourceKind::Window),
    ("gate", ResourceKind::Gate),
    ("lock", ResourceKind::Lock),
    ("light", ResourceKind::Light),
    ("switch", ResourceKind::Switch),
    ("climate", ResourceKind::Climate),
    ("sensor", ResourceKind::Sensor),
    ("camera", ResourceKind::Camera),
    ("appliance", ResourceKind::Appliance),
    ("robot", ResourceKind::Robot),
    ("vehicle", ResourceKind::Vehicle),
];

fn valid_extension_kind(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("x-") else { return false };
    let Some((vendor, kind)) = rest.split_once('.') else { return false };
    let seg = |t: &str, first_alpha: bool| {
        let b = t.as_bytes();
        !b.is_empty()
            && b.len() <= 32
            && (!first_alpha || b[0].is_ascii_lowercase())
            && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
    };
    seg(vendor, false) && seg(kind, true)
}

impl ResourceKind {
    pub fn as_str(&self) -> &str {
        match self {
            ResourceKind::Extension(s) => s,
            k => CORE_KINDS.iter().find(|(_, c)| c == k).map(|(s, _)| *s).expect("every core kind is listed"),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        if let Some((_, k)) = CORE_KINDS.iter().find(|(n, _)| *n == s) {
            return Some(k.clone());
        }
        valid_extension_kind(s).then(|| ResourceKind::Extension(s.to_string()))
    }

    /// Sites and spaces contain other resources and are never actuated
    /// themselves in v0.1 (a capability on a room would be a group command).
    pub fn is_container(&self) -> bool {
        matches!(self, ResourceKind::Site | ResourceKind::Space)
    }
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ResourceKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ResourceKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("unknown resource kind {s:?}")))
    }
}

// ───────────────────────────── facets ─────────────────────────────

/// Whether a resource separates the inside of a site from the outside world.
/// Policies and safety rules may treat perimeter resources (front door, gate,
/// garage) more strictly than interior ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Boundary {
    #[default]
    Interior,
    Perimeter,
}

impl Boundary {
    pub fn as_str(self) -> &'static str {
        match self {
            Boundary::Interior => "interior",
            Boundary::Perimeter => "perimeter",
        }
    }
}

/// Which device executes `capability` for this resource. The binding is the
/// only place where a resource meets a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityBinding {
    pub capability: CapabilityId,
    pub device: EntityId,
    /// Raises (never lowers) the registry risk of the capability for this
    /// resource: unlocking a perimeter door can be `critical` in one home.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_floor: Option<RiskClass>,
}

/// Where the reported state of a resource lives (the device twin) and how old
/// it may be before safety treats it as unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRef {
    pub device: EntityId,
    #[serde(default = "default_max_age")]
    pub max_age_ms: u64,
}

fn default_max_age() -> u64 {
    DEFAULT_MAX_STATE_AGE_MS
}

/// The action that brings a resource back to its safe state (spec 22), such as
/// `lock.lock` for a front door. While the resource is in recovery after a
/// failed outcome it is the only action Safety lets through there, and the
/// node runs it once by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeState {
    pub capability: CapabilityId,
    #[serde(default, skip_serializing_if = "Payload::is_empty")]
    pub params: Payload,
}

/// A per-resource limit on an integer parameter, inside the registry range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamLimit {
    pub capability: CapabilityId,
    pub param: String,
    pub min: i64,
    pub max: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub id: ResourceId,
    pub kind: ResourceKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ResourceId>,
    /// Persons with final authority over this resource and its descendants.
    /// Empty: inherited from the nearest ancestor that has owners.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<EntityId>,
    #[serde(default)]
    pub boundary: Boundary,
    /// Free location label (`entrance`, `upstairs`); grammar of an entity local id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<CapabilityBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub envelope: Vec<ParamLimit>,
    /// Two-key resource: an action of high or critical risk here, or below
    /// here, needs two different people to agree (spec 14 "Two keys").
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub two_key: bool,
    /// The action that brings it back to a safe state after a failed outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_state: Option<SafeState>,
}

impl Resource {
    pub fn binding(&self, capability: &CapabilityId) -> Option<&CapabilityBinding> {
        self.bindings.iter().find(|b| &b.capability == capability)
    }

    pub fn limits<'a>(&'a self, capability: &'a CapabilityId) -> impl Iterator<Item = &'a ParamLimit> + 'a {
        self.envelope.iter().filter(move |l| &l.capability == capability)
    }
}

/// Where a resource is, derived from the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// The root of the resource's tree.
    pub site: ResourceId,
    /// The nearest ancestor (or the resource itself) of kind `space`.
    pub space: Option<ResourceId>,
    /// The nearest zone label on the way to the root.
    pub zone: Option<String>,
    pub boundary: Boundary,
}

// ───────────────────────────── graph ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResourceError {
    #[error("duplicate resource {0}")]
    Duplicate(ResourceId),
    #[error("{0}: {1}")]
    Invalid(ResourceId, String),
    #[error("{child}: parent {parent} does not exist")]
    UnknownParent { child: ResourceId, parent: ResourceId },
    #[error("{0}: parent chain is cyclic or deeper than {MAX_DEPTH}")]
    Cycle(ResourceId),
    #[error("{0}: no owner on the way to the root; every resource needs a human with final authority")]
    Unowned(ResourceId),
    #[error("too many resources (max {MAX_RESOURCES})")]
    TooMany,
}

/// The validated resource tree of a domain. Immutable once built.
#[derive(Debug, Clone, Default)]
pub struct ResourceGraph {
    by_id: BTreeMap<ResourceId, Resource>,
    children: BTreeMap<ResourceId, Vec<ResourceId>>,
    by_device: BTreeMap<EntityId, BTreeSet<ResourceId>>,
}

fn valid_label(s: &str) -> bool {
    EntityId::new(EntityKind::Resource, s).is_ok()
}

fn check_resource(r: &Resource, registry: &CapabilityRegistry) -> Result<(), String> {
    if r.name.trim().is_empty() || r.name.chars().count() > MAX_NAME_LEN {
        return Err(format!("name must be 1..{MAX_NAME_LEN} characters"));
    }
    if r.parent.as_ref() == Some(&r.id) {
        return Err("a resource cannot be its own parent".into());
    }
    if r.owners.len() > MAX_OWNERS {
        return Err(format!("more than {MAX_OWNERS} owners"));
    }
    let mut owners = BTreeSet::new();
    for o in &r.owners {
        if o.kind() != EntityKind::Person {
            return Err(format!("owner {o} is not a person: only humans own resources"));
        }
        if !owners.insert(o) {
            return Err(format!("owner {o} listed twice"));
        }
    }
    if let Some(z) = &r.zone {
        if !valid_label(z) {
            return Err(format!("invalid zone label {z:?}"));
        }
    }
    if r.kind.is_container() && (!r.bindings.is_empty() || r.state.is_some()) {
        return Err(format!("a {} is a container and has no bindings or state in v0.1", r.kind));
    }
    if r.bindings.len() > MAX_BINDINGS {
        return Err(format!("more than {MAX_BINDINGS} bindings"));
    }
    let mut caps = BTreeSet::new();
    for b in &r.bindings {
        if !caps.insert(&b.capability) {
            return Err(format!("capability {} bound twice", b.capability));
        }
        let Some(def) = registry.get(&b.capability) else {
            return Err(format!("capability {} is not in registry {}", b.capability, registry.version()));
        };
        if def.target != TargetKind::Device {
            return Err(format!("{} targets the domain and cannot be bound to a resource", def.id));
        }
        if b.device.kind() != EntityKind::Device {
            return Err(format!("binding of {} names {}, which is not a device", b.capability, b.device));
        }
        if b.risk_floor.is_some_and(|f| f <= def.risk) {
            return Err(format!("risk floor of {} must be above its registry risk {}", def.id, def.risk));
        }
    }
    if let Some(s) = &r.state {
        if s.device.kind() != EntityKind::Device {
            return Err(format!("state reference {} is not a device", s.device));
        }
        if !(MIN_STATE_AGE_MS..=MAX_STATE_AGE_MS).contains(&s.max_age_ms) {
            return Err(format!("state max age must be in [{MIN_STATE_AGE_MS}, {MAX_STATE_AGE_MS}] ms"));
        }
    }
    let actions_bound =
        r.bindings.iter().any(|b| registry.get(&b.capability).is_some_and(|d| d.kind == CapabilityKind::Action));
    if actions_bound && r.state.is_none() {
        return Err("a resource with bound actions needs a state reference (safety must know its state)".into());
    }
    for l in &r.envelope {
        if r.binding(&l.capability).is_none() {
            return Err(format!("envelope for {}, which is not bound", l.capability));
        }
        let def = registry.get(&l.capability).expect("bound capabilities are in the registry");
        let Some(p) = def.params.iter().find(|p| p.name == l.param) else {
            return Err(format!("{} has no parameter {:?}", l.capability, l.param));
        };
        let ParamType::Integer { min, max } = p.ty else {
            return Err(format!("{}.{} is not an integer", l.capability, l.param));
        };
        if l.min > l.max || l.min < min || l.max > max {
            return Err(format!(
                "envelope {}..{} of {}.{} is not inside [{min}, {max}]",
                l.min, l.max, l.capability, l.param
            ));
        }
    }
    if let Some(s) = &r.safe_state {
        check_safe_state(r, s, registry)?;
    }
    Ok(())
}

/// A safe state is an action bound here, with valid parameters inside the
/// resource's envelope, and of at most medium effective risk: the node may run
/// it without anyone asking, so it must never be the kind of action that needs
/// a human (unlocking, anything critical).
fn check_safe_state(r: &Resource, s: &SafeState, registry: &CapabilityRegistry) -> Result<(), String> {
    let Some(b) = r.binding(&s.capability) else {
        return Err(format!("safe state {} is not bound here", s.capability));
    };
    let def = registry.get(&s.capability).expect("bound capabilities are in the registry");
    if def.kind != CapabilityKind::Action {
        return Err(format!("safe state {} is not an action", s.capability));
    }
    def.validate(&s.params).map_err(|e| format!("safe state {}: {e}", s.capability))?;
    for l in r.limits(&s.capability) {
        if let Some(ParamValue::Int(v)) = s.params.get(&l.param) {
            if *v < l.min || *v > l.max {
                return Err(format!("safe state {}.{} = {v} is outside the envelope", s.capability, l.param));
            }
        }
    }
    let risk = b.risk_floor.map_or(def.risk, |f| f.max(def.risk));
    if risk > RiskClass::Medium {
        return Err(format!("safe state {} is {risk} risk; a safe state is at most medium", s.capability));
    }
    Ok(())
}

impl ResourceGraph {
    /// Validate and index `resources` against the capability registry.
    pub fn new(resources: Vec<Resource>, registry: &CapabilityRegistry) -> Result<Self, ResourceError> {
        if resources.len() > MAX_RESOURCES {
            return Err(ResourceError::TooMany);
        }
        let mut g = ResourceGraph::default();
        for r in resources {
            check_resource(&r, registry).map_err(|e| ResourceError::Invalid(r.id.clone(), e))?;
            if g.by_id.contains_key(&r.id) {
                return Err(ResourceError::Duplicate(r.id));
            }
            g.by_id.insert(r.id.clone(), r);
        }
        for r in g.by_id.values() {
            if let Some(p) = &r.parent {
                if !g.by_id.contains_key(p) {
                    return Err(ResourceError::UnknownParent { child: r.id.clone(), parent: p.clone() });
                }
                g.children.entry(p.clone()).or_default().push(r.id.clone());
            }
            for d in r.bindings.iter().map(|b| &b.device).chain(r.state.as_ref().map(|s| &s.device)) {
                g.by_device.entry(d.clone()).or_default().insert(r.id.clone());
            }
        }
        for id in g.by_id.keys() {
            let mut cur = id;
            let mut depth = 0;
            while let Some(p) = g.by_id[cur].parent.as_ref() {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(ResourceError::Cycle(id.clone()));
                }
                cur = p;
            }
            if g.effective_owners(id).is_empty() {
                return Err(ResourceError::Unowned(id.clone()));
            }
        }
        Ok(g)
    }

    /// Check every binding and state reference against the devices of the
    /// domain: `supports(device, capability)` is `None` for an unknown device.
    pub fn check_devices(
        &self,
        supports: impl Fn(&EntityId, &CapabilityId) -> Option<bool>,
    ) -> Result<(), ResourceError> {
        let read = CapabilityId::parse("device.read_state").expect("static id");
        for r in self.by_id.values() {
            for b in &r.bindings {
                match supports(&b.device, &b.capability) {
                    None => return Err(ResourceError::Invalid(r.id.clone(), format!("unknown device {}", b.device))),
                    Some(false) => {
                        return Err(ResourceError::Invalid(
                            r.id.clone(),
                            format!("{} does not support {}", b.device, b.capability),
                        ))
                    }
                    Some(true) => {}
                }
            }
            if let Some(s) = &r.state {
                if supports(&s.device, &read).is_none() {
                    return Err(ResourceError::Invalid(r.id.clone(), format!("unknown device {}", s.device)));
                }
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn get(&self, id: &ResourceId) -> Option<&Resource> {
        self.by_id.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Resource> {
        self.by_id.values()
    }

    pub fn children(&self, id: &ResourceId) -> &[ResourceId] {
        self.children.get(id).map(Vec::as_slice).unwrap_or_default()
    }

    /// Proper ancestors, nearest first.
    pub fn ancestors(&self, id: &ResourceId) -> Vec<&Resource> {
        let mut out = Vec::new();
        let mut cur = self.by_id.get(id).and_then(|r| r.parent.as_ref());
        while let Some(p) = cur {
            let Some(r) = self.by_id.get(p) else { break };
            out.push(r);
            cur = r.parent.as_ref();
        }
        out
    }

    /// `id` itself followed by its ancestors, nearest first.
    pub fn lineage(&self, id: &ResourceId) -> Vec<&Resource> {
        self.by_id.get(id).into_iter().chain(self.ancestors(id)).collect()
    }

    /// `id` and everything below it, depth first.
    pub fn descendants_or_self(&self, id: &ResourceId) -> Vec<&Resource> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(cur) = stack.pop() {
            let Some(r) = self.by_id.get(cur) else { continue };
            out.push(r);
            stack.extend(self.children(cur).iter().rev());
        }
        out
    }

    /// Whether `id` is `ancestor` or lies below it.
    pub fn is_within(&self, id: &ResourceId, ancestor: &ResourceId) -> bool {
        self.lineage(id).iter().any(|r| &r.id == ancestor)
    }

    /// Owners of the nearest resource on the lineage that names any.
    pub fn effective_owners(&self, id: &ResourceId) -> &[EntityId] {
        self.lineage(id).into_iter().map(|r| r.owners.as_slice()).find(|o| !o.is_empty()).unwrap_or_default()
    }

    pub fn is_owner(&self, id: &ResourceId, person: &EntityId) -> bool {
        self.effective_owners(id).contains(person)
    }

    pub fn location(&self, id: &ResourceId) -> Option<Location> {
        let lineage = self.lineage(id);
        let me = lineage.first()?;
        Some(Location {
            site: lineage.last().map(|r| r.id.clone()).unwrap_or_else(|| me.id.clone()),
            space: lineage.iter().find(|r| r.kind == ResourceKind::Space).map(|r| r.id.clone()),
            zone: lineage.iter().find_map(|r| r.zone.clone()),
            boundary: me.boundary,
        })
    }

    /// Resources whose bindings or state reference name `device`.
    /// Whether the resource, or a resource it is in, needs two keys.
    pub fn two_key(&self, id: &ResourceId) -> bool {
        self.lineage(id).iter().any(|r| r.two_key)
    }

    pub fn bound_to(&self, device: &EntityId) -> impl Iterator<Item = &ResourceId> {
        self.by_device.get(device).into_iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(s: &str) -> ResourceId {
        ResourceId::new(s).unwrap()
    }
    fn eid(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }
    fn cap(s: &str) -> CapabilityId {
        CapabilityId::parse(s).unwrap()
    }
    fn reg() -> CapabilityRegistry {
        CapabilityRegistry::core_v0_1()
    }

    fn res(id: &str, kind: ResourceKind, parent: Option<&str>) -> Resource {
        Resource {
            id: rid(id),
            kind,
            name: id.to_string(),
            parent: parent.map(rid),
            owners: vec![],
            boundary: Boundary::Interior,
            zone: None,
            bindings: vec![],
            state: None,
            envelope: vec![],
            two_key: false,
            safe_state: None,
        }
    }

    fn bound(mut r: Resource, device: &str, caps: &[&str]) -> Resource {
        r.bindings = caps
            .iter()
            .map(|c| CapabilityBinding { capability: cap(c), device: eid(device), risk_floor: None })
            .collect();
        r.state = Some(StateRef { device: eid(device), max_age_ms: DEFAULT_MAX_STATE_AGE_MS });
        r
    }

    /// home ⊃ {living-room ⊃ light, entrance ⊃ front-door ⊃ front-door-lock}
    pub(crate) fn home() -> Vec<Resource> {
        let mut site = res("home", ResourceKind::Site, None);
        site.owners = vec![eid("person:alice")];
        let mut door = res("front-door", ResourceKind::Door, Some("entrance"));
        door.boundary = Boundary::Perimeter;
        let mut door = bound(door, "device:front-door", &["lock.lock", "lock.unlock"]);
        door.safe_state = Some(SafeState { capability: cap("lock.lock"), params: Payload::new() });
        let mut entrance = res("entrance", ResourceKind::Space, Some("home"));
        entrance.zone = Some("entrance".into());
        let mut light = bound(
            res("living-room-light", ResourceKind::Light, Some("living-room")),
            "device:living-room-light",
            &["light.turn_on", "light.turn_off", "light.set_brightness"],
        );
        light.envelope = vec![ParamLimit {
            capability: cap("light.set_brightness"),
            param: "brightness_pct".into(),
            min: 0,
            max: 80,
        }];
        vec![site, res("living-room", ResourceKind::Space, Some("home")), light, entrance, door]
    }

    #[test]
    fn ids_and_kinds() {
        assert_eq!(rid("front-door").to_string(), "resource:front-door");
        assert!(ResourceId::parse("device:front-door").is_err());
        assert_eq!(serde_json::to_string(&rid("a")).unwrap(), "\"resource:a\"");
        assert!(serde_json::from_str::<ResourceId>("\"person:a\"").is_err());
        for k in ["site", "door", "robot", "vehicle", "x-acme.drone", "x-acme2.elevator_car"] {
            assert_eq!(ResourceKind::parse(k).unwrap().as_str(), k);
        }
        for k in ["", "Door", "x-.drone", "x-acme", "x-acme.Drone", "x-acme.1drone", "robot.arm"] {
            assert!(ResourceKind::parse(k).is_none(), "{k}");
        }
    }

    #[test]
    fn tree_queries() {
        let g = ResourceGraph::new(home(), &reg()).unwrap();
        let door = rid("front-door");
        assert!(g.is_within(&door, &rid("home")));
        assert!(g.is_within(&door, &door));
        assert!(!g.is_within(&door, &rid("living-room")));
        assert_eq!(g.ancestors(&door).iter().map(|r| r.id.local()).collect::<Vec<_>>(), ["entrance", "home"]);
        assert_eq!(g.effective_owners(&door), [eid("person:alice")]);
        assert!(g.is_owner(&door, &eid("person:alice")) && !g.is_owner(&door, &eid("person:bob")));
        let loc = g.location(&door).unwrap();
        assert_eq!(loc.site, rid("home"));
        assert_eq!(loc.space, Some(rid("entrance")));
        assert_eq!(loc.zone.as_deref(), Some("entrance"));
        assert_eq!(loc.boundary, Boundary::Perimeter);
        let b = g.get(&door).unwrap().binding(&cap("lock.unlock")).unwrap();
        assert_eq!(b.device, eid("device:front-door"));
        assert_eq!(g.bound_to(&eid("device:front-door")).collect::<Vec<_>>(), [&door]);
        assert_eq!(g.children(&rid("home")).len(), 2);
        let below: Vec<&str> = g.descendants_or_self(&rid("entrance")).iter().map(|r| r.id.local()).collect();
        assert_eq!(below, ["entrance", "front-door"]);
        assert_eq!(g.descendants_or_self(&rid("home")).len(), 5);
    }

    #[test]
    fn nearer_owners_override() {
        let mut rs = home();
        rs.iter_mut().find(|r| r.id.local() == "living-room").unwrap().owners = vec![eid("person:bob")];
        let g = ResourceGraph::new(rs, &reg()).unwrap();
        assert_eq!(g.effective_owners(&rid("living-room-light")), [eid("person:bob")]);
        assert_eq!(g.effective_owners(&rid("front-door")), [eid("person:alice")]);
    }

    #[test]
    fn rejects_bad_graphs() {
        let check = |mutate: &dyn Fn(&mut Vec<Resource>)| {
            let mut rs = home();
            mutate(&mut rs);
            ResourceGraph::new(rs, &reg()).unwrap_err()
        };
        let find = |rs: &mut Vec<Resource>, id: &str| rs.iter().position(|r| r.id.local() == id).unwrap();
        // no human with final authority
        assert!(matches!(check(&|rs| rs[0].owners.clear()), ResourceError::Unowned(_)));
        // only persons own
        assert!(matches!(check(&|rs| rs[0].owners = vec![eid("ai:assistant")]), ResourceError::Invalid(..)));
        // dangling parent, cycle, duplicate
        assert!(matches!(
            check(&|rs| rs.push(res("x", ResourceKind::Light, Some("nowhere")))),
            ResourceError::UnknownParent { .. }
        ));
        assert!(matches!(check(&|rs| rs[0].parent = Some(rid("front-door"))), ResourceError::Cycle(_)));
        assert!(matches!(check(&|rs| rs.push(home().remove(1))), ResourceError::Duplicate(_)));
        // containers are not actuated
        assert!(matches!(
            check(&|rs| rs[0] = bound(rs[0].clone(), "device:front-door", &["lock.unlock"])),
            ResourceError::Invalid(..)
        ));
        // bindings: registry, device kind, domain capabilities, risk floor only raises
        assert!(matches!(
            check(&|rs| {
                let i = find(rs, "front-door");
                rs[i].bindings[0].capability = cap("x-acme.door.open");
            }),
            ResourceError::Invalid(..)
        ));
        assert!(matches!(
            check(&|rs| {
                let i = find(rs, "front-door");
                rs[i].bindings[0].device = eid("ai:assistant");
            }),
            ResourceError::Invalid(..)
        ));
        assert!(matches!(
            check(&|rs| {
                let i = find(rs, "front-door");
                rs[i].bindings[0].capability = cap("domain.delegate");
            }),
            ResourceError::Invalid(..)
        ));
        assert!(matches!(
            check(&|rs| {
                let i = find(rs, "front-door");
                rs[i].bindings[1].risk_floor = Some(RiskClass::Medium);
            }),
            ResourceError::Invalid(..)
        ));
        // actions need a state reference; envelopes stay inside the registry range
        assert!(matches!(
            check(&|rs| {
                let i = find(rs, "front-door");
                rs[i].state = None;
            }),
            ResourceError::Invalid(..)
        ));
        assert!(matches!(
            check(&|rs| {
                let i = find(rs, "living-room-light");
                rs[i].envelope[0].max = 140;
            }),
            ResourceError::Invalid(..)
        ));
        assert!(matches!(
            check(&|rs| {
                let i = find(rs, "front-door");
                rs[i].zone = Some("Front Door".into());
            }),
            ResourceError::Invalid(..)
        ));
    }

    #[test]
    fn safe_states_are_bound_valid_and_at_most_medium_risk() {
        let check = |mutate: &dyn Fn(&mut Resource)| {
            let mut rs = home();
            mutate(rs.iter_mut().find(|r| r.id.local() == "front-door").unwrap());
            ResourceGraph::new(rs, &reg())
        };
        let safe = |c: &str, p: Payload| Some(SafeState { capability: cap(c), params: p });
        assert!(check(&|_| {}).is_ok());
        // unlocking is high risk: never a safe state the node runs by itself
        assert!(check(&|r| r.safe_state = safe("lock.unlock", Payload::new())).is_err());
        // a raised floor makes locking too risky as well
        assert!(check(&|r| r.bindings[0].risk_floor = Some(RiskClass::High)).is_err());
        // not bound here, or parameters the capability does not take
        assert!(check(&|r| r.safe_state = safe("light.turn_off", Payload::new())).is_err());
        assert!(check(&|r| r.safe_state = safe("lock.lock", chitala_model::payload([("x", 1i64)]))).is_err());
        // inside the resource's own envelope
        let mut rs = home();
        let light = rs.iter_mut().find(|r| r.id.local() == "living-room-light").unwrap();
        light.safe_state = safe("light.set_brightness", chitala_model::payload([("brightness_pct", 90i64)]));
        assert!(ResourceGraph::new(rs.clone(), &reg()).is_err());
        let light = rs.iter_mut().find(|r| r.id.local() == "living-room-light").unwrap();
        light.safe_state = safe("light.set_brightness", chitala_model::payload([("brightness_pct", 10i64)]));
        assert!(ResourceGraph::new(rs, &reg()).is_ok());
    }

    #[test]
    fn risk_floor_raises() {
        let mut rs = home();
        let door = rs.iter_mut().find(|r| r.id.local() == "front-door").unwrap();
        door.bindings[1].risk_floor = Some(RiskClass::Critical);
        let g = ResourceGraph::new(rs, &reg()).unwrap();
        let b = g.get(&rid("front-door")).unwrap().binding(&cap("lock.unlock")).unwrap();
        assert_eq!(b.risk_floor, Some(RiskClass::Critical));
    }

    #[test]
    fn devices_are_checked() {
        let g = ResourceGraph::new(home(), &reg()).unwrap();
        let caps = |d: &EntityId, c: &CapabilityId| match d.local() {
            "front-door" => Some(c.as_str().starts_with("lock.") || c.as_str() == "device.read_state"),
            "living-room-light" => Some(c.as_str().starts_with("light.") || c.as_str() == "device.read_state"),
            _ => None,
        };
        g.check_devices(caps).unwrap();
        let no_unlock = |d: &EntityId, c: &CapabilityId| Some(c.as_str() != "lock.unlock" || d.local() != "front-door");
        assert!(g.check_devices(no_unlock).is_err());
        assert!(g.check_devices(|_: &EntityId, _: &CapabilityId| None).is_err());
    }

    #[test]
    fn config_round_trip() {
        let json = serde_json::to_string(&home()).unwrap();
        let back: Vec<Resource> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, home());
        let bad = r#"[{"id":"resource:a","kind":"site","name":"A","owners":["person:a"],"surprise":1}]"#;
        assert!(serde_json::from_str::<Vec<Resource>>(bad).is_err());
    }
}
