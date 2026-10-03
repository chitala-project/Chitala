//! Identifiers (spec §01-core-model "Identifiers").
//!
//! `EntityId`    = kind ":" local         e.g. `person:alice`, `ai:assistant`, `device:living-room-light`
//! `CapabilityId` = segment ("." segment)+ e.g. `light.turn_on`, `x-acme.fan.set_speed`

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const MAX_LOCAL_LEN: usize = 128;
pub const MAX_CAPABILITY_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("entity id must have the form <kind>:<local>: {0:?}")]
    Malformed(String),
    #[error("unknown entity kind {0:?}")]
    UnknownKind(String),
    #[error("invalid local id {0:?} (allowed: [a-z0-9][a-z0-9._-]{{0,127}})")]
    InvalidLocal(String),
    #[error("invalid capability id {0:?}")]
    InvalidCapability(String),
}

/// Principal / object kinds. `Person`, `Ai`, `Service` and `Device` are distinct
/// principals: `Device_ID ≠ AI_ID` (Blueprint v12 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityKind {
    Person,
    Ai,
    Device,
    Service,
    Domain,
}

impl EntityKind {
    pub const ALL: [EntityKind; 5] =
        [EntityKind::Person, EntityKind::Ai, EntityKind::Device, EntityKind::Service, EntityKind::Domain];

    pub fn as_str(self) -> &'static str {
        match self {
            EntityKind::Person => "person",
            EntityKind::Ai => "ai",
            EntityKind::Device => "device",
            EntityKind::Service => "service",
            EntityKind::Domain => "domain",
        }
    }

    /// Cedar entity type (spec §06-policy).
    pub fn cedar_type(self) -> &'static str {
        match self {
            EntityKind::Person => "Chitala::Person",
            EntityKind::Ai => "Chitala::AI",
            EntityKind::Device => "Chitala::Device",
            EntityKind::Service => "Chitala::Service",
            EntityKind::Domain => "Chitala::Domain",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntityId {
    kind: EntityKind,
    local: String,
}

fn valid_local(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_LOCAL_LEN {
        return false;
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
    first_ok
        && bytes[1..].iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

impl EntityId {
    pub fn new(kind: EntityKind, local: impl Into<String>) -> Result<Self, IdError> {
        let local = local.into();
        if !valid_local(&local) {
            return Err(IdError::InvalidLocal(local));
        }
        Ok(Self { kind, local })
    }

    pub fn parse(s: &str) -> Result<Self, IdError> {
        let (kind, local) = s.split_once(':').ok_or_else(|| IdError::Malformed(s.to_string()))?;
        let kind = EntityKind::parse(kind).ok_or_else(|| IdError::UnknownKind(kind.to_string()))?;
        Self::new(kind, local)
    }

    pub fn kind(&self) -> EntityKind {
        self.kind
    }

    pub fn local(&self) -> &str {
        &self.local
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.local)
    }
}

impl FromStr for EntityId {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for EntityId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EntityId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Capability identifier. First segment may be a vendor namespace `x-<vendor>`;
/// every other segment is `[a-z][a-z0-9_]*`. At least two segments.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityId(String);

fn valid_segment(seg: &str) -> bool {
    let b = seg.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b[1..].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn valid_vendor_segment(seg: &str) -> bool {
    match seg.strip_prefix("x-") {
        Some(v) => !v.is_empty() && v.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        None => false,
    }
}

impl CapabilityId {
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if s.len() > MAX_CAPABILITY_LEN {
            return Err(IdError::InvalidCapability(s.to_string()));
        }
        let segs: Vec<&str> = s.split('.').collect();
        let ok = segs.len() >= 2
            && (valid_segment(segs[0]) || valid_vendor_segment(segs[0]))
            && segs[1..].iter().all(|seg| valid_segment(seg));
        if ok {
            Ok(Self(s.to_string()))
        } else {
            Err(IdError::InvalidCapability(s.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_vendor_extension(&self) -> bool {
        self.0.starts_with("x-")
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CapabilityId {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for CapabilityId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapabilityId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_ids_round_trip() {
        for s in ["person:alice", "ai:assistant-1", "device:ha.light.living_room", "domain:home-1"] {
            assert_eq!(EntityId::parse(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn entity_ids_reject_bad_input() {
        for s in ["alice", "robot:x", "person:", "person:Alice", "person:-x", "person:a b", "person:a\"b"] {
            assert!(EntityId::parse(s).is_err(), "{s} should be rejected");
        }
        assert!(EntityId::parse(&format!("person:{}", "a".repeat(129))).is_err());
    }

    #[test]
    fn capability_ids() {
        for s in ["light.turn_on", "climate.set_target_temperature", "x-acme.fan.set_speed"] {
            assert!(CapabilityId::parse(s).is_ok(), "{s}");
        }
        for s in ["light", "Light.on", "light..on", "light.on-off", "x-.fan", "*", "light.*", "1x.y"] {
            assert!(CapabilityId::parse(s).is_err(), "{s} should be rejected");
        }
    }
}
