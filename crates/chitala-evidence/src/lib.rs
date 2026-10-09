//! Typed evidence (spec 35): what a source observed about a resource, when,
//! until when, how well, and how it came to the node. Never a bare
//! `safe = true`.
//!
//! - **A signature is not the truth.** It proves who sent the evidence, not
//!   that what it says is so. These types carry what is needed to judge
//!   evidence; they judge nothing on their own.
//! - **Unknown is a value.** Evidence may say that its source does not know.
//!   That is never read as any known value.
//! - **A conflict stays a conflict.** When sources disagree, [`combine`]
//!   says so; it never picks one.
//! - **Nothing here raises an assurance level.** Evidence that claims to be
//!   attested is refused, because attestation does not exist yet (gap G-4).
//!
//! Safety does not use these types yet: that is the Safety Contract's step
//! (P3). Every bound is checked: lengths, counts, times, coordinates and the
//! encoded size.

use chitala_model::EntityId;
use chitala_resource::ResourceId;
use serde::{Deserialize, Serialize};

/// Bounds on everything evidence may carry.
pub mod limits {
    /// The encoded evidence, in bytes.
    pub const MAX_ENCODED_BYTES: usize = 4_096;
    /// A kind's name, in characters.
    pub const MAX_KIND_LEN: usize = 64;
    /// A text reading, an unknown's reason, an adapter's name.
    pub const MAX_TEXT_LEN: usize = 256;
    /// A unit's name.
    pub const MAX_UNIT_LEN: usize = 16;
    /// Points of a region.
    pub const MAX_REGION_POINTS: usize = 16;
    /// A region's coordinates, in millimetres either side of the resource's
    /// origin: a thousand kilometres.
    pub const MAX_COORD_MM: i64 = 1_000_000_000;
    /// Hops between the source and the node.
    pub const MAX_PATH_HOPS: usize = 8;
    /// How long after its observation evidence may stay valid.
    pub const MAX_VALIDITY_MS: u64 = 3_600_000;
    /// How far ahead of the node a time may be, for clocks that disagree.
    pub const CLOCK_SKEW_MS: u64 = 5_000;
    /// Pieces of evidence combined at once.
    pub const MAX_COMBINED: usize = 32;
}

/// One piece of evidence, as a source reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// What is observed: `obstacle`, `localization`, `lock.bolt`, … A name,
    /// not a meaning: what a kind means is the contract's (P3).
    pub kind: String,
    /// The resource it is about.
    pub subject: ResourceId,
    /// The principal that observed it: a device, a sensor, a service.
    pub source: EntityId,
    /// When the source observed it, by the source's clock.
    pub observed_at_ms: u64,
    /// When the node received it, by the node's clock.
    pub received_at_ms: u64,
    /// After this, it is no evidence at all.
    pub valid_until_ms: u64,
    /// Which part of the subject it covers.
    pub scope: Scope,
    pub reading: Reading,
    pub quality: Quality,
    pub provenance: Provenance,
}

/// Which part of the subject evidence covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    /// The whole resource.
    Whole,
    /// A strictly convex region of it, in millimetres, in the resource's
    /// frame: its corners in order, in either direction.
    Region { points_mm: Vec<[i64; 2]> },
}

/// What the source reported: a value, or that it does not know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reading {
    Known { value: Measured },
    Unknown { reason: String },
}

/// A measured value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Measured {
    Bool(bool),
    Int(i64),
    Text(String),
}

/// How good the source says its reading is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quality {
    /// The source's own confidence, from 0 to 1000.
    pub confidence_per_mille: u16,
    /// The reading's accuracy, when the source states one.
    pub accuracy: Option<Accuracy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accuracy {
    /// Plus or minus this much…
    pub plus_minus: u64,
    /// …in this unit: `mm`, `mdeg`, `c_milli`, …
    pub unit: String,
}

/// How the evidence came to the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// The adapter that delivered it.
    pub adapter: String,
    /// The principals it passed through, from the source to the node.
    pub path: Vec<EntityId>,
    /// The source signed it. That proves who sent it, not that it is true.
    pub signed_by_source: bool,
    /// The source was attested. Always false: attestation does not exist
    /// yet, and a claim of it is refused (gap G-4).
    pub attested: bool,
}

/// Why evidence was refused. Each has a stable code, used by the test vectors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("the evidence is larger than {} bytes", limits::MAX_ENCODED_BYTES)]
    TooLarge,
    #[error("the evidence is malformed: {0}")]
    Malformed(String),
    #[error("a kind is 1 to {} characters of a-z, 0-9, '.', '_' or '-', starting with a letter", limits::MAX_KIND_LEN)]
    BadKind,
    #[error("observed after it was received, beyond the clock's skew")]
    FromTheFuture,
    #[error("received after the node's now, beyond the clock's skew")]
    ReceivedInTheFuture,
    #[error("valid until a time before its observation")]
    ValidBeforeObserved,
    #[error("valid for longer than {} ms after its observation", limits::MAX_VALIDITY_MS)]
    ValidTooLong,
    #[error("expired: it is no evidence any more")]
    Expired,
    #[error("a confidence is from 0 to 1000")]
    ConfidenceOutOfRange,
    #[error("a unit is 1 to {} characters of a-z or '_'", limits::MAX_UNIT_LEN)]
    BadUnit,
    #[error(
        "a region is 3 to {} corners of a strictly convex polygon, in order, within {} mm of the origin",
        limits::MAX_REGION_POINTS,
        limits::MAX_COORD_MM
    )]
    BadRegion,
    #[error("a path has at most {} hops", limits::MAX_PATH_HOPS)]
    PathTooLong,
    #[error("a text is at most {} characters", limits::MAX_TEXT_LEN)]
    TextTooLong,
    #[error("attestation is not supported yet: evidence that claims it is refused (gap G-4)")]
    AttestationUnsupported,
    #[error("at most {} pieces of evidence are combined at once", limits::MAX_COMBINED)]
    TooMany,
}

impl EvidenceError {
    /// The stable code of this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::Malformed(_) => "malformed",
            Self::BadKind => "bad_kind",
            Self::FromTheFuture => "from_the_future",
            Self::ReceivedInTheFuture => "received_in_the_future",
            Self::ValidBeforeObserved => "valid_before_observed",
            Self::ValidTooLong => "valid_too_long",
            Self::Expired => "expired",
            Self::ConfidenceOutOfRange => "confidence_out_of_range",
            Self::BadUnit => "bad_unit",
            Self::BadRegion => "bad_region",
            Self::PathTooLong => "path_too_long",
            Self::TextTooLong => "text_too_long",
            Self::AttestationUnsupported => "attestation_unsupported",
            Self::TooMany => "too_many",
        }
    }
}

/// Evidence that passed [`validate`]: well-formed, within every bound, and
/// valid at the time it was checked. Nothing else makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked(Evidence);

impl Checked {
    pub fn evidence(&self) -> &Evidence {
        &self.0
    }

    /// Still valid at `now_ms`.
    pub fn valid_at(&self, now_ms: u64) -> bool {
        now_ms < self.0.valid_until_ms
    }
}

fn text_ok(s: &str, max: usize) -> bool {
    s.chars().count() <= max
}

fn kind_ok(k: &str) -> bool {
    let mut chars = k.chars();
    k.len() <= limits::MAX_KIND_LEN
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// The corners of a strictly convex polygon, in order, in either direction:
/// every other corner lies strictly on one side of every edge, the same side
/// for all of them. That refuses a dent, edges that cross, a repeated corner
/// and three corners on a line. Within [`limits::MAX_COORD_MM`], nothing
/// overflows.
fn convex(points: &[[i64; 2]]) -> bool {
    let n = points.len();
    let mut side = 0;
    for i in 0..n {
        let (a, b) = (points[i], points[(i + 1) % n]);
        for (j, p) in points.iter().enumerate() {
            if j == i || j == (i + 1) % n {
                continue;
            }
            let cross =
                i128::from(b[0] - a[0]) * i128::from(p[1] - a[1]) - i128::from(b[1] - a[1]) * i128::from(p[0] - a[0]);
            if cross == 0 || (side != 0 && cross.signum() != side) {
                return false;
            }
            side = cross.signum();
        }
    }
    true
}

fn unit_ok(u: &str) -> bool {
    !u.is_empty() && u.len() <= limits::MAX_UNIT_LEN && u.chars().all(|c| c.is_ascii_lowercase() || c == '_')
}

/// Decode evidence from JSON, within the size bound and with no unknown
/// field, then [`validate`] it.
pub fn decode(bytes: &[u8], now_ms: u64) -> Result<Checked, EvidenceError> {
    if bytes.len() > limits::MAX_ENCODED_BYTES {
        return Err(EvidenceError::TooLarge);
    }
    let e: Evidence = serde_json::from_slice(bytes).map_err(|e| EvidenceError::Malformed(e.to_string()))?;
    validate(e, now_ms)
}

/// Check every bound of `e`, and that it is valid at `now_ms`.
pub fn validate(e: Evidence, now_ms: u64) -> Result<Checked, EvidenceError> {
    use limits::*;
    if !kind_ok(&e.kind) {
        return Err(EvidenceError::BadKind);
    }
    if e.observed_at_ms > e.received_at_ms.saturating_add(CLOCK_SKEW_MS) {
        return Err(EvidenceError::FromTheFuture);
    }
    if e.received_at_ms > now_ms.saturating_add(CLOCK_SKEW_MS) {
        return Err(EvidenceError::ReceivedInTheFuture);
    }
    if e.valid_until_ms <= e.observed_at_ms {
        return Err(EvidenceError::ValidBeforeObserved);
    }
    if e.valid_until_ms - e.observed_at_ms > MAX_VALIDITY_MS {
        return Err(EvidenceError::ValidTooLong);
    }
    if now_ms >= e.valid_until_ms {
        return Err(EvidenceError::Expired);
    }
    if e.quality.confidence_per_mille > 1_000 {
        return Err(EvidenceError::ConfidenceOutOfRange);
    }
    if e.quality.accuracy.as_ref().is_some_and(|a| !unit_ok(&a.unit)) {
        return Err(EvidenceError::BadUnit);
    }
    if let Scope::Region { points_mm } = &e.scope {
        if !(3..=MAX_REGION_POINTS).contains(&points_mm.len())
            || points_mm.iter().flatten().any(|c| !(-MAX_COORD_MM..=MAX_COORD_MM).contains(c))
            || !convex(points_mm)
        {
            return Err(EvidenceError::BadRegion);
        }
    }
    let text = match &e.reading {
        Reading::Known { value: Measured::Text(t) } => Some(t),
        Reading::Unknown { reason } => Some(reason),
        Reading::Known { .. } => None,
    };
    if text.is_some_and(|t| !text_ok(t, MAX_TEXT_LEN)) || !text_ok(&e.provenance.adapter, MAX_TEXT_LEN) {
        return Err(EvidenceError::TextTooLong);
    }
    if e.provenance.path.len() > MAX_PATH_HOPS {
        return Err(EvidenceError::PathTooLong);
    }
    if e.provenance.attested {
        return Err(EvidenceError::AttestationUnsupported);
    }
    Ok(Checked(e))
}

/// What several pieces of evidence of one kind about one subject say
/// together, at one time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Combined {
    /// Every source that knows says the same. Sources that do not know, or
    /// whose evidence expired, are listed: the caller decides what they mean.
    Agreed { value: Measured, sources: Vec<EntityId>, unknown: Vec<EntityId> },
    /// Sources that know disagree. Nothing is picked.
    Conflict { readings: Vec<(EntityId, Measured)>, unknown: Vec<EntityId> },
    /// No source knows, or none is valid any more.
    Unknown { sources: Vec<EntityId> },
}

/// Combine the pieces of `kind` about `subject`, as they stand at `now_ms`.
/// Pieces of another kind or subject are left out. Expired pieces count as
/// sources that do not know.
pub fn combine(pieces: &[Checked], subject: &ResourceId, kind: &str, now_ms: u64) -> Result<Combined, EvidenceError> {
    if pieces.len() > limits::MAX_COMBINED {
        return Err(EvidenceError::TooMany);
    }
    let mut known: Vec<(EntityId, Measured)> = Vec::new();
    let mut unknown: Vec<EntityId> = Vec::new();
    for p in pieces.iter().filter(|p| &p.0.subject == subject && p.0.kind == kind) {
        match (&p.0.reading, p.valid_at(now_ms)) {
            (Reading::Known { value }, true) => known.push((p.0.source.clone(), value.clone())),
            _ => unknown.push(p.0.source.clone()),
        }
    }
    let Some((_, first)) = known.first() else {
        return Ok(Combined::Unknown { sources: unknown });
    };
    if known.iter().all(|(_, v)| v == first) {
        let value = first.clone();
        return Ok(Combined::Agreed { value, sources: known.into_iter().map(|(s, _)| s).collect(), unknown });
    }
    Ok(Combined::Conflict { readings: known, unknown })
}

#[cfg(test)]
mod tests;
