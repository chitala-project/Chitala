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
//!   says so; it never picks one. It compares only pieces over the same
//!   scope, and keeps every piece whole.
//! - **Nothing here raises an assurance level.** Evidence that claims to be
//!   attested is refused, because attestation does not exist yet (gap G-4).
//! - **Checked is not authenticated.** [`validate`] checks the form, the
//!   bounds and the times against the node's now. It verifies no signature,
//!   and nothing stamps `received_at_ms` yet: those fields are what whoever
//!   built the evidence declared.
//!
//! Safety does not use these types yet: that is the Safety Contract's step
//! (P3). Every path to a [`Checked`] checks every bound: lengths, counts,
//! times, coordinates and the encoded size.

use std::io::Write;

use chitala_model::EntityId;
use chitala_resource::ResourceId;
use serde::{Deserialize, Serialize};

/// Bounds on everything evidence may carry.
pub mod limits {
    /// The evidence, encoded (spec 35: no whitespace outside strings, absent
    /// fields left out), in bytes; and the input [`super::decode`] reads.
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
    /// When the node received it, by the node's clock, as whoever built the
    /// evidence declares it: nothing stamps it yet (P3). [`validate`] checks
    /// only that it is not ahead of the node's now.
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
    /// The whole resource. A struct variant, so that an unknown field
    /// beside it is refused like any other.
    Whole {},
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
#[serde(tag = "type", content = "value", rename_all = "snake_case", deny_unknown_fields)]
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
    /// The reading's accuracy, when the source states one. Left out of the
    /// encoding when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// Whoever built the evidence declares that the source signed it. The
    /// evidence carries no signature and [`validate`] verifies none: until
    /// P3 does, `true` establishes nothing. A verified signature would prove
    /// who sent it, never that it is true.
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
    #[error("the node's now is before a piece of evidence was checked: its clock went back")]
    TimeWentBack,
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
            Self::TimeWentBack => "time_went_back",
        }
    }
}

/// Evidence that passed [`validate`]: well-formed, within every bound, and
/// valid at the time it was checked. Nothing else makes one.
///
/// It means that and no more: not that the source is who it says, not that a
/// signature was verified, not that the node stamped its receipt, and not
/// that what it says is true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    evidence: Evidence,
    checked_at_ms: u64,
}

impl Checked {
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The node's now when it was checked.
    pub fn checked_at_ms(&self) -> u64 {
        self.checked_at_ms
    }

    /// Valid at `now_ms`: not expired, and not before it was checked (a
    /// clock that went back makes it valid at no time).
    pub fn valid_at(&self, now_ms: u64) -> bool {
        self.checked_at_ms <= now_ms && now_ms < self.evidence.valid_until_ms
    }
}

/// Counts bytes, and stops at the bound: measuring the size never allocates
/// and never writes more than the bound.
struct Measure(usize);

impl Write for Measure {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        if self.0 > limits::MAX_ENCODED_BYTES {
            return Err(std::io::Error::other("too large"));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The encoding of spec 35 is within [`limits::MAX_ENCODED_BYTES`].
fn encoded_within_bound(e: &Evidence) -> bool {
    serde_json::to_writer(&mut Measure(0), e).is_ok()
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

/// A whole, or a region of 3 to [`limits::MAX_REGION_POINTS`] corners within
/// [`limits::MAX_COORD_MM`] that is strictly convex.
fn scope_ok(scope: &Scope) -> bool {
    use limits::*;
    match scope {
        Scope::Whole {} => true,
        Scope::Region { points_mm } => {
            (3..=MAX_REGION_POINTS).contains(&points_mm.len())
                && points_mm.iter().flatten().all(|c| (-MAX_COORD_MM..=MAX_COORD_MM).contains(c))
                && convex(points_mm)
        }
    }
}

/// A region's corners in one form: counter-clockwise, from the least corner.
/// Two regions are the same when their forms are equal, whatever corner and
/// direction each was given in. Only for a region [`scope_ok`] accepts.
fn canonical(points: &[[i64; 2]]) -> Vec<[i64; 2]> {
    let (a, b, c) = (points[0], points[1], points[2]);
    let cross = i128::from(b[0] - a[0]) * i128::from(c[1] - a[1]) - i128::from(b[1] - a[1]) * i128::from(c[0] - a[0]);
    let mut v = points.to_vec();
    if cross < 0 {
        v.reverse();
    }
    let least = v.iter().enumerate().min_by_key(|(_, p)| **p).map_or(0, |(i, _)| i);
    v.rotate_left(least);
    v
}

/// The same scope: both whole, or the same region. Nothing else is compared
/// yet: a region is never taken to stand for the whole, nor the whole for a
/// region, nor one region for another that it overlaps.
fn same_scope(a: &Scope, b: &Scope) -> bool {
    match (a, b) {
        (Scope::Whole {}, Scope::Whole {}) => true,
        (Scope::Region { points_mm: a }, Scope::Region { points_mm: b }) => canonical(a) == canonical(b),
        _ => false,
    }
}

fn unit_ok(u: &str) -> bool {
    !u.is_empty() && u.len() <= limits::MAX_UNIT_LEN && u.chars().all(|c| c.is_ascii_lowercase() || c == '_')
}

/// Decode evidence from JSON, then [`validate`] it. Input above
/// [`limits::MAX_ENCODED_BYTES`] is refused before it is parsed, so a sender
/// sends the encoding of spec 35, without padding.
pub fn decode(bytes: &[u8], now_ms: u64) -> Result<Checked, EvidenceError> {
    if bytes.len() > limits::MAX_ENCODED_BYTES {
        return Err(EvidenceError::TooLarge);
    }
    let e: Evidence = serde_json::from_slice(bytes).map_err(|e| EvidenceError::Malformed(e.to_string()))?;
    validate(e, now_ms)
}

/// Check every bound of `e`, its encoded size first, as [`decode`] does, and
/// that it is valid at `now_ms`.
pub fn validate(e: Evidence, now_ms: u64) -> Result<Checked, EvidenceError> {
    use limits::*;
    if !encoded_within_bound(&e) {
        return Err(EvidenceError::TooLarge);
    }
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
    if !scope_ok(&e.scope) {
        return Err(EvidenceError::BadRegion);
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
    Ok(Checked { evidence: e, checked_at_ms: now_ms })
}

/// What the counted pieces say together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every counted piece that knows says this value.
    Agreed(Measured),
    /// Counted pieces that know disagree. Nothing is picked, not even the
    /// more confident or the safer value.
    Conflict,
    /// No counted piece knows.
    Unknown,
}

/// Why a piece of the question's kind and subject was not counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftOut {
    /// It covers another scope. Evidence about one scope says nothing about
    /// another.
    OtherScope,
    /// Its source observed again later: a source counts by its latest
    /// observation only, so an older one never comes back when a newer one
    /// expires.
    Superseded,
    /// Its source said the same about the same moment again: counted once.
    Repeated,
    /// It expired. Expired evidence is no evidence.
    Expired,
}

/// What the pieces of one kind, about one subject, over one scope, say at
/// one time, with every piece kept whole: its times, scope, quality and
/// provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combination {
    pub kind: String,
    pub subject: ResourceId,
    /// What it is about, and nothing more: an `Agreed` over a region says
    /// nothing about the rest of the subject.
    pub scope: Scope,
    /// The node's now when it was combined.
    pub at_ms: u64,
    /// The earliest end of validity among the counted pieces. With nothing
    /// counted, `at_ms`: it holds at no time, and is combined again.
    pub valid_until_ms: u64,
    pub verdict: Verdict,
    /// The pieces counted: from each source, its latest observation.
    pub counted: Vec<Checked>,
    /// The pieces of this kind and subject that were not counted, and why.
    pub left_out: Vec<(Checked, LeftOut)>,
}

impl Combination {
    /// It still holds at `now_ms`: not before it was made, and before any
    /// counted piece expires.
    pub fn holds_at(&self, now_ms: u64) -> bool {
        self.at_ms <= now_ms && now_ms < self.valid_until_ms
    }

    /// The distinct sources of the counted pieces. Two pieces from one
    /// source are one source; and distinct sources are not shown to be
    /// independent (spec 35).
    pub fn sources(&self) -> Vec<&EntityId> {
        let mut v: Vec<&EntityId> = self.counted.iter().map(|p| &p.evidence.source).collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Combine the pieces of `kind` about `subject` over `scope`, as they stand
/// at `now_ms`. Pieces of another kind or subject are not part of the
/// question and are ignored; every other piece is either counted or left out
/// with its reason.
pub fn combine(
    pieces: &[Checked],
    subject: &ResourceId,
    kind: &str,
    scope: &Scope,
    now_ms: u64,
) -> Result<Combination, EvidenceError> {
    if pieces.len() > limits::MAX_COMBINED {
        return Err(EvidenceError::TooMany);
    }
    if !scope_ok(scope) {
        return Err(EvidenceError::BadRegion);
    }
    if pieces.iter().any(|p| now_ms < p.checked_at_ms) {
        return Err(EvidenceError::TimeWentBack);
    }
    let asked: Vec<&Checked> =
        pieces.iter().filter(|p| &p.evidence.subject == subject && p.evidence.kind == kind).collect();
    let mut counted: Vec<Checked> = Vec::new();
    let mut left_out: Vec<(Checked, LeftOut)> = Vec::new();
    for p in &asked {
        let e = &p.evidence;
        let latest = asked
            .iter()
            .filter(|q| q.evidence.source == e.source && same_scope(&q.evidence.scope, &e.scope))
            .map(|q| q.evidence.observed_at_ms)
            .max()
            .unwrap_or(e.observed_at_ms);
        let why = if !same_scope(&e.scope, scope) {
            Some(LeftOut::OtherScope)
        } else if e.observed_at_ms < latest {
            Some(LeftOut::Superseded)
        } else if !p.valid_at(now_ms) {
            Some(LeftOut::Expired)
        } else if counted.iter().any(|c| {
            c.evidence.source == e.source
                && c.evidence.observed_at_ms == e.observed_at_ms
                && c.evidence.reading == e.reading
        }) {
            Some(LeftOut::Repeated)
        } else {
            None
        };
        match why {
            Some(why) => left_out.push(((*p).clone(), why)),
            None => counted.push((*p).clone()),
        }
    }
    let mut known = counted.iter().filter_map(|p| match &p.evidence.reading {
        Reading::Known { value } => Some(value),
        Reading::Unknown { .. } => None,
    });
    let verdict = match known.next() {
        None => Verdict::Unknown,
        Some(first) if known.all(|v| v == first) => Verdict::Agreed(first.clone()),
        Some(_) => Verdict::Conflict,
    };
    let valid_until_ms = counted.iter().map(|p| p.evidence.valid_until_ms).min().unwrap_or(now_ms);
    Ok(Combination {
        kind: kind.to_string(),
        subject: subject.clone(),
        scope: scope.clone(),
        at_ms: now_ms,
        valid_until_ms,
        verdict,
        counted,
        left_out,
    })
}

#[cfg(test)]
mod tests;
