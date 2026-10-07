//! Checked history constraints, the Trusted Core's side (spec 32).
//!
//! History may make Safety stricter; it never supplies evidence that turns a
//! DENY into an ALLOW. A history evaluator, outside the Trusted Core, measures
//! a rule over the history log and signs a [`CheckedHistoryConstraint`]. The
//! core never reads the history and never trusts a signature alone. It
//! computes the evaluation context and the rules' digests itself, and
//! [`check`] decides `SAFE-10-HISTORY`: pass through, or refuse, for one of
//! three causes ([`Refusal`]).
//!
//! This crate is plain data and arithmetic over it: no I/O, no clock, no
//! keys. Verifying the signature against the authorized evaluator's enrolled
//! key is the node's, before it hands the records over.

#![forbid(unsafe_code)]

use chitala_model::{CapabilityId, EntityId, ParamValue, Payload};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A record lives at most this long after it was evaluated.
pub const MAX_CONSTRAINT_TTL_MS: u64 = 5_000;
/// The longest window a rule may measure: the history's retention.
pub const MAX_WINDOW_MS: u64 = 30 * 86_400_000;

/// What a rule measures (spec 32). Only these four; no query language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryPredicate {
    /// The key has been in the value without a known break for less than this.
    MaxContinuousMs { limit_ms: u64 },
    /// The key has been known out of the value for at least this.
    MinOffBeforeMs { limit_ms: u64 },
    /// Fewer entries into the value than this, in the window.
    MaxEntries { limit: u64, window_ms: u64 },
    /// Less time in the value than this, in the window.
    MaxInValueMs { limit_ms: u64, window_ms: u64 },
}

impl HistoryPredicate {
    /// The span of time the rule looks at, back from now.
    pub fn window_ms(&self) -> u64 {
        match *self {
            HistoryPredicate::MaxContinuousMs { limit_ms } | HistoryPredicate::MinOffBeforeMs { limit_ms } => limit_ms,
            HistoryPredicate::MaxEntries { window_ms, .. } | HistoryPredicate::MaxInValueMs { window_ms, .. } => {
                window_ms
            }
        }
    }
}

/// A history rule on one resource, for one capability (spec 32). Managed by
/// owners and authorized admins, versioned: the core holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRule {
    pub rule_id: String,
    pub version: u64,
    pub capability: CapabilityId,
    /// The device key it measures, and the value that counts.
    pub key: String,
    pub value: ParamValue,
    pub predicate: HistoryPredicate,
    /// How much unknown time the window may hold before the verdict is
    /// INSUFFICIENT_HISTORY. Not for `max_entries`: there, any is too much.
    #[serde(default)]
    pub max_unknown_ms: u64,
}

impl HistoryRule {
    /// A rule is well formed: a short id, a key, a limit and a window within
    /// the history's retention.
    pub fn check(&self) -> Result<(), String> {
        let label = |s: &str| {
            !s.is_empty()
                && s.len() <= 32
                && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        };
        if !label(&self.rule_id) {
            return Err(format!("rule id {:?}: 1..32 of [a-z0-9_-]", self.rule_id));
        }
        if self.key.is_empty() || self.key.len() > 32 {
            return Err(format!("{}: the key is 1..32 characters", self.rule_id));
        }
        if self.version == 0 {
            return Err(format!("{}: versions start at 1", self.rule_id));
        }
        let (limit, window) = match self.predicate {
            HistoryPredicate::MaxContinuousMs { limit_ms } | HistoryPredicate::MinOffBeforeMs { limit_ms } => {
                (limit_ms, limit_ms)
            }
            HistoryPredicate::MaxEntries { limit, window_ms } => (limit, window_ms),
            HistoryPredicate::MaxInValueMs { limit_ms, window_ms } => (limit_ms, window_ms),
        };
        if limit == 0 || window == 0 || window > MAX_WINDOW_MS {
            return Err(format!("{}: a limit, and a window of at most 30 days", self.rule_id));
        }
        if self.max_unknown_ms > window {
            return Err(format!("{}: max_unknown_ms is at most the window", self.rule_id));
        }
        Ok(())
    }

    /// SHA-256 of the rule's definition, version included.
    pub fn digest(&self) -> [u8; 32] {
        let mut e = Enc::new("chitala-history-rule-v1");
        e.rule(self);
        e.finish()
    }
}

/// SHA-256 over the rules that govern an action, sorted by id.
pub fn rule_set_digest(rules: &[HistoryRule]) -> [u8; 32] {
    let mut sorted: Vec<&HistoryRule> = rules.iter().collect();
    sorted.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    let mut e = Enc::new("chitala-history-rule-set-v1");
    e.u64(sorted.len() as u64);
    for r in sorted {
        e.bytes(&r.digest());
    }
    e.finish()
}

/// The request as verified, before Safety (spec 32): what a record is bound
/// to. It never contains a Safety result, nor the final decision.
#[derive(Debug, Clone, Copy)]
pub struct EvaluationContext<'a> {
    /// The intent id or the request's message id.
    pub subject: &'a [u8; 16],
    pub actor: &'a EntityId,
    pub on_behalf_of: &'a EntityId,
    pub resource: &'a EntityId,
    pub capability: &'a CapabilityId,
    pub parameters: &'a Payload,
    pub authority_epoch: u64,
    pub rule_set_digest: [u8; 32],
}

impl EvaluationContext<'_> {
    pub fn digest(&self) -> [u8; 32] {
        let mut e = Enc::new("chitala-history-context-v1");
        e.bytes(self.subject);
        e.str(&self.actor.to_string());
        e.str(&self.on_behalf_of.to_string());
        e.str(&self.resource.to_string());
        e.str(self.capability.as_str());
        e.payload(self.parameters);
        e.u64(self.authority_epoch);
        e.bytes(&self.rule_set_digest);
        e.finish()
    }
}

/// A point of the history log's hash chain, recorded in the audit log
/// (spec 32): the log once reached `head`, the link after its `len`-th
/// record, in the chain that begins with `chain`. A log that no longer
/// contains it was truncated or replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryAnchor {
    /// The chain's first link: which chain (a compaction begins a new one).
    #[serde(with = "hex32")]
    pub chain: [u8; 32],
    pub len: u64,
    #[serde(with = "hex32")]
    pub head: [u8; 32],
}

/// What the evaluator found. There is no ALLOW.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryVerdict {
    /// This rule adds no denial; everything else still decides.
    PassThrough,
    /// Enough history, and the limit is reached.
    LimitExceeded,
    /// Too much unknown time, or a broken chain, to show the limit is kept.
    InsufficientHistory,
}

/// The record an evaluator signs, one per rule (spec 32).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckedHistoryConstraint {
    #[serde(with = "hex32")]
    pub evaluation_context_digest: [u8; 32],
    pub resource: EntityId,
    pub capability: CapabilityId,
    pub rule_id: String,
    pub rule_version: u64,
    #[serde(with = "hex32")]
    pub rule_digest: [u8; 32],
    pub verdict: HistoryVerdict,
    /// The worst-case measure, in ms or entries.
    pub measured_value: u64,
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub unknown_ms: u64,
    /// The history chain's hash at the last record measured.
    #[serde(with = "hex32")]
    pub evidence_digest: [u8; 32],
    pub evaluated_at_ms: u64,
    pub expires_at_ms: u64,
    pub evaluator_id: EntityId,
    pub evaluator_version: String,
}

impl CheckedHistoryConstraint {
    /// The bytes the evaluator signs: every field, canonically.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Enc::new("chitala-history-constraint-v1");
        e.bytes(&self.evaluation_context_digest);
        e.str(&self.resource.to_string());
        e.str(self.capability.as_str());
        e.str(&self.rule_id);
        e.u64(self.rule_version);
        e.bytes(&self.rule_digest);
        e.u64(match self.verdict {
            HistoryVerdict::PassThrough => 0,
            HistoryVerdict::LimitExceeded => 1,
            HistoryVerdict::InsufficientHistory => 2,
        });
        for v in [self.measured_value, self.window_start_ms, self.window_end_ms, self.unknown_ms] {
            e.u64(v);
        }
        e.bytes(&self.evidence_digest);
        e.u64(self.evaluated_at_ms);
        e.u64(self.expires_at_ms);
        e.str(&self.evaluator_id.to_string());
        e.str(&self.evaluator_version);
        e.buf
    }
}

/// A record and its evaluator's Ed25519 signature over
/// [`CheckedHistoryConstraint::signing_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConstraint {
    pub constraint: CheckedHistoryConstraint,
    #[serde(with = "hex64")]
    pub sig: [u8; 64],
}

/// What the node hands Safety for an action a rule governs: the records
/// whose signatures it verified against the authorized evaluator's key, or
/// why there are none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evaluated {
    Records(Vec<CheckedHistoryConstraint>),
    Unavailable(String),
}

/// Why `SAFE-10-HISTORY` refuses (spec 32). All three are DENY; they are
/// logged apart for operations and investigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    LimitExceeded { rule_id: String, measured: u64 },
    InsufficientHistory { rule_id: String, unknown_ms: u64 },
    EvaluatorUnavailable(String),
}

impl Refusal {
    pub fn cause(&self) -> &'static str {
        match self {
            Refusal::LimitExceeded { .. } => "LIMIT_EXCEEDED",
            Refusal::InsufficientHistory { .. } => "INSUFFICIENT_HISTORY",
            Refusal::EvaluatorUnavailable(_) => "EVALUATOR_UNAVAILABLE",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::LimitExceeded { rule_id, measured } => {
                write!(f, "LIMIT_EXCEEDED: history rule {rule_id} is at its limit ({measured})")
            }
            Refusal::InsufficientHistory { rule_id, unknown_ms } => write!(
                f,
                "INSUFFICIENT_HISTORY: history rule {rule_id} cannot be shown to hold ({unknown_ms} ms unknown)"
            ),
            Refusal::EvaluatorUnavailable(why) => write!(f, "EVALUATOR_UNAVAILABLE: {why}"),
        }
    }
}

/// `SAFE-10-HISTORY` (spec 32): for an action governed by `rules`, every rule
/// needs a valid record, bound to this context and this rule's version,
/// fresh, and passing through. Anything else refuses. No rules, nothing to
/// check: history never adds an allow.
pub fn check(
    rules: &[HistoryRule],
    context_digest: &[u8; 32],
    resource: &EntityId,
    capability: &CapabilityId,
    evaluated: &Evaluated,
    now: u64,
) -> Result<(), Refusal> {
    if rules.is_empty() {
        return Ok(());
    }
    let records = match evaluated {
        Evaluated::Records(r) => r,
        Evaluated::Unavailable(why) => return Err(Refusal::EvaluatorUnavailable(why.clone())),
    };
    let mut sorted: Vec<&HistoryRule> = rules.iter().collect();
    sorted.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    for rule in sorted {
        let unavailable = |why: String| Err(Refusal::EvaluatorUnavailable(format!("rule {}: {why}", rule.rule_id)));
        let Some(c) = records.iter().find(|c| c.rule_id == rule.rule_id) else {
            return unavailable("no record".into());
        };
        if &c.evaluation_context_digest != context_digest || &c.resource != resource || &c.capability != capability {
            return unavailable("a record for another request".into());
        }
        if c.rule_version != rule.version || c.rule_digest != rule.digest() {
            return unavailable(format!("a record for version {}, not {}", c.rule_version, rule.version));
        }
        if !(c.evaluated_at_ms <= now && now < c.expires_at_ms)
            || c.expires_at_ms.saturating_sub(c.evaluated_at_ms) > MAX_CONSTRAINT_TTL_MS
        {
            return unavailable("an expired record".into());
        }
        match c.verdict {
            HistoryVerdict::PassThrough => {}
            HistoryVerdict::LimitExceeded => {
                return Err(Refusal::LimitExceeded { rule_id: rule.rule_id.clone(), measured: c.measured_value })
            }
            HistoryVerdict::InsufficientHistory => {
                return Err(Refusal::InsufficientHistory { rule_id: rule.rule_id.clone(), unknown_ms: c.unknown_ms })
            }
        }
    }
    Ok(())
}

/// A canonical, length-prefixed encoding for digests and signatures: a
/// domain separator, then each field as its kind and its length.
struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    fn new(domain: &str) -> Self {
        let mut e = Self { buf: Vec::new() };
        e.str(domain);
        e
    }

    fn bytes(&mut self, b: &[u8]) {
        self.buf.push(b'b');
        self.buf.extend((b.len() as u64).to_be_bytes());
        self.buf.extend(b);
    }

    fn str(&mut self, s: &str) {
        self.buf.push(b's');
        self.buf.extend((s.len() as u64).to_be_bytes());
        self.buf.extend(s.as_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.buf.push(b'u');
        self.buf.extend(v.to_be_bytes());
    }

    fn value(&mut self, v: &ParamValue) {
        match v {
            ParamValue::Bool(b) => {
                self.buf.push(b'?');
                self.buf.push(u8::from(*b));
            }
            ParamValue::Int(i) => {
                self.buf.push(b'i');
                self.buf.extend(i.to_be_bytes());
            }
            ParamValue::Text(t) => self.str(t),
        }
    }

    /// A payload's entries in key order (it is a sorted map).
    fn payload(&mut self, p: &Payload) {
        self.u64(p.len() as u64);
        for (k, v) in p {
            self.str(k);
            self.value(v);
        }
    }

    fn rule(&mut self, r: &HistoryRule) {
        self.str(&r.rule_id);
        self.u64(r.version);
        self.str(r.capability.as_str());
        self.str(&r.key);
        self.value(&r.value);
        let (kind, a, b) = match r.predicate {
            HistoryPredicate::MaxContinuousMs { limit_ms } => (1, limit_ms, 0),
            HistoryPredicate::MinOffBeforeMs { limit_ms } => (2, limit_ms, 0),
            HistoryPredicate::MaxEntries { limit, window_ms } => (3, limit, window_ms),
            HistoryPredicate::MaxInValueMs { limit_ms, window_ms } => (4, limit_ms, window_ms),
        };
        self.u64(kind);
        self.u64(a);
        self.u64(b);
        self.u64(r.max_unknown_ms);
    }

    fn finish(self) -> [u8; 32] {
        Sha256::digest(&self.buf).into()
    }
}

macro_rules! hex_array {
    ($name:ident, $n:expr) => {
        mod $name {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(v: &[u8; $n], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&hex::encode(v))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $n], D::Error> {
                let s = String::deserialize(d)?;
                let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                v.try_into().map_err(|_| serde::de::Error::custom(concat!("expected ", $n, " bytes")))
            }
        }
    };
}
hex_array!(hex32, 32);
hex_array!(hex64, 64);

#[cfg(test)]
mod tests;
