//! The history evaluator (spec 32): measures history rules over the
//! hash-chained log and signs a [`CheckedHistoryConstraint`] per rule.
//!
//! It is outside the Trusted Core, but a safety-relevant trusted dependency
//! for the rules it evaluates: a wrong PASS-THROUGH suppresses the denial a
//! rule was meant to add. It never produces an ALLOW: there is none to
//! produce.
//!
//! Every measure is the worst case for the rule. Unknown time is never taken
//! as the state before or after it: for a run or a time in value it counts as
//! in the value; for entries it cannot be bounded at all, so any of it is
//! INSUFFICIENT_HISTORY.

use chitala_history_check::{
    CheckedHistoryConstraint, HistoryPredicate, HistoryRule, HistoryVerdict, SignedConstraint, MAX_CONSTRAINT_TTL_MS,
};
use chitala_identity::Keypair;
use chitala_model::{CapabilityId, EntityId, ParamValue};
use serde::{Deserialize, Serialize};

use crate::log::Chained;
use crate::query::timeline;
use crate::Record;

/// What the node asks (spec 32): one action, the rules that govern it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRequest {
    #[serde(with = "hex32")]
    pub evaluation_context_digest: [u8; 32],
    pub resource: EntityId,
    /// The device whose history the rules measure: the resource's witness.
    pub device: EntityId,
    pub capability: CapabilityId,
    pub rules: Vec<HistoryRule>,
    /// The node's clock: windows end here.
    pub now_ms: u64,
}

/// A rule's worst-case measure and its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measure {
    pub verdict: HistoryVerdict,
    pub measured_value: u64,
    pub window_start_ms: u64,
    pub unknown_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    In,
    Out,
    Unknown,
}

/// The window's intervals, oldest first: their lengths and what they were.
fn intervals(records: &[Record], device: &EntityId, rule: &HistoryRule, from: u64, to: u64) -> Vec<(u64, State)> {
    timeline(records, device, &rule.key, from, to)
        .into_iter()
        .map(|s| {
            let state = match &s.value {
                None => State::Unknown,
                Some(v) if v == &rule.value => State::In,
                Some(_) => State::Out,
            };
            (s.len(), state)
        })
        .collect()
}

/// Measure `rule` over the chain's `records` for `device`, up to `now`.
pub fn measure(rule: &HistoryRule, records: &[Record], device: &EntityId, now: u64) -> Measure {
    use HistoryVerdict::*;
    let window = rule.predicate.window_ms();
    let from = now.saturating_sub(window);
    let parts = intervals(records, device, rule, from, now);
    let unknown_ms: u64 = parts.iter().filter(|(_, s)| *s == State::Unknown).map(|(l, _)| l).sum();
    let too_much_unknown = unknown_ms > rule.max_unknown_ms;
    let m = |verdict, measured_value| Measure { verdict, measured_value, window_start_ms: from, unknown_ms };
    match rule.predicate {
        HistoryPredicate::MaxContinuousMs { limit_ms } => {
            // back from now: the run in the value, or possibly in it
            let (mut worst, mut known, mut broken) = (0u64, 0u64, false);
            for (len, state) in parts.iter().rev() {
                match state {
                    State::Out => break,
                    State::In if !broken => {
                        worst += len;
                        known += len;
                    }
                    State::In => worst += len,
                    State::Unknown => {
                        worst += len;
                        broken = true;
                    }
                }
            }
            if known >= limit_ms {
                m(LimitExceeded, known)
            } else if worst >= limit_ms || too_much_unknown {
                m(InsufficientHistory, worst)
            } else {
                m(PassThrough, worst)
            }
        }
        HistoryPredicate::MinOffBeforeMs { limit_ms } => {
            // back from now: how long it has been known out of the value
            let mut off = 0u64;
            let mut before = None;
            for (len, state) in parts.iter().rev() {
                if *state == State::Out {
                    off += len;
                } else {
                    before = Some(*state);
                    break;
                }
            }
            match before {
                _ if off >= limit_ms => m(PassThrough, off),
                Some(State::Unknown) | None => m(InsufficientHistory, off),
                Some(_) => m(LimitExceeded, off),
            }
        }
        HistoryPredicate::MaxEntries { limit, .. } => {
            // entries cannot be bounded through a gap: it may hide any number
            let entries = parts.windows(2).filter(|w| w[0].1 == State::Out && w[1].1 == State::In).count() as u64;
            if unknown_ms > 0 {
                m(InsufficientHistory, entries)
            } else if entries >= limit {
                m(LimitExceeded, entries)
            } else {
                m(PassThrough, entries)
            }
        }
        HistoryPredicate::MaxInValueMs { limit_ms, .. } => {
            let in_value: u64 = parts.iter().filter(|(_, s)| *s == State::In).map(|(l, _)| l).sum();
            let worst = in_value + unknown_ms;
            if in_value >= limit_ms {
                m(LimitExceeded, in_value)
            } else if worst >= limit_ms || too_much_unknown {
                m(InsufficientHistory, worst)
            } else {
                m(PassThrough, worst)
            }
        }
    }
}

/// The evaluator: its identity, version and signing key.
pub struct Evaluator {
    pub id: EntityId,
    pub version: String,
    key: Keypair,
}

impl Evaluator {
    pub fn new(id: EntityId, version: impl Into<String>, key: Keypair) -> Self {
        Self { id, version: version.into(), key }
    }

    /// One signed record per rule. Over a broken chain, or for a rule that
    /// is not well formed, the verdict is INSUFFICIENT_HISTORY.
    pub fn evaluate(&self, req: &EvalRequest, log: &Chained) -> Vec<SignedConstraint> {
        req.rules
            .iter()
            .map(|rule| {
                let window = rule.predicate.window_ms();
                let measure = match (log.intact, rule.check()) {
                    (true, Ok(())) => measure(rule, &log.records, &req.device, req.now_ms),
                    _ => Measure {
                        verdict: HistoryVerdict::InsufficientHistory,
                        measured_value: 0,
                        window_start_ms: req.now_ms.saturating_sub(window),
                        unknown_ms: window,
                    },
                };
                let constraint = CheckedHistoryConstraint {
                    evaluation_context_digest: req.evaluation_context_digest,
                    resource: req.resource.clone(),
                    capability: req.capability.clone(),
                    rule_id: rule.rule_id.clone(),
                    rule_version: rule.version,
                    rule_digest: rule.digest(),
                    verdict: measure.verdict,
                    measured_value: measure.measured_value,
                    window_start_ms: measure.window_start_ms,
                    window_end_ms: req.now_ms,
                    unknown_ms: measure.unknown_ms,
                    evidence_digest: log.head,
                    evaluated_at_ms: req.now_ms,
                    expires_at_ms: req.now_ms + MAX_CONSTRAINT_TTL_MS,
                    evaluator_id: self.id.clone(),
                    evaluator_version: self.version.clone(),
                };
                let sig = self.key.sign(&constraint.signing_bytes());
                SignedConstraint { constraint, sig }
            })
            .collect()
    }
}

/// A value the rules compare: as a device reports it.
pub fn value_of(text: &str) -> ParamValue {
    match text {
        "true" => ParamValue::Bool(true),
        "false" => ParamValue::Bool(false),
        v => v.parse::<i64>().map(ParamValue::Int).unwrap_or_else(|_| ParamValue::Text(text.to_string())),
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)?.try_into().map_err(|_| serde::de::Error::custom("32 bytes"))
    }
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod tests;
