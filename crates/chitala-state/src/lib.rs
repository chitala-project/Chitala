//! Digital Twin store (spec `specs/10-twin-and-events.md`, Blueprint v9 §4, v15 §5).
//!
//! Each entity has a *reported* state (what the device last said, authoritative for
//! the physical world) and a *desired* state (what Chitala asked for). The two are
//! never merged blindly:
//!
//! - reported state only changes from observations, and an observation older than
//!   the current one is ignored (offline replay/reconnect must not roll state back);
//! - desired state never overwrites reported state — the difference is exposed as
//!   drift ([`TwinStore::drift`]);
//! - every reported change bumps a monotonic `version`;
//! - freshness is explicit, so stale data can be refused for high-risk decisions;
//! - a device that can no longer be observed keeps its last known state as
//!   history, but that state is no evidence any more ([`TwinStore::evidence`]).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use chitala_model::{EntityId, ParamValue, Payload};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Default age after which reported state is considered stale.
pub const DEFAULT_STALE_AFTER_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Twin {
    pub reported: Payload,
    pub desired: Payload,
    pub version: u64,
    pub reported_at_ms: Option<u64>,
    pub desired_at_ms: Option<u64>,
    /// Who produced the last observation (adapter name).
    pub source: Option<String>,
    /// Since when the device cannot be observed: set by a failed observation,
    /// cleared by the next good one. Meanwhile `reported` is only the last
    /// known state (v0.3 step ③A, finding F6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unobservable_since_ms: Option<u64>,
    /// When the state's source produced it, as far as its adapter could tell
    /// (`reported_at_ms` is when Chitala received it). A backend can answer
    /// now with a state minutes old (finding F9 of v0.3 step ③A).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Freshness {
    Fresh,
    Stale,
    Unknown,
}

/// What an observation changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateChange {
    pub version: u64,
    /// Keys whose value is new or different, with the new value.
    pub changed: Payload,
    /// Keys that disappeared from the reported state.
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwinStore {
    twins: BTreeMap<EntityId, Twin>,
    stale_after_ms: u64,
}

impl Default for TwinStore {
    fn default() -> Self {
        Self::new(DEFAULT_STALE_AFTER_MS)
    }
}

fn to_json(p: &Payload) -> Value {
    serde_json::to_value(p).unwrap_or(Value::Null)
}

impl TwinStore {
    pub fn new(stale_after_ms: u64) -> Self {
        Self { twins: BTreeMap::new(), stale_after_ms }
    }

    pub fn ensure(&mut self, id: &EntityId) -> &Twin {
        self.twins.entry(id.clone()).or_default()
    }

    pub fn get(&self, id: &EntityId) -> Option<&Twin> {
        self.twins.get(id)
    }

    pub fn ids(&self) -> impl Iterator<Item = &EntityId> {
        self.twins.keys()
    }

    /// Record what Chitala asked for (merged key by key).
    pub fn set_desired(&mut self, id: &EntityId, patch: &Payload, ts_ms: u64) {
        let twin = self.twins.entry(id.clone()).or_default();
        for (k, v) in patch {
            twin.desired.insert(k.clone(), v.clone());
        }
        twin.desired_at_ms = Some(ts_ms);
    }

    /// Apply an observation received at `ts_ms`, whose source produced it at
    /// `source_at_ms` if known. Returns `None` if nothing changed or if the
    /// observation is older than the one already applied.
    pub fn apply_reported(
        &mut self,
        id: &EntityId,
        reported: Payload,
        source: &str,
        ts_ms: u64,
        source_at_ms: Option<u64>,
    ) -> Option<StateChange> {
        let twin = self.twins.entry(id.clone()).or_default();
        if matches!(twin.reported_at_ms, Some(prev) if ts_ms < prev) {
            return None;
        }
        twin.reported_at_ms = Some(ts_ms);
        twin.source_at_ms = source_at_ms;
        twin.source = Some(source.to_string());
        if twin.unobservable_since_ms.is_some_and(|since| ts_ms >= since) {
            twin.unobservable_since_ms = None;
        }
        let changed: Payload = reported
            .iter()
            .filter(|(k, v)| twin.reported.get(*k) != Some(v))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let removed: Vec<String> = twin.reported.keys().filter(|k| !reported.contains_key(*k)).cloned().collect();
        if changed.is_empty() && removed.is_empty() {
            return None;
        }
        twin.reported = reported;
        twin.version += 1;
        Some(StateChange { version: twin.version, changed, removed })
    }

    /// An observation of the device failed: whatever it reported before is no
    /// longer known to be so. The first failure counts; the next good
    /// observation ends it.
    pub fn lost(&mut self, id: &EntityId, ts_ms: u64) {
        self.twins.entry(id.clone()).or_default().unobservable_since_ms.get_or_insert(ts_ms);
    }

    /// What the device reports now, and how old that is: the evidence Safety
    /// may rely on. `None` when nothing was ever observed, or when the device
    /// cannot be observed any more: losing observability makes the last known
    /// state history, for every adapter alike.
    pub fn evidence(&self, id: &EntityId, now_ms: u64) -> Option<(u64, &Payload)> {
        let t = self.twins.get(id)?;
        if t.unobservable_since_ms.is_some() {
            return None;
        }
        t.reported_at_ms.map(|at| (now_ms.saturating_sub(at), &t.reported))
    }

    pub fn freshness(&self, id: &EntityId, now_ms: u64) -> Freshness {
        if self.twins.get(id).is_some_and(|t| t.unobservable_since_ms.is_some()) {
            return Freshness::Unknown;
        }
        match self.twins.get(id).and_then(|t| t.reported_at_ms) {
            None => Freshness::Unknown,
            Some(at) if now_ms.saturating_sub(at) > self.stale_after_ms => Freshness::Stale,
            Some(_) => Freshness::Fresh,
        }
    }

    /// Desired values the device has not (yet) reported.
    pub fn drift(&self, id: &EntityId) -> Payload {
        let Some(t) = self.twins.get(id) else {
            return Payload::new();
        };
        t.desired.iter().filter(|(k, v)| t.reported.get(*k) != Some(v)).map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// JSON view returned by `device.read_state`.
    pub fn view(&self, id: &EntityId, now_ms: u64) -> Value {
        let Some(t) = self.twins.get(id) else {
            return json!({ "entity": id.to_string(), "freshness": Freshness::Unknown });
        };
        let mut v = json!({
            "entity": id.to_string(),
            "reported": to_json(&t.reported),
            "desired": to_json(&t.desired),
            "drift": to_json(&self.drift(id)),
            "version": t.version,
            "reported_at_ms": t.reported_at_ms,
            "freshness": self.freshness(id, now_ms),
            "source": t.source,
        });
        if let Some(since) = t.unobservable_since_ms {
            // `reported` is the last known state, not the current one
            v["unobservable_since_ms"] = json!(since);
        }
        if let Some(at) = t.source_at_ms {
            v["source_at_ms"] = json!(at);
        }
        v
    }
}

/// Convenience for adapters: a boolean/int/text payload value lookup.
pub fn get_bool(p: &Payload, k: &str) -> Option<bool> {
    p.get(k).and_then(ParamValue::as_bool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_model::payload;

    fn id() -> EntityId {
        EntityId::parse("device:light-1").unwrap()
    }

    #[test]
    fn versions_and_changes() {
        let mut s = TwinStore::default();
        let c = s.apply_reported(&id(), payload([("on", false)]), "mock", 10, None).unwrap();
        assert_eq!(c.version, 1);
        assert!(s.apply_reported(&id(), payload([("on", false)]), "mock", 11, None).is_none());
        let c = s
            .apply_reported(
                &id(),
                payload([("on", ParamValue::Bool(true)), ("brightness_pct", ParamValue::Int(40))]),
                "mock",
                12,
                None,
            )
            .unwrap();
        assert_eq!(c.version, 2);
        assert_eq!(c.changed.len(), 2);
        let c = s.apply_reported(&id(), payload([("on", true)]), "mock", 13, None).unwrap();
        assert_eq!(c.removed, vec!["brightness_pct".to_string()]);
        assert_eq!(s.get(&id()).unwrap().version, 3);
    }

    #[test]
    fn old_observations_do_not_roll_back() {
        let mut s = TwinStore::default();
        s.apply_reported(&id(), payload([("on", true)]), "mock", 100, None);
        assert!(s.apply_reported(&id(), payload([("on", false)]), "replayed", 50, None).is_none());
        assert_eq!(get_bool(&s.get(&id()).unwrap().reported, "on"), Some(true));
    }

    #[test]
    fn desired_never_overwrites_reported() {
        let mut s = TwinStore::default();
        s.apply_reported(&id(), payload([("on", false)]), "mock", 1, None);
        s.set_desired(&id(), &payload([("on", true)]), 2);
        assert_eq!(get_bool(&s.get(&id()).unwrap().reported, "on"), Some(false));
        assert_eq!(s.drift(&id()), payload([("on", true)]));
        s.apply_reported(&id(), payload([("on", true)]), "mock", 3, None);
        assert!(s.drift(&id()).is_empty());
    }

    #[test]
    fn freshness() {
        let mut s = TwinStore::new(1_000);
        assert_eq!(s.freshness(&id(), 0), Freshness::Unknown);
        s.apply_reported(&id(), payload([("on", true)]), "mock", 10_000, None);
        assert_eq!(s.freshness(&id(), 10_500), Freshness::Fresh);
        assert_eq!(s.freshness(&id(), 11_001), Freshness::Stale);
        assert_eq!(s.view(&id(), 11_001)["freshness"], "stale");
    }

    #[test]
    fn a_device_that_cannot_be_observed_keeps_its_history_but_gives_no_evidence() {
        let mut s = TwinStore::new(1_000_000);
        s.apply_reported(&id(), payload([("on", true)]), "mock", 100, None);
        assert_eq!(s.evidence(&id(), 150).map(|(age, p)| (age, p.clone())), Some((50, payload([("on", true)]))));
        s.lost(&id(), 200);
        s.lost(&id(), 300); // the first failure counts
        assert_eq!(s.evidence(&id(), 350), None);
        assert_eq!(s.freshness(&id(), 350), Freshness::Unknown);
        assert_eq!(get_bool(&s.get(&id()).unwrap().reported, "on"), Some(true), "history is kept");
        assert_eq!(s.view(&id(), 350)["unobservable_since_ms"], 200);
        // an observation from before the loss does not end it
        assert!(s.apply_reported(&id(), payload([("on", true)]), "mock", 150, None).is_none());
        assert_eq!(s.evidence(&id(), 350), None);
        // the next good one does, even when nothing changed
        assert!(s.apply_reported(&id(), payload([("on", true)]), "mock", 400, None).is_none());
        assert_eq!(s.evidence(&id(), 450).map(|(age, _)| age), Some(50));
        assert_eq!(s.freshness(&id(), 450), Freshness::Fresh);
        assert!(s.view(&id(), 450).get("unobservable_since_ms").is_none());
    }
}
