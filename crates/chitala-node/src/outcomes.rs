//! Outcome verification and recovery (spec 22).
//!
//! A receipt says what the adapter host claims it did. Whether the world ended
//! up in the intended state is a separate question, answered by the resource's
//! *witness*, the device its state reference names:
//!
//! ```text
//! order ─▶ receipt (claimed) ─▶ witness observed right after ─▶ verified
//!                                        │ (not yet)
//!                                        ▼
//!                  observed again every tick until the registry's `within_ms`
//!                                        │
//!                    ├─ matches ─▶ verified
//!                    └─ deadline ─▶ diverged (observed, not as expected) | unconfirmed (no observation)
//!                                        │ medium risk or more
//!                                        ▼
//!               recovery: SAFE-8 lets only the resource's safe state through;
//!               after `diverged` (the witness was observed) the node runs that safe
//!               state once (Authority::Recovery → Safety → boundary); after
//!               `unconfirmed` it runs nothing (no blind second command);
//!               a person ends the recovery (domain.safety_release)
//! ```
//!
//! **Uncertainty survives the node.** An action that may change the world is
//! written into the persisted domain state before its decision is recorded
//! (`DomainState::inflight`), bumping the epoch so a state file rolled back
//! past it is refused. It stays there until its outcome settles. After a crash
//! the node watches every such order again: the uncertainty about the physical
//! world never vanishes with a restart, even though plans do (v0.2 RC audit).
//!
//! A command whose fate is unknown (`X_EXECUTION_UNKNOWN`: it was delivered
//! and the answer lost; or a receipt that does not match, `X_RECEIPT_INVALID`)
//! is watched the same way: `applied` once the witness reports the expected
//! state, `not_applied` if it was observed and does not by the deadline,
//! `unconfirmed` if it could not be observed — and `unconfirmed` at medium
//! risk or more enters recovery too, without a safe state (Project Lead,
//! 2026-10-05). A command that certainly did not execute (`X_DEVICE_UNAVAILABLE`,
//! `X_DEVICE_REFUSED`, `X_ADAPTER`, `X_ORDER_REJECTED`) is not watched and
//! never leads to recovery.

use chitala_model::Pose;
use chitala_platform::random_array;
use chitala_policy::authority::{authorize_recovery, RecoveryRequest};

use super::*;

/// What an order promised, to be checked against the resource's witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Watch {
    resource: ResourceId,
    capability: CapabilityId,
    risk: RiskClass,
    /// The state the action must lead to: the registry's outcome for its parameters.
    expected: Payload,
    /// The device that reports the resource's state (its state reference).
    pub(super) witness: EntityId,
    /// The witness is another device, served by another adapter host
    /// instance: a compromised host cannot vouch for its own work.
    independent: bool,
    within_ms: u64,
    /// The order is a safe state the node ran: its failure never leads to another.
    recovery: bool,
    /// The execution's fate is unknown (it may have executed): judged as
    /// applied or not, never as verified.
    indeterminate: bool,
    /// When the order could first act: set when it is minted (and persisted),
    /// then to when it is sent. Only a state its source produced at or after
    /// this is evidence of what the order did; a state read later but produced
    /// before is history (finding F9 of v0.3 step ③A). An entry recorded
    /// before this field existed has no such time: nothing is evidence for it.
    #[serde(default = "never")]
    pub(super) sent_at_ms: u64,
    /// A robot's motion (spec 30): the pose it must also end at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pose: Option<PoseWatch>,
    /// Keys whose value may be any of several (a stopped robot is at rest).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    any_of: BTreeMap<String, Vec<ParamValue>>,
}

/// The pose a motion must end at, within a tolerance, computed from the pose
/// the robot was at when the order was cleared. `end` is `None` if that pose
/// was unknown: then nothing can confirm the motion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PoseWatch {
    end: Option<Pose>,
    tolerance_mm: u64,
    tolerance_mdeg: u64,
}

fn never() -> u64 {
    u64::MAX
}

impl InFlight {
    /// Its order was minted: it may have reached its device.
    pub fn minted(&self) -> bool {
        self.order.is_some()
    }
}

/// An action that may change the world, as the persisted domain state keeps
/// it until its outcome settles (keyed by the intent or request id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InFlight {
    watch: Watch,
    /// The order, once minted. An entry without one at a restart was never sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    order: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision_seq: Option<u64>,
    /// The adapter host reported the execution; otherwise its fate is unknown.
    #[serde(default)]
    reported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    execution_seq: Option<u64>,
}

/// An outcome waiting for its witness after a reported success.
pub(super) struct Pending {
    watch: Watch,
    mid: String,
    decision_seq: u64,
    execution_seq: Option<u64>,
    deadline_ms: u64,
    /// The latest observation of the witness since the execution that is
    /// evidence of it...
    seen: Option<Payload>,
    /// ...and the answer it came in ([`Received::seq`]): a newer answer that
    /// cannot vouch for itself and states another fact takes it away (F11).
    seen_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeStatus {
    /// The witness reports the expected state.
    Verified,
    /// Not confirmed yet; the witness is observed until the deadline.
    Pending,
    /// The witness was observed after the action and does not report the expected state.
    Diverged,
    /// The witness could not be observed after the action.
    Unconfirmed,
    /// A newer action on the same resource came first; this outcome is no longer checked.
    Superseded,
    /// The execution failed indeterminately, yet the witness reports the expected state.
    Applied,
    /// The execution failed indeterminately and the witness does not report the expected state.
    NotApplied,
}

impl OutcomeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            OutcomeStatus::Verified => "verified",
            OutcomeStatus::Pending => "pending",
            OutcomeStatus::Diverged => "diverged",
            OutcomeStatus::Unconfirmed => "unconfirmed",
            OutcomeStatus::Superseded => "superseded",
            OutcomeStatus::Applied => "applied",
            OutcomeStatus::NotApplied => "not_applied",
        }
    }
}

/// Whether `observed` reports every expected value.
fn reports(expected: &Payload, observed: &Payload) -> bool {
    expected.iter().all(|(k, v)| observed.get(k) == Some(v))
}

fn payload_json(p: &Payload) -> Value {
    serde_json::to_value(p).unwrap_or(Value::Null)
}

/// The observed values of the expected keys (the rest of the state is not
/// evidence for this outcome).
fn observed_json(expected: &Payload, observed: Option<&Payload>) -> Value {
    match observed {
        None => Value::Null,
        Some(o) => payload_json(
            &o.iter().filter(|(k, _)| expected.contains_key(*k)).map(|(k, v)| (k.clone(), v.clone())).collect(),
        ),
    }
}

impl Watch {
    fn view(&self, status: OutcomeStatus, observed: Option<&Payload>) -> Value {
        let mut v = json!({
            "status": status.as_str(),
            "resource": self.resource.to_string(),
            "capability": self.capability.to_string(),
            "expected": payload_json(&self.expected),
            "observed": observed_json(&self.expected, observed),
            "witness": self.witness.to_string(),
            "independent": self.independent,
            "execution": if self.indeterminate { "unknown" } else { "reported" },
        });
        if !self.any_of.is_empty() {
            v["expected_any_of"] = json!(self.any_of);
            if let (Some(o), Value::Object(seen)) = (observed, &mut v["observed"]) {
                for k in self.any_of.keys() {
                    seen.insert(k.clone(), json!(o.get(k)));
                }
            }
        }
        if let Some(p) = &self.pose {
            v["expected_pose"] =
                json!({"pose": p.end, "tolerance_mm": p.tolerance_mm, "tolerance_mdeg": p.tolerance_mdeg});
            v["observed_pose"] = json!(observed.and_then(Pose::of));
        }
        v
    }

    /// The witness reports what the action promised: every expected value,
    /// and for a motion, a pose within the tolerance of where it must end.
    fn met(&self, observed: &Payload) -> bool {
        reports(&self.expected, observed)
            && self.any_of.iter().all(|(k, values)| observed.get(k).is_some_and(|v| values.contains(v)))
            && self.pose.as_ref().is_none_or(|p| {
                p.end.is_some_and(|end| {
                    Pose::of(observed).is_some_and(|at| end.within(&at, p.tolerance_mm, p.tolerance_mdeg))
                })
            })
    }

    /// `newer` states the fact `seen` stated, for every key the action
    /// promised, the pose included (F11).
    fn same_fact(&self, seen: &Payload, newer: &Payload) -> bool {
        same_fact(&self.expected, seen, newer)
            && self.any_of.keys().all(|k| seen.get(k) == newer.get(k))
            && (self.pose.is_none() || Pose::of(seen) == Pose::of(newer))
    }

    /// The witness answers every key the action promised, the pose included.
    fn settled(&self, seen: &Payload) -> bool {
        settled(&self.expected, seen)
            && self.any_of.keys().all(|k| seen.contains_key(k))
            && (self.pose.is_none() || Pose::of(seen).is_some())
    }
}

impl Node {
    /// What an order about to be minted promises, if its capability declares an
    /// outcome (every device action in the registry does).
    pub(super) fn watch_for(&self, authority: &Authority, resource: &ResourceId, risk: RiskClass) -> Option<Watch> {
        let outcome = authority.def().outcome.as_ref()?;
        let witness = self.resources.get(resource)?.state.as_ref()?.device.clone();
        let actuator = authority.device();
        // another adapter host instance: one that a compromised actuator host does not control
        let session = |d: &EntityId| self.executor.session(d).map(|s| s.executor);
        let independent = &witness != actuator && session(&witness).is_some_and(|w| Some(w) != session(actuator));
        // a motion ends where it takes the robot from where it is now, and
        // takes its own time on top of the outcome's (spec 30)
        let (pose, motion_ms) = match &outcome.pose {
            None => (None, 0),
            Some(o) => {
                let start = self.twins.get(&witness).and_then(|t| Pose::of(&t.reported));
                let planned = start.and_then(|s| o.motion.plan(authority.params(), s));
                let end = planned.map(|(end, _)| end);
                let watch = PoseWatch { end, tolerance_mm: o.tolerance_mm, tolerance_mdeg: o.tolerance_mdeg };
                (Some(watch), planned.map_or(0, |(_, ms)| ms))
            }
        };
        Some(Watch {
            resource: resource.clone(),
            capability: authority.def().id.clone(),
            risk,
            expected: outcome.expect(authority.params()),
            witness,
            independent,
            within_ms: outcome.within_ms.saturating_add(motion_ms),
            recovery: matches!(authority, Authority::Recovery(_)),
            indeterminate: false,
            sent_at_ms: never(),
            pose,
            any_of: outcome.any_of.clone(),
        })
    }

    /// A new order on `resource` makes the outcome still pending there moot:
    /// its witness will report the newer action.
    pub(super) fn supersede(&mut self, resource: &ResourceId, now: u64) {
        let moot: Vec<String> =
            self.outcomes.iter().filter(|(_, p)| &p.watch.resource == resource).map(|(k, _)| k.clone()).collect();
        for order in moot {
            if let Some(p) = self.outcomes.remove(&order) {
                self.record_outcome(&order, &p, OutcomeStatus::Superseded, now);
                self.forget(&p.mid);
                self.plan_outcome(&p.mid, OutcomeStatus::Superseded, now);
            }
        }
    }

    /// Phase 3, for an order that may have executed: fold the witness's
    /// observation into the twin and judge the outcome. A reported success
    /// that the witness does not confirm yet is left pending, returned for the
    /// caller to keep once the execution record exists.
    pub(super) fn judge(
        &mut self,
        mut watch: Watch,
        success: bool,
        witnessed: Option<(Result<Observed, AdapterError>, Received)>,
        mid: &str,
        decision_seq: u64,
        now: u64,
    ) -> (Value, Option<Pending>) {
        let (seen, seen_seq) = match witnessed {
            Some((Ok(o), received)) => {
                let adapter = self.adapter_name(&watch.witness);
                let origin = origin(received.at_ms, o.age_ms, o.provenance);
                // a later answer about the witness came first: this one is history
                if !self.observed(&watch.witness, o.state.clone(), &adapter, None, origin, received) {
                    (None, 0)
                } else {
                    let at = evidence_at(&origin);
                    self.witnessed(&watch.witness, &o.state, at, received.seq, now);
                    // evidence of this order only if its source produced it after
                    // the order left, and it was confirmed current since
                    (after(at, watch.sent_at_ms).then_some(o.state), received.seq)
                }
            }
            Some((Err(_), received)) => {
                self.unobservable(&watch.witness, received);
                (None, 0)
            }
            None => (None, 0),
        };
        watch.indeterminate = !success;
        // a command whose fate is unknown is watched like a reported success:
        // the witness may still be on its way, or a moment from reachable
        let status = match (success, seen.as_ref().is_some_and(|s| watch.met(s))) {
            (true, true) => OutcomeStatus::Verified,
            (false, true) => OutcomeStatus::Applied,
            _ => OutcomeStatus::Pending,
        };
        let mut view = watch.view(status, seen.as_ref());
        if status != OutcomeStatus::Pending {
            return (view, None);
        }
        let deadline_ms = now + watch.within_ms;
        view["deadline_ms"] = json!(deadline_ms);
        let pending =
            Pending { watch, mid: mid.to_string(), decision_seq, execution_seq: None, deadline_ms, seen, seen_seq };
        (view, Some(pending))
    }

    /// Keep a pending outcome until its witness confirms it or its deadline passes.
    pub(super) fn keep_pending(&mut self, order: String, mut p: Pending, execution_seq: Option<u64>) {
        p.execution_seq = execution_seq;
        if let Some(e) = self.state.inflight.get_mut(&p.mid) {
            e.reported = !p.watch.indeterminate;
            e.execution_seq = execution_seq;
            self.save_state();
        }
        self.outcomes.insert(order, p);
    }

    /// Put an action that may change the world on record before its decision:
    /// persisted, with an epoch bump so a state file rolled back past it is
    /// refused at start-up.
    /// If the record cannot be made durable, the action does not happen.
    pub(super) fn reserve(&mut self, mid: &str, watch: Watch) -> Result<(), ExecError> {
        let entry = InFlight { watch, order: None, decision_seq: None, reported: false, execution_seq: None };
        self.state.inflight.insert(mid.to_string(), entry);
        self.state.epoch += 1;
        self.persist().map_err(|e| {
            self.state.inflight.remove(mid);
            self.state.epoch -= 1;
            exec(ExecCode::Internal, format!("the action could not be put on record ({e}); not executed"))
        })
    }

    /// The order of an action on record was minted: from now on it may reach
    /// the device. Persisted before the order leaves the node.
    /// If that cannot be made durable, the order must not leave.
    pub(super) fn minted(&mut self, mid: &str, order: &str, decision_seq: u64, now: u64) -> Result<(), ExecError> {
        let Some(e) = self.state.inflight.get_mut(mid) else { return Ok(()) };
        e.order = Some(order.to_string());
        e.decision_seq = Some(decision_seq);
        e.watch.sent_at_ms = now;
        self.persist().map_err(|e| {
            if let Some(entry) = self.state.inflight.get_mut(mid) {
                entry.order = None;
            }
            exec(ExecCode::Internal, format!("the order could not be put on record ({e}); not sent"))
        })
    }

    /// The action's outcome is settled, or it certainly did not execute.
    pub(super) fn forget(&mut self, mid: &str) {
        if self.state.inflight.remove(mid).is_some() {
            self.save_state();
        }
    }

    /// After a restart: watch again every order that may have reached its
    /// device, with a fresh deadline (the node's clock moved on). An entry
    /// whose order was never minted was never sent. Returns how many.
    pub(super) fn restore_inflight(&mut self, now: u64) -> usize {
        let entries: Vec<(String, InFlight)> =
            self.state.inflight.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut restored = 0;
        for (mid, e) in entries {
            let (Some(order), Some(decision_seq)) = (e.order.clone(), e.decision_seq) else {
                self.state.inflight.remove(&mid);
                continue;
            };
            let mut watch = e.watch;
            // a crash before the adapter's answer leaves the fate unknown
            watch.indeterminate = !e.reported;
            let deadline_ms = now + watch.within_ms;
            let pending = Pending {
                watch,
                mid,
                decision_seq,
                execution_seq: e.execution_seq,
                deadline_ms,
                seen: None,
                seen_seq: 0,
            };
            self.outcomes.insert(order, pending);
            restored += 1;
        }
        self.save_state();
        restored
    }

    /// An observation of `device`, the answer `seq`, that is evidence from
    /// `at` ([`evidence_at`]): every outcome it witnesses and now confirms is
    /// verified. A state its source produced before an order is no evidence of
    /// what that order did, however late it was read (finding F9), and neither
    /// is one its adapter could not confirm current (F9b): it is left out, and
    /// an outcome with no evidence by its deadline is `unconfirmed`, never
    /// `not_applied`.
    ///
    /// Evidence belongs to the answer that gave it (F11). A newer answer that
    /// is no evidence itself, and no longer states the same fact (another
    /// value for a key the action promised), takes the older evidence away:
    /// the witness may have moved since, and nobody can confirm where to.
    pub(super) fn witnessed(&mut self, device: &EntityId, state: &Payload, at: Option<u64>, seq: u64, now: u64) {
        let mut verified = Vec::new();
        for (order, p) in self.outcomes.iter_mut().filter(|(_, p)| &p.watch.witness == device) {
            if !after(at, p.watch.sent_at_ms) {
                if p.seen.as_ref().is_some_and(|seen| p.seen_seq < seq && !p.watch.same_fact(seen, state)) {
                    p.seen = None;
                }
                continue;
            }
            p.seen = Some(state.clone());
            p.seen_seq = seq;
            if p.watch.met(state) {
                verified.push(order.clone());
            }
        }
        for order in verified {
            if let Some(p) = self.outcomes.remove(&order) {
                let status = if p.watch.indeterminate { OutcomeStatus::Applied } else { OutcomeStatus::Verified };
                self.settled(&order, &p, status, now);
            }
        }
    }

    /// Witnesses of pending outcomes: observed on every tick.
    pub(super) fn pending_witnesses(&self) -> BTreeSet<EntityId> {
        self.outcomes.values().map(|p| p.watch.witness.clone()).collect()
    }

    /// Outcomes still waiting for their witness (order id → resource).
    pub fn pending_outcomes(&self) -> Vec<(String, ResourceId)> {
        self.outcomes.iter().map(|(k, p)| (k.clone(), p.watch.resource.clone())).collect()
    }

    /// Settle every outcome whose deadline has passed: diverged if the witness
    /// was observed and does not report the expected state, unconfirmed if it
    /// could not be observed. A broken promise of medium risk or more puts the
    /// resource in recovery, and the node may bring it to its safe state: the
    /// orders returned are those safe states, to run like any other device
    /// operation (outside the node lock) and then [`Node::finish`].
    pub fn settle_outcomes(&mut self) -> Vec<PendingDevice> {
        let now = self.now();
        let due: Vec<String> =
            self.outcomes.iter().filter(|(_, p)| now >= p.deadline_ms).map(|(k, _)| k.clone()).collect();
        let mut work = Vec::new();
        for order in due {
            let Some(p) = self.outcomes.remove(&order) else { continue };
            let status = match (p.watch.indeterminate, p.seen.as_ref()) {
                (false, Some(_)) => OutcomeStatus::Diverged,
                // "it did not take effect" needs a settled answer: the keys the
                // action promised, with other values. A device in motion or at
                // fault (or Home Assistant's own optimistic `unlocking`) is not
                // known to be unchanged (F9)
                (true, Some(seen)) if p.watch.settled(seen) => OutcomeStatus::NotApplied,
                _ => OutcomeStatus::Unconfirmed,
            };
            let seq = self.settled(&order, &p, status, now);
            // a command known not to have taken effect leaves a known state;
            // a broken promise, or a state nobody can establish, stops the resource
            if p.watch.recovery || p.watch.risk < RiskClass::Medium || status == OutcomeStatus::NotApplied {
                continue;
            }
            let evidence = status == OutcomeStatus::Diverged;
            let reason = format!(
                "the outcome of {} was {} (expected {}){}",
                p.watch.capability,
                status.as_str(),
                payload_json(&p.watch.expected),
                if evidence {
                    ""
                } else {
                    "; it may have executed and the resource could not be observed: no safe state runs \
                     without an observation, a person must observe and release it"
                }
            );
            let trigger = seq.unwrap_or(p.decision_seq);
            self.enter_recovery(&p.watch.resource, &reason, trigger, p.watch.sent_at_ms.min(now), now);
            // a promise broken on evidence: the safe state runs once now, as
            // the outcome showed it is needed (spec 22)
            if evidence {
                if let Some(attempt) = self.safe_state(&p.watch.resource, p.seen.as_ref(), trigger, now) {
                    let entry = self.attempts_of(&p.watch.resource);
                    entry.count += 1;
                    entry.since_ms = now;
                    self.save_state();
                    work.push(attempt);
                }
            }
        }
        // later attempts: on new evidence of danger only, when it comes
        work.extend(self.attempt_safe_states(now));
        work
    }

    /// SAFE-8 (spec 22): bring each resource in recovery to its declared safe
    /// state, on new evidence. The first attempt follows a promise broken on
    /// evidence; after it, or after a promise nobody could confirm, one
    /// attempt per confirmed unsafe observation:
    ///
    /// - only a state its witness's adapter confirmed current, produced after
    ///   the broken order (or the last attempt) was sent: nothing blind, and
    ///   no order ever sent twice: each attempt is a new order, decided anew;
    /// - only on evidence of danger: the witness states the keys the safe
    ///   state promises, with other values. Nothing while it is safe already
    ///   or its state is unknown, or an attempt is on its way or awaits its
    ///   outcome;
    /// - the same observation triggers one attempt at most, and an episode
    ///   [`MAX_SAFE_STATE_ATTEMPTS`]: then only a person acts.
    fn attempt_safe_states(&mut self, now: u64) -> Vec<PendingDevice> {
        let mut work = Vec::new();
        let recovering: Vec<ResourceId> = self.state.recovery.keys().cloned().collect();
        for resource in recovering {
            let Some(r) = self.resources.get(&resource) else { continue };
            let (Some(safe), Some(witness)) = (r.safe_state.clone(), r.state.as_ref().map(|s| s.device.clone())) else {
                continue;
            };
            if self.outcomes.values().any(|p| p.watch.resource == resource) || self.resource_busy(&resource, now) {
                continue;
            }
            let Some((produced, state)) = self.fresh_evidence(&witness) else { continue };
            let a = self.state.safe_state_attempts.entry(resource.clone()).or_default().clone();
            if produced < a.since_ms || a.last_evidence_ms.is_some_and(|last| produced <= last) {
                continue;
            }
            // evidence of danger: the witness states the keys the safe state
            // promises, with other values. Safe already, or unknown (a jam, a
            // lost localisation), is no reason to act
            let Some(promise) = self.registry.get(&safe.capability).and_then(|d| d.outcome.clone()) else { continue };
            if !promise.stated(&safe.params, &state) || promise.reported(&safe.params, &state) {
                continue;
            }
            if a.count >= MAX_SAFE_STATE_ATTEMPTS {
                if !a.exhausted {
                    let why = format!(
                        "{} attempts made in this recovery and the resource is still not safe: a person must act",
                        a.count
                    );
                    let mid = hex::encode(random_array::<16>(self.entropy.as_ref()));
                    self.safe_state_refused(&mid, &resource, &safe.capability, "attempts", why, None, a.trigger, now);
                    self.attempts_of(&resource).exhausted = true;
                    self.save_state();
                }
                continue;
            }
            let attempt = self.safe_state(&resource, Some(&state), a.trigger, now);
            // this observation is used, whatever came of it
            let entry = self.attempts_of(&resource);
            entry.last_evidence_ms = Some(produced);
            if attempt.is_some() {
                entry.count += 1;
                entry.since_ms = now;
            }
            self.save_state();
            work.extend(attempt);
        }
        work
    }

    fn attempts_of(&mut self, resource: &ResourceId) -> &mut SafeStateAttempts {
        self.state.safe_state_attempts.entry(resource.clone()).or_default()
    }

    /// The device's state now, if its adapter confirmed it current, and when
    /// its source produced it (F9, F9b): what a safe state may act on.
    fn fresh_evidence(&self, device: &EntityId) -> Option<(u64, Payload)> {
        let t = self.twins.get(device)?;
        if t.unobservable_since_ms.is_some() {
            return None;
        }
        let produced = t.source_at_ms?;
        t.confirmed_at_ms.filter(|confirmed| *confirmed >= produced)?;
        Some((produced, t.reported.clone()))
    }

    /// Record a settled outcome and announce it (the requester has its
    /// response already). Returns the audit sequence of the record.
    fn settled(&mut self, order: &str, p: &Pending, status: OutcomeStatus, now: u64) -> Option<u64> {
        let seq = self.record_outcome(order, p, status, now);
        self.forget(&p.mid);
        let mut data = payload([
            ("status", status.as_str().to_string()),
            ("resource", p.watch.resource.to_string()),
            ("capability", p.watch.capability.to_string()),
            ("order", order.to_string()),
        ]);
        data.insert("independent".into(), p.watch.independent.into());
        self.publish(EventKind::Outcome, p.watch.witness.clone(), data, Some(p.mid.clone()), now);
        // a plan goes on only after a verified step (spec 23)
        self.plan_outcome(&p.mid, status, now);
        seq
    }

    fn record_outcome(&mut self, order: &str, p: &Pending, status: OutcomeStatus, now: u64) -> Option<u64> {
        let mut f = obj(p.watch.view(status, p.seen.as_ref()));
        f.insert("order".into(), json!(order));
        f.insert("mid".into(), json!(p.mid));
        f.insert("decision_seq".into(), json!(p.decision_seq));
        f.insert("execution_seq".into(), json!(p.execution_seq));
        f.insert("safe_state".into(), json!(p.watch.recovery));
        self.audit.append(now, "outcome", f).ok().map(|a| a.seq)
    }

    /// Put a resource in recovery: persisted (a restart does not end it), the
    /// epoch bumped (a state file rolled back past it is refused), orders in
    /// flight there stopped unless they are its safe state.
    fn enter_recovery(&mut self, resource: &ResourceId, reason: &str, trigger: u64, since_ms: u64, now: u64) {
        if self.state.recovery.contains_key(resource) {
            return;
        }
        let reason: String = reason.chars().take(280).collect();
        self.safety.recover(resource.clone(), reason.clone());
        self.state.recovery.insert(resource.clone(), reason.clone());
        let attempts = SafeStateAttempts { trigger, since_ms, ..Default::default() };
        self.state.safe_state_attempts.insert(resource.clone(), attempts);
        self.state.epoch += 1;
        self.save_state();
        self.refresh_authority_view();
        let by = self.node_id.clone();
        self.safety_changed("recovery", resource, Some(&reason), &by, now);
    }

    /// Bring a resource in recovery to its declared safe state, once: the
    /// Authority Engine grants it, Safety clears it, the boundary mints it.
    /// Nothing is run when no safe state is declared, or when the witness
    /// already reports it.
    fn safe_state(
        &mut self,
        resource: &ResourceId,
        seen: Option<&Payload>,
        trigger: u64,
        now: u64,
    ) -> Option<PendingDevice> {
        let safe = self.resources.get(resource)?.safe_state.clone()?;
        let def = self.registry.get(&safe.capability)?.clone();
        let target = def.outcome.as_ref().map(|o| o.expect(&safe.params)).unwrap_or_default();
        if seen.is_some_and(|s| def.outcome.as_ref().is_some_and(|o| o.reported(&safe.params, s))) {
            return None;
        }
        let subject: [u8; 16] = random_array(self.entropy.as_ref());
        let mid = hex::encode(subject);
        let node = self.node_id.clone();
        let req = RecoveryRequest {
            graph: &self.resources,
            registry: &self.registry,
            resource,
            actor: &node,
            subject,
            trigger,
            now_ms: now,
        };
        let grant = match authorize_recovery(req) {
            Ok(g) => g,
            Err(why) => {
                self.safe_state_refused(&mid, resource, &safe.capability, "authority", why, None, trigger, now);
                return None;
            }
        };
        let Some(view) = self.safety_view(resource, grant.device(), now) else {
            let why = format!("{resource} is no longer governed");
            self.safe_state_refused(&mid, resource, &safe.capability, "safety", why, None, trigger, now);
            return None;
        };
        let proposed = Proposed {
            subject: &subject,
            resource,
            capability: grant.def(),
            params: grant.params(),
            risk: grant.risk(),
            device: grant.device(),
            device_state: view.device_state,
            observation: view.observation.as_ref().map(|(age, st)| Observation { age_ms: *age, state: st }),
            device_busy: self.device_busy(grant.device(), now),
            resource_busy: self.resource_busy(resource, now),
        };
        let clearance = match self.safety.clear(&self.resources, &proposed, now) {
            Ok(c) => c,
            Err(v) => {
                let rule = v.rule.id().to_string();
                self.safe_state_refused(
                    &mid,
                    resource,
                    &safe.capability,
                    "safety",
                    v.to_string(),
                    Some(rule),
                    trigger,
                    now,
                );
                return None;
            }
        };
        let (device, risk) = (grant.device().clone(), grant.risk());
        let authority = Authority::Recovery(Box::new(grant));
        // on record before its decision, like every action that may change the world
        let watch = self.watch_for(&authority, resource, risk);
        if let Some(w) = &watch {
            if let Err(e) = self.reserve(&mid, w.clone()) {
                let why = e.message;
                self.safe_state_refused(&mid, resource, &safe.capability, "record", why, None, trigger, now);
                return None;
            }
        }
        let fp = self.policy.fingerprint();
        let ctx = DecisionContext { domain: &self.domain, policy_fingerprint: fp, epoch: self.state.epoch };
        let f = obj(json!({
            "decision": "allow",
            "safe_state": true,
            "mid": mid,
            "actor": node.to_string(),
            "resource": resource.to_string(),
            "capability": safe.capability.to_string(),
            "device": device.to_string(),
            "risk": risk.label(),
            "payload": redact_payload(&safe.params),
            "trigger": trigger,
            "safety": "cleared",
            "policy_fp": fp,
            "epoch": self.state.epoch,
            "context": authority.context(&ctx),
        }));
        // no evidence, no action
        let Ok(appended) = self.audit.append(now, "decision", f) else {
            self.forget(&mid);
            return None;
        };
        let decision_seq = appended.seq;
        self.twins.set_desired(&device, &target, now);
        let adapter = self.adapter_name(&device);
        match self.mint(authority, clearance, decision_seq, now, None, watch) {
            Ok(op) => Some(PendingDevice {
                executor: Arc::clone(&self.executor),
                device,
                adapter,
                op,
                mid,
                decision_seq,
                witnessed: None,
                arrivals: self.arrivals.clone(),
                answered: None,
            }),
            Err(e) => {
                self.forget(&mid);
                self.complete(&mid, decision_seq, &device, Err(e), now);
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn safe_state_refused(
        &mut self,
        mid: &str,
        resource: &ResourceId,
        capability: &CapabilityId,
        stage: &str,
        why: String,
        rule: Option<String>,
        trigger: u64,
        now: u64,
    ) {
        let reason: String = why.chars().take(300).collect();
        let f = obj(json!({
            "decision": "deny",
            "safe_state": true,
            "mid": mid,
            "actor": self.node_id.to_string(),
            "resource": resource.to_string(),
            "capability": capability.to_string(),
            "stage": stage,
            "reason": reason,
            "safety": rule.into_iter().collect::<Vec<_>>(),
            "trigger": trigger,
            "policy_fp": self.policy.fingerprint(),
            "epoch": self.state.epoch,
        }));
        let _ = self.audit.append(now, "decision", f);
    }

    /// Observe what is due, settle what has run out of time and run the safe
    /// states that follows, all in this thread. The IPC server does the same
    /// without holding the node lock while a device answers
    /// (`ipc::refresh_state`); tests and in-process nodes call this.
    pub fn tick(&mut self) {
        let now = self.now();
        // no answer is no consent (C14): an unanswered plan step stops its plan
        self.expire_pending(now);
        for o in self.due_observations(now) {
            let r = o.run();
            self.observed_by(&o, r);
        }
        for mut p in self.settle_outcomes() {
            let r = p.run();
            self.finish(p, r);
        }
        // plans whose step was just verified go on (spec 23), each as far as it can
        for mut step in self.continue_plans() {
            loop {
                let r = match step {
                    Step::Done(r) => r,
                    Step::Device(mut p) => {
                        let o = p.run();
                        self.finish(p, o)
                    }
                };
                match self.continue_plan_of(&r) {
                    Some(next) => step = next,
                    None => break,
                }
            }
        }
    }
}

/// When an observation can vouch for the world: when its source produced the
/// state, provided its adapter confirmed it current no earlier than that
/// (finding F9b). A gateway's timestamp alone is not physical freshness: Home
/// Assistant re-emits a dead device's cached value with a new one. `None`: the
/// observation is history, evidence of nothing.
pub(super) fn evidence_at(origin: &Origin) -> Option<u64> {
    let produced = origin.produced_at_ms?;
    origin.confirmed_at_ms.filter(|confirmed| *confirmed >= produced).map(|_| produced)
}

/// A state produced at `source_at` tells what an order sent at `sent_at` did
/// only if it was produced at or after it. An unknown source time tells
/// nothing.
fn after(source_at: Option<u64>, sent_at: u64) -> bool {
    source_at.is_some_and(|at| at >= sent_at)
}

/// `newer` states the fact `seen` stated: the same value (or the same
/// absence) for every key the action promised (F11). Keys outside the promise
/// do not matter.
pub(super) fn same_fact(expected: &Payload, seen: &Payload, newer: &Payload) -> bool {
    expected.keys().all(|k| seen.get(k) == newer.get(k))
}

/// The witness answers every key the action promised: its state is settled,
/// not in motion or at fault.
fn settled(expected: &Payload, seen: &Payload) -> bool {
    expected.keys().all(|k| seen.contains_key(k))
}
