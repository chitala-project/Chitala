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
    /// The latest observation of the witness since the execution.
    seen: Option<Payload>,
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
        json!({
            "status": status.as_str(),
            "resource": self.resource.to_string(),
            "capability": self.capability.to_string(),
            "expected": payload_json(&self.expected),
            "observed": observed_json(&self.expected, observed),
            "witness": self.witness.to_string(),
            "independent": self.independent,
            "execution": if self.indeterminate { "unknown" } else { "reported" },
        })
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
        Some(Watch {
            resource: resource.clone(),
            capability: authority.def().id.clone(),
            risk,
            expected: outcome.expect(authority.params()),
            witness,
            independent,
            within_ms: outcome.within_ms,
            recovery: matches!(authority, Authority::Recovery(_)),
            indeterminate: false,
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
        witnessed: Option<Result<Payload, AdapterError>>,
        mid: &str,
        decision_seq: u64,
        now: u64,
    ) -> (Value, Option<Pending>) {
        let seen = match witnessed {
            Some(Ok(state)) => {
                let adapter = self.adapter_name(&watch.witness);
                self.observed(&watch.witness, state.clone(), &adapter, None, now);
                self.witnessed(&watch.witness, &state, now);
                Some(state)
            }
            _ => None,
        };
        watch.indeterminate = !success;
        // a command whose fate is unknown is watched like a reported success:
        // the witness may still be on its way, or a moment from reachable
        let status = match (success, seen.as_ref().is_some_and(|s| reports(&watch.expected, s))) {
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
        let pending = Pending { watch, mid: mid.to_string(), decision_seq, execution_seq: None, deadline_ms, seen };
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
    pub(super) fn reserve(&mut self, mid: &str, watch: Watch) {
        let entry = InFlight { watch, order: None, decision_seq: None, reported: false, execution_seq: None };
        self.state.inflight.insert(mid.to_string(), entry);
        self.state.epoch += 1;
        self.save_state();
    }

    /// The order of an action on record was minted: from now on it may reach
    /// the device. Persisted before the order leaves the node.
    pub(super) fn minted(&mut self, mid: &str, order: &str, decision_seq: u64) {
        if let Some(e) = self.state.inflight.get_mut(mid) {
            e.order = Some(order.to_string());
            e.decision_seq = Some(decision_seq);
            self.save_state();
        }
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
            let pending = Pending { watch, mid, decision_seq, execution_seq: e.execution_seq, deadline_ms, seen: None };
            self.outcomes.insert(order, pending);
            restored += 1;
        }
        self.save_state();
        restored
    }

    /// A fresh observation of `device`: every outcome it witnesses and now
    /// confirms is verified.
    pub(super) fn witnessed(&mut self, device: &EntityId, state: &Payload, now: u64) {
        let mut verified = Vec::new();
        for (order, p) in self.outcomes.iter_mut().filter(|(_, p)| &p.watch.witness == device) {
            p.seen = Some(state.clone());
            if reports(&p.watch.expected, state) {
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
            let status = match (p.watch.indeterminate, p.seen.is_some()) {
                (false, true) => OutcomeStatus::Diverged,
                (true, true) => OutcomeStatus::NotApplied,
                (_, false) => OutcomeStatus::Unconfirmed,
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
            self.enter_recovery(&p.watch.resource, &reason, now);
            // the safe state runs only on evidence: never a blind second command
            if !evidence {
                continue;
            }
            if let Some(device) =
                self.safe_state(&p.watch.resource, p.seen.as_ref(), seq.unwrap_or(p.decision_seq), now)
            {
                work.push(device);
            }
        }
        work
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
    fn enter_recovery(&mut self, resource: &ResourceId, reason: &str, now: u64) {
        if self.state.recovery.contains_key(resource) {
            return;
        }
        let reason: String = reason.chars().take(280).collect();
        self.safety.recover(resource.clone(), reason.clone());
        self.state.recovery.insert(resource.clone(), reason.clone());
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
        if seen.is_some_and(|s| reports(&target, s)) {
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
            self.reserve(&mid, w.clone());
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
