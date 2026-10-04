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
//!               recovery: SAFE-8 lets only the resource's safe state through,
//!               the node runs that safe state once (Authority::Recovery → Safety → boundary),
//!               a person ends the recovery (domain.safety_release)
//! ```
//!
//! After an indeterminate failure (the device was unreachable, the adapter
//! failed, or the receipt did not match the order) the witness is observed
//! once too, so the requester learns whether the action took effect anyway
//! (`applied`, `not_applied`, `unconfirmed`). That is information, not a
//! broken promise: it never leads to recovery.

use chitala_platform::random_array;
use chitala_policy::authority::{authorize_recovery, RecoveryRequest};

use super::*;

/// What an order promised, to be checked against the resource's witness.
#[derive(Debug, Clone)]
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
        watch: Watch,
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
        let confirmed = seen.as_ref().is_some_and(|s| reports(&watch.expected, s));
        let status = match (success, confirmed, &seen) {
            (true, true, _) => OutcomeStatus::Verified,
            (true, false, _) => OutcomeStatus::Pending,
            (false, true, _) => OutcomeStatus::Applied,
            (false, false, Some(_)) => OutcomeStatus::NotApplied,
            (false, false, None) => OutcomeStatus::Unconfirmed,
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
        self.outcomes.insert(order, p);
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
                self.settled(&order, &p, OutcomeStatus::Verified, now);
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
            let status = if p.seen.is_some() { OutcomeStatus::Diverged } else { OutcomeStatus::Unconfirmed };
            let seq = self.settled(&order, &p, status, now);
            if p.watch.recovery || p.watch.risk < RiskClass::Medium {
                continue;
            }
            let reason = format!(
                "the outcome of {} was {} (expected {})",
                p.watch.capability,
                status.as_str(),
                payload_json(&p.watch.expected)
            );
            self.enter_recovery(&p.watch.resource, &reason, now);
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
        let decision_seq = self.audit.append(now, "decision", f).ok()?.seq;
        self.twins.set_desired(&device, &target, now);
        let adapter = self.adapter_name(&device);
        match self.mint(authority, clearance, decision_seq, now, None, risk) {
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
