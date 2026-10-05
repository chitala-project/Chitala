//! Plans (spec 23): several actions, one after the other, each only once the
//! one before has verifiably taken effect.
//!
//! ```text
//! signed intent + follow-up steps ─▶ Monitor (admission, once)
//!   ─▶ precheck: every step through the Authority Engine and Safety, before anything moves
//!        (a DENY anywhere refuses the whole plan; an ESCALATE is where it will pause)
//!   ─▶ step k: judged again in full ─▶ Safety ─▶ boundary ─▶ order ─▶ outcome (spec 22)
//!        ├─ verified ─▶ step k+1
//!        ├─ needs a person ─▶ waits for an approval of this step alone ─▶ step k runs ─▶ …
//!        └─ denied, refused, failed, not verified, no answer ─▶ the plan stops
//! ```
//!
//! A plan creates no authority (Blueprint v20 §8): every step is an intent of
//! its own, derived from the signed plan ([`VerifiedIntent::plan_step`]) and
//! decided by the Authority Engine when it runs, so a revocation, a hold, a
//! recovery or a change of policy between steps applies to the next step. A
//! step that needs a person pauses the plan and asks for that step alone
//! (Project Lead decision, 2026-10-05). People can cancel a plan at any time;
//! the authority fence stops its order in flight. Plans live in memory: a
//! restart stops every plan.

use chitala_intent::{id_hex, VerifiedIntent};
use chitala_monitor::{decide_intent, Stage};
use chitala_policy::authority::Verdict;
use chitala_safety::Violation;

use super::*;

/// Running plans one actor may have at once, and the whole domain (spec 23).
pub const MAX_PLANS_PER_ACTOR: usize = 2;
pub const MAX_PLANS: usize = 64;
/// An ended plan stays this long, so its requester and the people it acts for
/// can still see how it ended; at most this many are kept.
pub const PLAN_RETENTION_MS: u64 = 60 * 60 * 1000;
pub const MAX_STORED_PLANS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanStatus {
    Running,
    /// The current step waits for a person's approval.
    WaitingApproval,
    /// Every step was verified.
    Done,
    /// A step was denied, refused, failed or not verified; nothing more runs.
    Stopped,
    /// A person cancelled it.
    Cancelled,
}

impl PlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanStatus::Running => "running",
            PlanStatus::WaitingApproval => "waiting_approval",
            PlanStatus::Done => "done",
            PlanStatus::Stopped => "stopped",
            PlanStatus::Cancelled => "cancelled",
        }
    }

    fn ended(self) -> bool {
        matches!(self, PlanStatus::Done | PlanStatus::Stopped | PlanStatus::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepStatus {
    Planned,
    Running,
    WaitingApproval,
    Done,
    Denied,
    Failed,
    Cancelled,
}

impl StepStatus {
    fn as_str(self) -> &'static str {
        match self {
            StepStatus::Planned => "planned",
            StepStatus::Running => "running",
            StepStatus::WaitingApproval => "waiting_approval",
            StepStatus::Done => "done",
            StepStatus::Denied => "denied",
            StepStatus::Failed => "failed",
            StepStatus::Cancelled => "cancelled",
        }
    }
}

struct StepState {
    mid: String,
    status: StepStatus,
    code: Option<String>,
    outcome: Option<Value>,
    audit_seq: Option<u64>,
}

/// One plan, as the node keeps it in memory.
pub(super) struct Plan {
    /// The signed plan intent every step is derived from.
    root: VerifiedIntent,
    steps: Vec<StepState>,
    current: usize,
    status: PlanStatus,
    /// The current step may start: the step before it was verified.
    ready: bool,
    reason: Option<String>,
    started_at_ms: u64,
    ended_at_ms: Option<u64>,
}

impl Plan {
    fn view(&self, id: &str) -> Value {
        let i = self.root.intent();
        let steps: Vec<Value> = self
            .steps
            .iter()
            .enumerate()
            .map(|(k, s)| {
                let step = self.root.plan_step(k).expect("k < plan_len");
                let si = step.intent();
                json!({
                    "n": k + 1,
                    "mid": s.mid,
                    "capability": si.action.to_string(),
                    "resource": si.resource.to_string(),
                    "status": s.status.as_str(),
                    "code": s.code,
                    "outcome": s.outcome,
                    "audit_seq": s.audit_seq,
                })
            })
            .collect();
        json!({
            "id": id,
            "status": self.status.as_str(),
            "actor": i.actor.to_string(),
            "on_behalf_of": i.on_behalf_of.to_string(),
            "current": self.current + 1,
            "of": self.steps.len(),
            "reason": self.reason,
            "deadline_ms": i.constraints.deadline_ms,
            "started_at_ms": self.started_at_ms,
            "ended_at_ms": self.ended_at_ms,
            "steps": steps,
        })
    }
}

impl Node {
    fn running_plans(&self, actor: Option<&EntityId>) -> usize {
        self.plans
            .values()
            .filter(|p| !p.status.ended())
            .filter(|p| actor.is_none_or(|a| &p.root.intent().actor == a))
            .count()
    }

    /// Drop plans that ended long enough ago, and the oldest ended ones beyond
    /// [`MAX_STORED_PLANS`].
    fn prune_plans(&mut self, now: u64) {
        let old = |p: &Plan| p.ended_at_ms.is_some_and(|t| now.saturating_sub(t) > PLAN_RETENTION_MS);
        let mut gone: Vec<String> = self.plans.iter().filter(|(_, p)| old(p)).map(|(k, _)| k.clone()).collect();
        let mut ended: Vec<(u64, String)> = self
            .plans
            .iter()
            .filter(|(k, p)| p.status.ended() && !gone.contains(k))
            .map(|(k, p)| (p.ended_at_ms.unwrap_or(0), k.clone()))
            .collect();
        ended.sort();
        let excess = (self.plans.len() - gone.len()).saturating_sub(MAX_STORED_PLANS);
        gone.extend(ended.into_iter().take(excess).map(|(_, k)| k));
        for id in gone {
            if let Some(p) = self.plans.remove(&id) {
                for s in &p.steps {
                    self.plan_steps.remove(&s.mid);
                }
            }
        }
    }

    /// Phase 1 for an intent that carries a plan: the plan rules, the precheck
    /// of every step, then the first step.
    pub(super) fn begin_plan(&mut self, v: VerifiedIntent, now: u64) -> Step {
        self.prune_plans(now);
        let actor = v.intent().actor.clone();
        let mine = self.running_plans(Some(&actor));
        if mine >= MAX_PLANS_PER_ACTOR || self.running_plans(None) >= MAX_PLANS {
            let why = format!("{actor} already runs {mine} plans; wait for one to end");
            let refused = (Stage::Authority, "plan");
            return Step::Done(self.intent_denied(&v, &[], None, refused, DenyCode::PlanDenied, why, vec![], now));
        }
        // nothing moves unless every step could be taken now; each step is
        // judged again, in full, when it runs
        let n = v.plan_len();
        for k in 0..n {
            let step = v.plan_step(k).expect("k < plan_len");
            let si = step.intent();
            let label = format!("plan step {} of {n} ({} on {})", k + 1, si.action, si.resource);
            let decision = {
                let dir = directory!(self);
                let world = world!(self, dir, now);
                decide_intent(&world, &step, &[])
            };
            let risk = match &decision.verdict {
                Verdict::Deny(d) => {
                    let (code, reason, policy) = (d.code, format!("{label}: {}", d.reason), d.policy_reasons.clone());
                    let at = (Stage::Authority, d.step.as_str());
                    let trace = decision.trace.clone();
                    return Step::Done(self.intent_denied(&v, &trace, decision.risk, at, code, reason, policy, now));
                }
                Verdict::Allow(g) => g.risk(),
                Verdict::Escalate(e) => e.risk,
            };
            if let Some(Err(violation)) = self.safety_dry_run(&si.id, &si.resource, &si.action, &si.params, risk, now) {
                let violation = Violation { rule: violation.rule, reason: format!("{label}: {}", violation.reason) };
                return Step::Done(self.safety_denied(&v, &decision.trace, risk, violation, now));
            }
        }
        let id = id_hex(&v.intent().id);
        let steps: Vec<StepState> = (0..n)
            .map(|k| StepState {
                mid: id_hex(&v.plan_step(k).expect("k < plan_len").intent().id),
                status: StepStatus::Planned,
                code: None,
                outcome: None,
                audit_seq: None,
            })
            .collect();
        for (k, s) in steps.iter().enumerate() {
            self.plan_steps.insert(s.mid.clone(), (id.clone(), k));
        }
        let mut f = self.intent_fields(&v);
        f.insert(
            "steps".into(),
            json!((0..n)
                .map(|k| {
                    let s = v.plan_step(k).expect("k < plan_len");
                    json!({"mid": id_hex(&s.intent().id), "capability": s.intent().action.to_string(),
                           "resource": s.intent().resource.to_string(), "digest": hex::encode(&s.digest()[..16])})
                })
                .collect::<Vec<_>>()),
        );
        let plan = Plan {
            root: v,
            steps,
            current: 0,
            status: PlanStatus::Running,
            ready: false,
            reason: None,
            started_at_ms: now,
            ended_at_ms: None,
        };
        self.plans.insert(id.clone(), plan);
        self.plan_changed_with(&id, "accepted", f, now);
        self.run_plan_step(&id, now)
    }

    /// Start the current step of a plan: the Authority Engine decides it again,
    /// in full, now.
    fn run_plan_step(&mut self, id: &str, now: u64) -> Step {
        let Some(plan) = self.plans.get_mut(id) else {
            return Step::Done(Response { decision: "deny".into(), ..Default::default() });
        };
        plan.ready = false;
        let k = plan.current;
        plan.steps[k].status = StepStatus::Running;
        let step = plan.root.plan_step(k).expect("current < plan_len");
        let decision = {
            let dir = directory!(self);
            let world = world!(self, dir, now);
            decide_intent(&world, &step, &[])
        };
        self.on_authority(step, decision, None, now)
    }

    /// A step's request ended with `r` (a decision, an escalation, an
    /// execution): move its plan on, and show the plan in the response.
    pub(super) fn plan_track(&mut self, r: &mut Response, now: u64) {
        let Some((id, k)) = r.mid.as_ref().and_then(|m| self.plan_steps.get(m)).cloned() else { return };
        let waiting =
            r.mid.as_deref().and_then(chitala_intent::parse_id_hex).is_some_and(|i| self.pending.contains_key(&i));
        // what this response means for the step: None while its outcome is pending
        let verdict = match self.plans.get_mut(&id).filter(|p| !p.status.ended() && p.current == k) {
            None => None,
            Some(plan) => {
                let s = &mut plan.steps[k];
                s.audit_seq = r.audit_seq.or(s.audit_seq);
                if r.outcome.is_some() {
                    s.outcome = r.outcome.clone();
                }
                if waiting {
                    Some(StepStatus::WaitingApproval)
                } else if r.decision == "deny" {
                    s.code = r.code.map(|c| c.as_str().to_string());
                    Some(StepStatus::Denied)
                } else if let Some(e) = &r.error {
                    s.code = Some(e.code.as_str().to_string());
                    Some(StepStatus::Failed)
                } else {
                    match r.outcome.as_ref().and_then(|o| o["status"].as_str()) {
                        Some("pending") => None,
                        Some("verified") | None => Some(StepStatus::Done),
                        Some(_) => Some(StepStatus::Failed),
                    }
                }
            }
        };
        match verdict {
            None => {}
            Some(StepStatus::WaitingApproval) => {
                // recorded once, however many answers come in before the last
                let first = self.plans.get_mut(&id).is_some_and(|plan| {
                    let first = plan.status != PlanStatus::WaitingApproval;
                    plan.steps[k].status = StepStatus::WaitingApproval;
                    plan.status = PlanStatus::WaitingApproval;
                    first
                });
                if first {
                    self.plan_changed(&id, "waiting_approval", now);
                }
            }
            Some(StepStatus::Done) => self.plan_step_done(&id, now),
            Some(failed) => {
                let why = r.reason.clone().or_else(|| r.error.as_ref().map(|e| e.message.clone()));
                let why = format!("step {}: {}", k + 1, why.unwrap_or_else(|| "it did not take effect".into()));
                self.plan_stop(&id, failed, why, now);
            }
        }
        if let Some(plan) = self.plans.get(&id) {
            let view = plan.view(&id);
            match &mut r.result {
                Some(Value::Object(m)) => {
                    m.insert("plan".into(), view);
                }
                other => *other = Some(json!({ "plan": view })),
            }
        }
    }

    /// The outcome of a plan step was settled after its response (spec 22).
    pub(super) fn plan_outcome(&mut self, mid: &str, status: OutcomeStatus, now: u64) {
        let Some((id, k)) = self.plan_steps.get(mid).cloned() else { return };
        let Some(plan) = self.plans.get_mut(&id).filter(|p| !p.status.ended() && p.current == k) else { return };
        if let Some(o) = plan.steps[k].outcome.as_mut() {
            o["status"] = json!(status.as_str());
        }
        match status {
            OutcomeStatus::Verified => self.plan_step_done(&id, now),
            other => {
                let why = format!("the outcome of step {} was {}", k + 1, other.as_str());
                self.plan_stop(&id, StepStatus::Failed, why, now);
            }
        }
    }

    /// An escalated step got no answer in time: no answer is no consent (C14).
    pub(super) fn plan_step_expired(&mut self, mid: &str, now: u64) {
        let Some((id, k)) = self.plan_steps.get(mid).cloned() else { return };
        if self.plans.get(&id).is_some_and(|p| !p.status.ended() && p.current == k) {
            let why = format!("nobody approved step {} in time", k + 1);
            self.plan_stop(&id, StepStatus::Denied, why, now);
        }
    }

    fn plan_step_done(&mut self, id: &str, now: u64) {
        let Some(plan) = self.plans.get_mut(id) else { return };
        let k = plan.current;
        plan.steps[k].status = StepStatus::Done;
        if k + 1 < plan.steps.len() {
            plan.current = k + 1;
            plan.status = PlanStatus::Running;
            plan.ready = true;
            self.plan_changed(id, "step_done", now);
        } else {
            plan.status = PlanStatus::Done;
            plan.ended_at_ms = Some(now);
            self.plan_changed(id, "done", now);
        }
    }

    /// The current step did not take effect: nothing more runs. There is no
    /// compensation; a broken promise of medium risk or more has already put its
    /// resource in recovery (spec 22).
    fn plan_stop(&mut self, id: &str, step: StepStatus, why: String, now: u64) {
        let Some(plan) = self.plans.get_mut(id) else { return };
        let k = plan.current;
        plan.steps[k].status = step;
        for s in plan.steps.iter_mut().skip(k + 1) {
            s.status = StepStatus::Cancelled;
        }
        plan.status = PlanStatus::Stopped;
        plan.ready = false;
        plan.reason = Some(why.chars().take(300).collect());
        plan.ended_at_ms = Some(now);
        self.plan_changed(id, "stopped", now);
    }

    /// Audit and announce a change of a plan.
    fn plan_changed(&mut self, id: &str, what: &str, now: u64) {
        self.plan_changed_with(id, what, Map::new(), now);
    }

    /// [`Node::plan_changed`] with more fields for the audit record (the
    /// accepted plan's intent and steps).
    fn plan_changed_with(&mut self, id: &str, what: &str, extra: Map<String, Value>, now: u64) {
        let Some(plan) = self.plans.get(id) else { return };
        let k = plan.current;
        let mut f = extra;
        f.extend(obj(json!({
            "plan": id,
            "event": what,
            "status": plan.status.as_str(),
            "step": k + 1,
            "of": plan.steps.len(),
            "step_status": plan.steps[k].status.as_str(),
            "step_mid": plan.steps[k].mid,
            "reason": plan.reason,
        })));
        if what == "accepted" {
            f.remove("step_status");
        }
        let actor = plan.root.intent().actor.clone();
        let _ = self.audit.append(now, "plan", f);
        let data = payload([
            ("plan", id.to_string()),
            ("event", what.to_string()),
            ("status", plan.status.as_str().to_string()),
            ("step", (k + 1).to_string()),
        ]);
        self.publish(EventKind::Plan, actor, data, Some(id.to_string()), now);
    }

    /// Plans whose next step may start, started: the first decision of each.
    /// The devices among them run like any other device operation (outside the
    /// node lock), then [`Node::finish`]; the server calls this every tick.
    pub fn continue_plans(&mut self) -> Vec<Step> {
        let now = self.now();
        let ready: Vec<String> =
            self.plans.iter().filter(|(_, p)| p.ready && !p.status.ended()).map(|(k, _)| k.clone()).collect();
        ready.into_iter().map(|id| self.plan_next(&id, now)).collect()
    }

    /// The next step of the plan `r` belongs to, if it may start now: a
    /// request carries its plan on as far as it can without waiting.
    pub fn continue_plan_of(&mut self, r: &Response) -> Option<Step> {
        let (id, _) = r.mid.as_ref().and_then(|m| self.plan_steps.get(m)).cloned()?;
        let ready = self.plans.get(&id).is_some_and(|p| p.ready && !p.status.ended());
        ready.then(|| {
            let now = self.now();
            self.plan_next(&id, now)
        })
    }

    fn plan_next(&mut self, id: &str, now: u64) -> Step {
        match self.run_plan_step(id, now) {
            Step::Done(mut r) => {
                self.plan_track(&mut r, now);
                Step::Done(r)
            }
            device => device,
        }
    }

    /// The plan an order is one step of, if any (for the authority fence).
    pub(super) fn plan_of_subject(&self, subject: &[u8; 16]) -> Option<String> {
        self.plan_steps.get(&hex::encode(subject)).map(|(id, _)| id.clone())
    }

    /// Plans a person cancelled (for the authority fence).
    pub(super) fn cancelled_plans(&self) -> BTreeSet<String> {
        self.plans.iter().filter(|(_, p)| p.status == PlanStatus::Cancelled).map(|(k, _)| k.clone()).collect()
    }

    /// `domain.plan_cancel`: the person a plan acts for, an owner or an admin
    /// cancels it. No further step starts; a step waiting for approval is no
    /// longer asked; an order in flight is stopped by the authority fence.
    pub(super) fn plan_cancel(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let id = match a.payload().get("plan") {
            Some(ParamValue::Text(t)) => t.to_ascii_lowercase(),
            _ => return Err(exec(ExecCode::InvalidArgument, "missing plan")),
        };
        let actor = a.actor().clone();
        let Some(plan) = self.plans.get(&id) else {
            return Err(exec(ExecCode::InvalidArgument, "no such plan"));
        };
        let privileged =
            self.identities.get(&actor).map(|p| p.roles.iter().any(|r| r == "owner" || r == "admin")).unwrap_or(false);
        if !(privileged || plan.root.intent().on_behalf_of == actor) {
            return Err(exec(
                ExecCode::NotPermitted,
                "only the person a plan acts for, an owner or an admin may cancel it",
            ));
        }
        if plan.status.ended() {
            return Ok(json!({ "plan": id, "cancelled": false, "status": plan.status.as_str() }));
        }
        let waiting: Vec<IntentId> = plan
            .steps
            .iter()
            .filter(|s| s.status == StepStatus::WaitingApproval)
            .filter_map(|s| chitala_intent::parse_id_hex(&s.mid))
            .collect();
        for w in waiting {
            self.pending.remove(&w);
        }
        let plan = self.plans.get_mut(&id).expect("present above");
        for s in plan.steps.iter_mut().filter(|s| !matches!(s.status, StepStatus::Done)) {
            s.status = StepStatus::Cancelled;
        }
        plan.status = PlanStatus::Cancelled;
        plan.ready = false;
        plan.reason = Some(format!("cancelled by {actor}"));
        plan.ended_at_ms = Some(now);
        self.refresh_authority_view();
        self.plan_changed(&id, "cancelled", now);
        Ok(json!({ "plan": id, "cancelled": true }))
    }

    /// `domain.list_plans`: owners and admins see every plan; anyone else the
    /// plans that act for them.
    pub(super) fn list_plans(&self, who: &EntityId) -> Value {
        let all =
            self.identities.get(who).map(|p| p.roles.iter().any(|r| r == "owner" || r == "admin")).unwrap_or(false);
        let list: Vec<Value> = self
            .plans
            .iter()
            .filter(|(_, p)| all || &p.root.intent().on_behalf_of == who)
            .map(|(id, p)| p.view(id))
            .collect();
        json!({ "plans": list })
    }
}
