//! The intent path of the node (specs 15–17), the Physical Authority Slice:
//!
//! ```text
//! signed intent ─▶ Reference Monitor (admission: envelope, identity, freshness, replay, relay chain)
//!               ─▶ Authority Engine (WHO … APPROVAL) ─▶ DENY ─▶ audit + event + containment
//!               │                                    ─▶ ESCALATE ─▶ safety dry run ─▶ pending ─▶ human
//!               ▼                                                                         │
//!            ALLOW ─▶ Safety (clear) ─▶ audit ("no evidence, no action") ─▶ boundary ◀───┘ (approval:
//!                                                       │                    Authority + Safety again)
//!                                                       ▼
//!                 order minted by the Trusted Execution Boundary ─▶ adapter host ─▶ device ─▶ receipt
//! ```

use chitala_intent::{id_hex, IntentId, LeaseClause, VerifiedApproval, VerifiedIntent};
use chitala_monitor::{decide_intent, Stage};
use chitala_policy::authority::{AuthorityDecision, Escalation, Grant, StepRecord, Verdict};
use chitala_safety::Violation;

use super::*;

/// Intents one actor may have waiting for a human at once: an agent must not
/// be able to flood its owner with approval requests (approval fatigue).
pub const MAX_PENDING_PER_ACTOR: usize = 3;
/// Intents waiting for a human in the whole domain.
pub const MAX_PENDING: usize = 256;

/// An escalated intent waiting for people to answer.
pub(super) struct PendingIntent {
    intent: VerifiedIntent,
    escalation: Escalation,
    asked_at_ms: u64,
    /// Valid approvals so far (a two-key resource needs two).
    approvals: Vec<VerifiedApproval>,
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub(super) fn trace_json(trace: &[StepRecord]) -> Value {
    Value::Array(
        trace
            .iter()
            .map(|s| json!({"step": s.step.as_str(), "ok": s.passed, "detail": clip(&s.detail, 300)}))
            .collect(),
    )
}

/// What safety needs to know about the world, owned so the node can be
/// borrowed mutably while it is used.
pub(super) struct SafetyView {
    pub(super) device: EntityId,
    pub(super) device_state: SecurityState,
    pub(super) observation: Option<(u64, Payload)>,
}

impl Node {
    // ───────────────────────────── entry points ─────────────────────────────

    /// Phase 1 for a signed intent.
    pub(super) fn begin_intent(&mut self, bytes: &[u8], now: u64) -> Step {
        let admitted = {
            let dir = directory!(self);
            let world = world!(self, dir, now);
            self.monitor.admit_intent(&world, bytes)
        };
        let verified = match admitted {
            Ok(v) => v,
            Err(d) => return Step::Done(self.on_deny(*d, now)),
        };
        // one use of an execution lease is judged against its lease (spec 21)
        if let Some(LeaseClause::Use(id)) = verified.intent().lease {
            return self.begin_lease_use(verified, id, now);
        }
        // several actions, one after the other (spec 23)
        if verified.plan_len() > 0 {
            return self.begin_plan(verified, now);
        }
        let decision = {
            let dir = directory!(self);
            let world = world!(self, dir, now);
            decide_intent(&world, &verified, &[])
        };
        self.on_authority(verified, decision, None, now)
    }

    /// Phase 1 for a human's signed answer to an escalated intent.
    pub(super) fn begin_approval(&mut self, bytes: &[u8], now: u64) -> Step {
        let admitted = {
            let dir = directory!(self);
            let world = world!(self, dir, now);
            self.monitor.admit_approval(&world, bytes)
        };
        let answer = match admitted {
            Ok(a) => a,
            Err(d) => return Step::Done(self.on_deny(*d, now)),
        };
        let a = answer.approval();
        let Some(pending) = self.pending.get(&a.intent) else {
            let d = Denial {
                code: DenyCode::ApprovalInvalid,
                stage: Stage::Authority,
                reason: "no intent is waiting for this answer (unknown, expired or already answered)".into(),
                authenticated: true,
                actor: Some(a.approver.clone()),
                message_id: Some(a.intent),
                target: None,
                capability: None,
                token_id: None,
                policy_reasons: vec![],
            };
            return Step::Done(self.on_deny(d, now));
        };
        // Authority again, with every answer so far — tokens may have been
        // revoked and states changed while people were deciding.
        let decision = {
            let dir = directory!(self);
            let world = world!(self, dir, now);
            let mut answers: Vec<&VerifiedApproval> = pending.approvals.iter().collect();
            answers.push(&answer);
            decide_intent(&world, &pending.intent, &answers)
        };
        // An answer from someone who may not give it leaves the question open:
        // otherwise anyone enrolled could cancel other people's escalations.
        if decision.denial().is_some_and(|d| d.code == DenyCode::ApprovalInvalid) {
            let d = decision.denial().cloned().expect("checked");
            let denial = Denial {
                code: d.code,
                stage: Stage::Authority,
                reason: d.reason,
                authenticated: true,
                actor: Some(a.approver.clone()),
                message_id: Some(a.intent),
                target: Some(pending.escalation.resource.as_entity().clone()),
                capability: Some(pending.intent.intent().action.clone()),
                token_id: None,
                policy_reasons: vec![],
            };
            return Step::Done(self.on_deny(denial, now));
        }
        // a valid key, but not the last one: keep waiting for the others
        if let Verdict::Escalate(e) = &decision.verdict {
            let e = e.clone();
            let pending = self.pending.get_mut(&a.intent).expect("present above");
            pending.approvals.push(answer.clone());
            pending.escalation = e;
            let asked = pending.asked_at_ms;
            self.record_answer(asked, &answer, now);
            return Step::Done(self.still_waiting(&a.intent));
        }
        let pending = self.pending.remove(&a.intent).expect("present above");
        self.record_answer(pending.asked_at_ms, &answer, now);
        self.on_authority(pending.intent, decision, Some(&answer), now)
    }

    /// The answer to an approval that was valid but not the last key.
    fn still_waiting(&self, id: &IntentId) -> Response {
        let e = &self.pending[id].escalation;
        let approvers: Vec<String> = e.approvers.iter().map(ToString::to_string).collect();
        let approved: Vec<String> = e.approved_by.iter().map(ToString::to_string).collect();
        let reason = format!(
            "{} approved ({} of {}); still waiting for {}: {}",
            approved.join(" and "),
            approved.len(),
            e.quorum,
            approvers.join(" or "),
            e.reasons.join("; ")
        );
        Response {
            decision: "escalate".into(),
            mid: Some(id_hex(id)),
            stage: Some(Stage::Authority.as_str().into()),
            step: Some("approval".into()),
            reason: Some(clip(&reason, 300)),
            approvers: Some(approvers),
            deadline_ms: Some(e.deadline_ms),
            ..Default::default()
        }
    }

    pub(super) fn on_authority(
        &mut self,
        v: VerifiedIntent,
        decision: AuthorityDecision,
        answer: Option<&VerifiedApproval>,
        now: u64,
    ) -> Step {
        let AuthorityDecision { verdict, trace, risk } = decision;
        match verdict {
            Verdict::Deny(d) => Step::Done(self.intent_denied(
                &v,
                &trace,
                risk,
                (Stage::Authority, d.step.as_str()),
                d.code,
                d.reason,
                d.policy_reasons,
                now,
            )),
            Verdict::Escalate(e) if answer.is_none() => Step::Done(self.escalate(v, e, &trace, now)),
            Verdict::Escalate(_) => Step::Done(self.intent_denied(
                &v,
                &trace,
                risk,
                (Stage::Authority, "approval"),
                DenyCode::Internal,
                "still escalated after an answer".into(),
                vec![],
                now,
            )),
            // a lease request is granted as a lease, never executed (spec 21)
            Verdict::Allow(g) if g.asks_lease().is_some() => Step::Done(self.grant_lease(&v, *g, &trace, now)),
            Verdict::Allow(g) => self.execute_grant(&v, *g, &trace, now, None),
        }
    }

    // ───────────────────────────── outcomes ─────────────────────────────

    pub(super) fn intent_fields(&self, v: &VerifiedIntent) -> Map<String, Value> {
        let i = v.intent();
        let relayed: Vec<String> = v.chain().iter().skip(1).map(|c| c.actor.to_string()).collect();
        obj(json!({
            "path": "intent",
            "mid": id_hex(&i.id),
            "actor": i.actor.to_string(),
            "on_behalf_of": i.on_behalf_of.to_string(),
            "relayed_from": relayed,
            "resource": i.resource.to_string(),
            "capability": i.action.to_string(),
            "purpose": i.context.purpose.as_deref().map(|p| clip(p, 280)),
            "digest": hex::encode(&v.digest()[..16]),
            "payload": redact_payload(&i.params),
            "policy_fp": self.policy.fingerprint(),
            "epoch": self.state.epoch,
            "lease_request": match &i.lease {
                Some(LeaseClause::Request(t)) => json!({"max_uses": t.max_uses, "duration_ms": t.duration_ms, "envelope": t.envelope}),
                _ => Value::Null,
            },
            "lease_use": match &i.lease {
                Some(LeaseClause::Use(id)) => json!(hex::encode(id)),
                _ => Value::Null,
            },
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn intent_denied(
        &mut self,
        v: &VerifiedIntent,
        trace: &[StepRecord],
        risk: Option<chitala_model::RiskClass>,
        (stage, step): (Stage, &str),
        code: DenyCode,
        reason: String,
        policy: Vec<String>,
        now: u64,
    ) -> Response {
        let i = v.intent();
        let mid = id_hex(&i.id);
        let reason = clip(&reason, 300);
        let mut f = self.intent_fields(v);
        f.insert("decision".into(), json!("deny"));
        f.insert("stage".into(), json!(stage.as_str()));
        f.insert("step".into(), json!(step));
        f.insert("code".into(), json!(code.as_str()));
        f.insert("reason".into(), json!(reason));
        f.insert("risk".into(), json!(risk.map(|r| r.label())));
        f.insert("trace".into(), trace_json(trace));
        f.insert("policy".into(), json!(policy));
        let seq = self.audit.append(now, "decision", f).ok().map(|a| a.seq);

        let mut data = payload([("code", code.as_str()), ("stage", stage.as_str()), ("step", step)]);
        data.insert("capability".into(), ParamValue::Text(i.action.to_string()));
        data.insert("target".into(), ParamValue::Text(i.resource.to_string()));
        self.publish(EventKind::SecurityDenied, i.actor.clone(), data, Some(mid.clone()), now);
        if i.actor.kind() != EntityKind::Person && Containment::counts(code) {
            let actor = i.actor.clone();
            self.contain(&actor, now);
        }
        Response {
            decision: "deny".into(),
            mid: Some(mid),
            code: Some(code),
            stage: Some(stage.as_str().into()),
            step: Some(step.to_string()),
            reason: Some(reason),
            audit_seq: seq,
            ..Default::default()
        }
    }

    fn escalate(&mut self, v: VerifiedIntent, e: Escalation, trace: &[StepRecord], now: u64) -> Response {
        let i = v.intent();
        // nobody is asked to approve what safety would refuse anyway
        if let Some(Err(violation)) = self.safety_dry_run(&i.id, &i.resource, &i.action, &i.params, e.risk, now) {
            return self.safety_denied(&v, trace, e.risk, violation, now);
        }
        let actor = i.actor.clone();
        let waiting = self.pending.values().filter(|p| p.intent.intent().actor == actor).count();
        if waiting >= MAX_PENDING_PER_ACTOR || self.pending.len() >= MAX_PENDING {
            let why = format!("{actor} already has {waiting} intents waiting for a human; wait for an answer");
            return self.intent_denied(
                &v,
                trace,
                Some(e.risk),
                (Stage::Authority, "approval"),
                DenyCode::RateLimited,
                why,
                vec![],
                now,
            );
        }
        let mid = id_hex(&i.id);
        let mut f = self.intent_fields(&v);
        f.insert("decision".into(), json!("escalate"));
        f.insert("risk".into(), json!(e.risk.label()));
        f.insert("approvers".into(), json!(e.approvers.iter().map(ToString::to_string).collect::<Vec<_>>()));
        f.insert("quorum".into(), json!(e.quorum));
        f.insert("reasons".into(), json!(e.reasons));
        f.insert("deadline_ms".into(), json!(e.deadline_ms));
        f.insert("trace".into(), trace_json(trace));
        let seq = match self.audit.append(now, "decision", f) {
            Ok(x) => x.seq,
            Err(err) => {
                return Response {
                    decision: "deny".into(),
                    mid: Some(mid),
                    code: Some(DenyCode::Internal),
                    reason: Some(format!("audit unavailable, nobody was asked: {err}")),
                    ..Default::default()
                }
            }
        };
        let approvers: Vec<String> = e.approvers.iter().map(ToString::to_string).collect();
        let mut data = payload([
            ("intent", mid.clone()),
            ("resource", e.resource.to_string()),
            ("capability", i.action.to_string()),
            ("risk", e.risk.label().to_string()),
            ("approvers", approvers.join(",")),
        ]);
        data.insert("deadline_ms".into(), ParamValue::Int(e.deadline_ms.min(i64::MAX as u64) as i64));
        self.publish(EventKind::ApprovalRequested, actor, data, Some(mid.clone()), now);
        let who = if e.quorum > 1 { "two people" } else { "a human" };
        let reason = format!("waiting for {who} ({}): {}", approvers.join(" or "), e.reasons.join("; "));
        let deadline = e.deadline_ms;
        self.pending.insert(i.id, PendingIntent { intent: v, escalation: e, asked_at_ms: now, approvals: Vec::new() });
        Response {
            decision: "escalate".into(),
            mid: Some(mid),
            stage: Some(Stage::Authority.as_str().into()),
            step: Some("approval".into()),
            reason: Some(clip(&reason, 300)),
            approvers: Some(approvers),
            deadline_ms: Some(deadline),
            audit_seq: Some(seq),
            ..Default::default()
        }
    }

    pub(super) fn safety_denied(
        &mut self,
        v: &VerifiedIntent,
        trace: &[StepRecord],
        risk: chitala_model::RiskClass,
        violation: Violation,
        now: u64,
    ) -> Response {
        let rule = violation.rule.id().to_string();
        self.intent_denied(
            v,
            trace,
            Some(risk),
            (Stage::Safety, "safety"),
            DenyCode::Safety,
            violation.to_string(),
            vec![rule],
            now,
        )
    }

    /// Authority said yes: clear with safety, record the evidence, then let the
    /// boundary mint the command.
    pub(super) fn execute_grant(
        &mut self,
        v: &VerifiedIntent,
        grant: Grant,
        trace: &[StepRecord],
        now: u64,
        lease: Option<String>,
    ) -> Step {
        let Some(view) = self.safety_view(grant.resource(), grant.device(), now) else {
            let why = format!("{} is no longer governed", grant.resource());
            return Step::Done(self.intent_denied(
                v,
                trace,
                Some(grant.risk()),
                (Stage::Safety, "safety"),
                DenyCode::UnknownResource,
                why,
                vec![],
                now,
            ));
        };
        let proposed = Proposed {
            subject: grant.intent(),
            resource: grant.resource(),
            capability: grant.def(),
            params: grant.params(),
            risk: grant.risk(),
            device: grant.device(),
            device_state: view.device_state,
            observation: view.observation.as_ref().map(|(age, s)| Observation { age_ms: *age, state: s }),
            device_busy: self.device_busy(grant.device(), now),
            resource_busy: self.resource_busy(grant.resource(), now),
        };
        let clearance = match self.safety.clear(&self.resources, &proposed, now) {
            Ok(c) => c,
            Err(violation) => return Step::Done(self.safety_denied(v, trace, grant.risk(), violation, now)),
        };
        // a lease use is counted, and persisted, before its order exists: a crash
        // from here on spends it, and it is never given again (spec 21)
        let lease_use = match &lease {
            Some(id) => match self.spend_lease_use(id, now) {
                Ok((n, of)) => Some(json!({"id": id, "use": n, "of": of})),
                Err((code, why)) => {
                    return Step::Done(self.intent_denied(
                        v,
                        trace,
                        Some(grant.risk()),
                        (Stage::Authority, "lease"),
                        code,
                        why,
                        vec![],
                        now,
                    ))
                }
            },
            None => None,
        };

        let mid = id_hex(grant.intent());
        let mut f = self.intent_fields(v);
        f.insert("decision".into(), json!("allow"));
        f.insert("risk".into(), json!(grant.risk().label()));
        f.insert("device".into(), json!(grant.device().to_string()));
        f.insert("approved_by".into(), json!(grant.approved_by().iter().map(ToString::to_string).collect::<Vec<_>>()));
        f.insert("tokens".into(), json!(grant.tokens()));
        f.insert("policy".into(), json!(grant.policy_reasons()));
        f.insert("safety".into(), json!("cleared"));
        if let Some(l) = lease_use {
            f.insert("lease".into(), l);
        }
        f.insert("trace".into(), trace_json(trace));
        let authority = Authority::Intent(Box::new(grant));
        // an action that may change the world is on record before its decision
        let watch = match &authority {
            Authority::Intent(g) if authority.def().kind == CapabilityKind::Action => {
                self.watch_for(&authority, g.resource(), g.risk())
            }
            _ => None,
        };
        if let Some(w) = &watch {
            if let Err(e) = self.reserve(&mid, w.clone()) {
                return Step::Done(Response {
                    decision: "allow".into(),
                    mid: Some(mid),
                    error: Some(e),
                    ..Default::default()
                });
            }
            f.insert("epoch".into(), json!(self.state.epoch));
        }
        let fp = self.policy.fingerprint();
        let ctx = DecisionContext { domain: &self.domain, policy_fingerprint: fp, epoch: self.state.epoch };
        f.insert("context".into(), authority.context(&ctx));
        // no evidence, no action
        let decision_seq = match self.audit.append(now, "decision", f) {
            Ok(x) => x.seq,
            Err(e) => {
                self.forget(&mid);
                return Step::Done(Response {
                    decision: "allow".into(),
                    mid: Some(mid),
                    error: Some(exec(ExecCode::Internal, format!("audit unavailable, action not executed: {e}"))),
                    ..Default::default()
                });
            }
        };

        let device = authority.device().clone();
        let adapter = self.adapter_name(&device);
        let op = if authority.def().kind == CapabilityKind::Query {
            DeviceOp::Observe
        } else {
            self.twins.set_desired(&device, &expected_state(authority.def(), authority.params()), now);
            match self.mint(authority, clearance, decision_seq, now, lease, watch) {
                Ok(op) => op,
                Err(e) => {
                    self.forget(&mid);
                    return Step::Done(self.complete(&mid, decision_seq, &device, Err(e), now));
                }
            }
        };
        Step::Device(PendingDevice {
            executor: Arc::clone(&self.executor),
            device,
            adapter,
            op,
            mid,
            decision_seq,
            witnessed: None,
            clock: Arc::clone(&self.clock),
            answered_at: None,
        })
    }

    // ───────────────────────────── safety plumbing ─────────────────────────────

    pub(super) fn safety_view(&self, resource: &ResourceId, device: &EntityId, now: u64) -> Option<SafetyView> {
        let r = self.resources.get(resource)?;
        // only what the device reports now: a device that cannot be observed
        // any more gives Safety no evidence, whatever it reported before
        let observation =
            r.state.as_ref().and_then(|s| self.twins.evidence(&s.device, now)).map(|(age, state)| (age, state.clone()));
        Some(SafetyView { device: device.clone(), device_state: device_state(&self.identities, device), observation })
    }

    /// Safety without side effects, for an intent that has not been granted yet.
    pub(super) fn safety_dry_run(
        &self,
        subject: &IntentId,
        resource: &ResourceId,
        capability: &CapabilityId,
        params: &Payload,
        risk: chitala_model::RiskClass,
        now: u64,
    ) -> Option<Result<(), Violation>> {
        let def = self.registry.get(capability)?;
        let device = self.resources.get(resource)?.binding(capability)?.device.clone();
        let view = self.safety_view(resource, &device, now)?;
        let proposed = Proposed {
            subject,
            resource,
            capability: def,
            params,
            risk,
            device: &view.device,
            device_state: view.device_state,
            observation: view.observation.as_ref().map(|(age, s)| Observation { age_ms: *age, state: s }),
            // a busy device is transient: nobody is refused a question for it
            device_busy: false,
            resource_busy: false,
        };
        Some(self.safety.check(&self.resources, &proposed, now))
    }

    // ───────────────────────────── pending approvals ─────────────────────────────

    fn record_answer(&mut self, asked_at_ms: u64, answer: &VerifiedApproval, now: u64) {
        let a = answer.approval();
        let mid = id_hex(&a.intent);
        let f = obj(json!({
            "intent": mid,
            "approver": a.approver.to_string(),
            "verdict": a.verdict.as_str(),
            "note": a.note.as_deref().map(|n| clip(n, 280)),
            "waited_ms": now.saturating_sub(asked_at_ms),
        }));
        self.audit_signed(now, "approval", f);
        let data = payload([("intent", mid.clone()), ("verdict", a.verdict.as_str().to_string())]);
        self.publish(EventKind::ApprovalAnswered, a.approver.clone(), data, Some(mid), now);
    }

    /// Forget escalations whose deadline has passed; each is recorded.
    /// Close every escalation whose deadline has passed: no answer is no
    /// consent (C14). Runs before every request and on every server tick.
    pub fn expire_approvals(&mut self) {
        let now = self.now();
        self.expire_pending(now);
    }

    pub(super) fn expire_pending(&mut self, now: u64) {
        let expired: Vec<IntentId> =
            self.pending.iter().filter(|(_, p)| now >= p.escalation.deadline_ms).map(|(k, _)| *k).collect();
        for id in expired {
            let Some(p) = self.pending.remove(&id) else { continue };
            let mid = id_hex(&id);
            let f = obj(json!({"intent": mid, "verdict": "expired", "waited_ms": now.saturating_sub(p.asked_at_ms)}));
            self.audit_signed(now, "approval", f);
            let data = payload([("intent", mid.clone()), ("verdict", "expired".to_string())]);
            let node = self.node_id.clone();
            self.publish(EventKind::ApprovalAnswered, node, data, Some(mid.clone()), now);
            self.plan_step_expired(&mid, now);
        }
    }

    /// Escalations `who` may answer (`domain.list_approvals`).
    pub(super) fn list_approvals(&self, who: &EntityId) -> Value {
        let list: Vec<Value> = self
            .pending
            .values()
            .filter(|p| p.escalation.approvers.contains(who))
            .map(|p| {
                let i = p.intent.intent();
                json!({
                    "intent": id_hex(&i.id),
                    "digest": hex::encode(p.intent.digest()),
                    "actor": i.actor.to_string(),
                    "on_behalf_of": i.on_behalf_of.to_string(),
                    "relayed_from": p.intent.chain().iter().skip(1).map(|c| c.actor.to_string()).collect::<Vec<_>>(),
                    "resource": i.resource.to_string(),
                    "capability": i.action.to_string(),
                    "params": redact_payload(&i.params),
                    // a lease request: the human approves exactly these terms (spec 21)
                    "lease": match &i.lease {
                        Some(LeaseClause::Request(t)) => json!({
                            "max_uses": t.max_uses,
                            "duration_ms": t.duration_ms,
                            "envelope": t.envelope,
                        }),
                        _ => Value::Null,
                    },
                    "purpose": i.context.purpose,
                    "risk": p.escalation.risk.label(),
                    "quorum": p.escalation.quorum,
                    "approved_by": p.escalation.approved_by.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "reasons": p.escalation.reasons,
                    "requested_at_ms": i.requested_at_ms,
                    "deadline_ms": p.escalation.deadline_ms,
                })
            })
            .collect();
        json!({ "approvals": list })
    }

    /// Ids (hex) of the intents waiting for a human.
    pub fn pending_approvals(&self) -> Vec<String> {
        self.pending.keys().map(id_hex).collect()
    }
}
