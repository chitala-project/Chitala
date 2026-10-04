//! Execution leases (spec 21): one authority decision, and for a high-risk
//! action one human approval of exact terms, that a bounded series of uses may
//! draw on.
//!
//! ```text
//! intent + lease request ─▶ Authority (as the action, + lease rules) ─▶ [owner approves the terms] ─▶ lease
//! intent + lease id ─▶ Monitor ─▶ lease (window, uses, match, envelope) ─▶ Authority again (lease approval)
//!                   ─▶ Safety ─▶ use counted and persisted ─▶ audit ─▶ boundary: one single-use order
//! ```

use chitala_intent::{id_hex, new_intent_id, LeaseId, VerifiedIntent};
use chitala_monitor::{decide_lease_use, Stage};
use chitala_policy::authority::{AuthorityDecision, Grant, LeaseBacking, StepRecord, Verdict};

use super::intents::trace_json;
use super::*;

/// Active leases one actor may hold at once, and the whole domain (spec 21).
pub const MAX_LEASES_PER_ACTOR: usize = 4;
pub const MAX_LEASES: usize = 256;
/// An ended lease stays this long after its expiry, so a late use learns why it
/// is refused; the state keeps at most this many leases, dropping ended ones first.
pub const LEASE_RETENTION_MS: u64 = 60 * 60 * 1000;
pub const MAX_STORED_LEASES: usize = 4 * MAX_LEASES;

/// One execution lease, as the node keeps it in the persisted domain state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// The intent that asked for it, and its digest: an approval binds to it.
    pub intent: String,
    pub intent_digest: String,
    pub actor: EntityId,
    pub on_behalf_of: EntityId,
    pub resource: ResourceId,
    pub capability: CapabilityId,
    /// Parameters every use repeats exactly.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fixed: Payload,
    /// Integer parameters a use may choose, each within `[min, max]`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub envelope: BTreeMap<String, (i64, i64)>,
    pub granted_at_ms: u64,
    pub expires_at_ms: u64,
    pub max_uses: u32,
    pub uses: u32,
    pub risk: chitala_model::RiskClass,
    /// The owners who approved the terms (high risk).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved_by: Vec<EntityId>,
    /// Revocation ids of the capability tokens it was granted on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<String>,
    /// The authority epoch it was granted in.
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<EntityId>,
}

impl Lease {
    /// Why the lease can no longer be used, if it cannot.
    fn ended(&self, now: u64) -> Option<(DenyCode, String)> {
        if let Some(by) = &self.revoked_by {
            return Some((DenyCode::LeaseRevoked, format!("the lease was revoked by {by}")));
        }
        if now >= self.expires_at_ms {
            return Some((DenyCode::LeaseExpired, "the lease has expired".into()));
        }
        if self.uses >= self.max_uses {
            return Some((DenyCode::LeaseExhausted, format!("all {} uses of the lease are spent", self.max_uses)));
        }
        None
    }

    /// A use's parameters against the lease: fixed ones repeated exactly,
    /// envelope ones inside their range, nothing else.
    fn envelope_violation(&self, params: &Payload) -> Option<String> {
        for (name, value) in params {
            match (self.envelope.get(name), self.fixed.get(name)) {
                (Some((min, max)), _) => {
                    if !matches!(value, ParamValue::Int(v) if (*min..=*max).contains(v)) {
                        return Some(format!("{name} = {value} is outside the lease's [{min}, {max}]"));
                    }
                }
                (None, Some(fixed)) if fixed == value => {}
                (None, Some(fixed)) => return Some(format!("{name} = {value}, but the lease fixed it to {fixed}")),
                (None, None) => return Some(format!("{name} is not covered by the lease")),
            }
        }
        self.fixed
            .keys()
            .find(|k| !params.contains_key(*k))
            .map(|k| format!("{k} must be repeated as the lease fixed it"))
    }

    fn view(&self, id: &str) -> Value {
        json!({
            "id": id,
            "actor": self.actor.to_string(),
            "on_behalf_of": self.on_behalf_of.to_string(),
            "resource": self.resource.to_string(),
            "capability": self.capability.to_string(),
            "fixed": redact_payload(&self.fixed),
            "envelope": self.envelope,
            "granted_at_ms": self.granted_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "max_uses": self.max_uses,
            "uses": self.uses,
            "risk": self.risk.label(),
            "approved_by": self.approved_by.iter().map(ToString::to_string).collect::<Vec<_>>(),
        })
    }
}

impl Node {
    /// Leases leave the state an hour after they expire; above
    /// [`MAX_STORED_LEASES`], ended ones leave first, oldest first.
    fn prune_leases(&mut self, now: u64) {
        self.state.leases.retain(|_, l| now < l.expires_at_ms.saturating_add(LEASE_RETENTION_MS));
        let excess = self.state.leases.len().saturating_sub(MAX_STORED_LEASES);
        if excess > 0 {
            let mut ended: Vec<(u64, String)> = self
                .state
                .leases
                .iter()
                .filter(|(_, l)| l.ended(now).is_some())
                .map(|(id, l)| (l.expires_at_ms, id.clone()))
                .collect();
            ended.sort();
            for (_, id) in ended.into_iter().take(excess) {
                self.state.leases.remove(&id);
            }
        }
    }

    fn active_leases(&self, actor: Option<&EntityId>, now: u64) -> usize {
        self.state.leases.values().filter(|l| l.ended(now).is_none() && actor.is_none_or(|a| &l.actor == a)).count()
    }

    /// The Authority Engine granted a lease request: record the lease (spec 21
    /// "Asking for a lease"). Nothing is executed.
    pub(super) fn grant_lease(&mut self, v: &VerifiedIntent, grant: Grant, trace: &[StepRecord], now: u64) -> Response {
        let refuse = |node: &mut Self, why: String| {
            node.intent_denied(
                v,
                trace,
                Some(grant.risk()),
                (Stage::Authority, "lease"),
                DenyCode::LeaseDenied,
                why,
                vec![],
                now,
            )
        };
        let Some(terms) = grant.asks_lease().cloned() else {
            return refuse(self, "not a lease request".into());
        };
        self.prune_leases(now);
        if self.active_leases(Some(grant.actor()), now) >= MAX_LEASES_PER_ACTOR {
            return refuse(self, format!("{} already holds {MAX_LEASES_PER_ACTOR} active leases", grant.actor()));
        }
        if self.active_leases(None, now) >= MAX_LEASES {
            return refuse(self, format!("the domain already holds {MAX_LEASES} active leases"));
        }
        // never longer than the tokens it stands on
        let expires_at_ms =
            grant.token_refs().iter().map(|t| t.expires_at_ms).fold(now.saturating_add(terms.duration_ms), u64::min);
        let id = hex::encode(new_intent_id(&*self.entropy));
        self.state.epoch += 1;
        let lease = Lease {
            intent: id_hex(grant.intent()),
            intent_digest: hex::encode(grant.digest()),
            actor: grant.actor().clone(),
            on_behalf_of: grant.on_behalf_of().clone(),
            resource: grant.resource().clone(),
            capability: grant.def().id.clone(),
            fixed: grant.params().clone(),
            envelope: terms.envelope.clone(),
            granted_at_ms: now,
            expires_at_ms,
            max_uses: terms.max_uses,
            uses: 0,
            risk: grant.risk(),
            approved_by: grant.approved_by().to_vec(),
            tokens: grant.tokens().to_vec(),
            epoch: self.state.epoch,
            revoked_by: None,
        };
        self.state.leases.insert(id.clone(), lease.clone());
        self.save_state();

        let mid = id_hex(grant.intent());
        let mut f = self.intent_fields(v);
        f.insert("decision".into(), json!("allow"));
        f.insert("risk".into(), json!(grant.risk().label()));
        f.insert("lease".into(), lease.view(&id));
        f.insert("tokens".into(), json!(grant.tokens()));
        f.insert("policy".into(), json!(grant.policy_reasons()));
        f.insert("trace".into(), trace_json(trace));
        // no evidence, no lease
        let seq = match self.audit.append(now, "decision", f) {
            Ok(a) => a.seq,
            Err(e) => {
                self.state.leases.remove(&id);
                self.save_state();
                return Response {
                    decision: "allow".into(),
                    mid: Some(mid),
                    error: Some(exec(ExecCode::Internal, format!("audit unavailable, lease not granted: {e}"))),
                    ..Default::default()
                };
            }
        };
        let _ = self.audit.checkpoint(now);
        let data = payload([("op", "lease_grant".to_string()), ("lease", id.clone())]);
        self.publish(EventKind::AuthorityChanged, grant.actor().clone(), data, Some(mid.clone()), now);
        Response {
            decision: "allow".into(),
            mid: Some(mid),
            result: Some(json!({ "lease": lease.view(&id) })),
            audit_seq: Some(seq),
            ..Default::default()
        }
    }

    /// One use of a lease (spec 21 "Using a lease"): the lease first, then the
    /// whole Authority chain again with the lease's approval, then Safety and
    /// the boundary like any action.
    pub(super) fn begin_lease_use(&mut self, v: VerifiedIntent, id: LeaseId, now: u64) -> Step {
        self.prune_leases(now);
        let key = hex::encode(id);
        let refuse = |node: &mut Self, code: DenyCode, why: String, trace: &[StepRecord]| {
            Step::Done(node.intent_denied(&v, trace, None, (Stage::Authority, "lease"), code, why, vec![], now))
        };
        let Some(lease) = self.state.leases.get(&key).cloned() else {
            return refuse(self, DenyCode::LeaseUnknown, format!("no lease {}", &key[..16]), &[]);
        };
        if let Some((code, why)) = lease.ended(now) {
            return refuse(self, code, why, &[]);
        }
        let i = v.intent();
        if v.chain().len() > 1
            || i.actor != lease.actor
            || i.on_behalf_of != lease.on_behalf_of
            || i.action != lease.capability
            || i.resource != lease.resource
        {
            let why = format!(
                "the lease covers {} doing {} on {} for {}, first-hand",
                lease.actor, lease.capability, lease.resource, lease.on_behalf_of
            );
            return refuse(self, DenyCode::LeaseMismatch, why, &[]);
        }
        if let Some(why) = lease.envelope_violation(&i.params) {
            return refuse(self, DenyCode::LeaseEnvelope, why, &[]);
        }
        let decision = {
            let dir = directory!(self);
            let world = world!(self, dir, now);
            decide_lease_use(&world, &v, LeaseBacking { approved_by: &lease.approved_by })
        };
        let AuthorityDecision { verdict, trace, risk } = decision;
        match verdict {
            Verdict::Allow(g) => {
                let (mut presented, mut leased) = (g.tokens().to_vec(), lease.tokens.clone());
                presented.sort();
                leased.sort();
                if presented != leased {
                    let why = "the use presents another token than the lease was granted on".to_string();
                    return refuse(self, DenyCode::LeaseMismatch, why, &trace);
                }
                self.execute_grant(&v, *g, &trace, now, Some(key))
            }
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
            Verdict::Escalate(_) => refuse(self, DenyCode::Internal, "a lease use never escalates".into(), &trace),
        }
    }

    /// Count one use before its order exists (spec 21, step 7). Returns the use
    /// number and the limit, or why the lease cannot give another.
    pub(super) fn spend_lease_use(&mut self, id: &str, now: u64) -> Result<(u32, u32), (DenyCode, String)> {
        let lease = self.state.leases.get_mut(id).ok_or((DenyCode::LeaseUnknown, "the lease is gone".to_string()))?;
        if let Some(ended) = lease.ended(now) {
            return Err(ended);
        }
        lease.uses += 1;
        let spent = (lease.uses, lease.max_uses);
        self.state.epoch += 1;
        self.save_state();
        Ok(spent)
    }

    /// `domain.lease_revoke`: an owner or an admin, the person the lease acts
    /// for, or one of its approvers ends it. An order in flight from it is
    /// stopped by the authority fence.
    pub(super) fn lease_revoke(&mut self, a: &Authorized, now: u64) -> Result<Value, ExecError> {
        let id = match a.payload().get("lease_id") {
            Some(ParamValue::Text(t)) => t.to_ascii_lowercase(),
            _ => return Err(exec(ExecCode::InvalidArgument, "missing lease_id")),
        };
        let actor = a.actor().clone();
        let Some(lease) = self.state.leases.get(&id) else {
            return Err(exec(ExecCode::InvalidArgument, "no such lease"));
        };
        let privileged =
            self.identities.get(&actor).map(|p| p.roles.iter().any(|r| r == "owner" || r == "admin")).unwrap_or(false);
        if !(privileged || lease.on_behalf_of == actor || lease.approved_by.contains(&actor)) {
            return Err(exec(
                ExecCode::NotPermitted,
                "only an owner or an admin, the person a lease acts for, or one of its approvers may end it",
            ));
        }
        if lease.revoked_by.is_some() {
            return Ok(json!({ "lease": id, "already_revoked": true }));
        }
        if let Some(l) = self.state.leases.get_mut(&id) {
            l.revoked_by = Some(actor.clone());
        }
        self.state.epoch += 1;
        self.save_state();
        self.refresh_authority_view();
        let f = json!({"op": "lease_revoke", "lease": id, "by": actor.to_string(), "epoch": self.state.epoch});
        self.audit_signed(now, "authority", obj(f));
        let data = payload([("op", "lease_revoke".to_string()), ("lease", id.clone())]);
        self.publish(EventKind::AuthorityChanged, actor, data, Some(a.message_id_hex()), now);
        Ok(json!({ "lease": id, "revoked": true }))
    }

    /// `domain.list_leases`: owners and admins see every active lease; anyone
    /// else those they use, approved, or that act for them.
    pub(super) fn list_leases(&self, who: &EntityId, now: u64) -> Value {
        let all =
            self.identities.get(who).map(|p| p.roles.iter().any(|r| r == "owner" || r == "admin")).unwrap_or(false);
        let list: Vec<Value> = self
            .state
            .leases
            .iter()
            .filter(|(_, l)| l.ended(now).is_none())
            .filter(|(_, l)| all || &l.actor == who || &l.on_behalf_of == who || l.approved_by.contains(who))
            .map(|(id, l)| l.view(id))
            .collect();
        json!({ "leases": list })
    }
}
