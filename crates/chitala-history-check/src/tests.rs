use chitala_model::payload;

use super::*;

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}

fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).unwrap()
}

fn pump_rule() -> HistoryRule {
    HistoryRule {
        rule_id: "pump-continuous".into(),
        version: 1,
        capability: cap("switch.turn_on"),
        key: "on".into(),
        value: ParamValue::Bool(true),
        predicate: HistoryPredicate::MaxContinuousMs { limit_ms: 1_800_000 },
        max_unknown_ms: 60_000,
    }
}

const NOW: u64 = 1_790_000_000_000;
const SUBJECT: [u8; 16] = [7; 16];

struct Ctx {
    actor: EntityId,
    on_behalf_of: EntityId,
    resource: EntityId,
    capability: CapabilityId,
    params: Payload,
}

fn ctx() -> Ctx {
    Ctx {
        actor: id("ai:assistant"),
        on_behalf_of: id("person:alice"),
        resource: id("resource:pump"),
        capability: cap("switch.turn_on"),
        params: Payload::new(),
    }
}

impl Ctx {
    fn digest(&self, epoch: u64, rules: &[HistoryRule]) -> [u8; 32] {
        EvaluationContext {
            subject: &SUBJECT,
            actor: &self.actor,
            on_behalf_of: &self.on_behalf_of,
            resource: &self.resource,
            capability: &self.capability,
            parameters: &self.params,
            authority_epoch: epoch,
            rule_set_digest: rule_set_digest(rules),
        }
        .digest()
    }
}

fn record(rule: &HistoryRule, context: [u8; 32], verdict: HistoryVerdict) -> CheckedHistoryConstraint {
    CheckedHistoryConstraint {
        evaluation_context_digest: context,
        resource: id("resource:pump"),
        capability: rule.capability.clone(),
        rule_id: rule.rule_id.clone(),
        rule_version: rule.version,
        rule_digest: rule.digest(),
        verdict,
        measured_value: 600_000,
        window_start_ms: NOW - 1_800_000,
        window_end_ms: NOW,
        unknown_ms: 0,
        evidence_digest: [9; 32],
        evaluated_at_ms: NOW,
        expires_at_ms: NOW + 5_000,
        evaluator_id: id("service:history"),
        evaluator_version: "0.4.0".into(),
    }
}

#[test]
fn rules_are_well_formed() {
    assert!(pump_rule().check().is_ok());
    let bad = |f: &dyn Fn(&mut HistoryRule)| {
        let mut r = pump_rule();
        f(&mut r);
        r.check().is_err()
    };
    assert!(bad(&|r| r.rule_id = "Pump Rule".into()));
    assert!(bad(&|r| r.version = 0));
    assert!(bad(&|r| r.predicate = HistoryPredicate::MaxEntries { limit: 0, window_ms: 3_600_000 }));
    assert!(bad(&|r| r.predicate = HistoryPredicate::MaxInValueMs { limit_ms: 1, window_ms: MAX_WINDOW_MS + 1 }));
    assert!(bad(&|r| r.max_unknown_ms = 1_800_001), "more unknown than the window");
}

/// The digests change with every field that matters, and only with them.
#[test]
fn the_context_binds_the_request_the_epoch_and_the_rule_set() {
    let rules = [pump_rule()];
    let c = ctx();
    let base = c.digest(4, &rules);
    assert_eq!(base, c.digest(4, &rules), "deterministic");
    assert_ne!(base, c.digest(5, &rules), "another epoch");
    let mut newer = pump_rule();
    newer.version = 2;
    assert_ne!(base, c.digest(4, &[newer]), "another rule set");
    let mut other = ctx();
    other.params = payload([("x", 1i64)]);
    assert_ne!(base, other.digest(4, &rules), "other parameters");
    let mut other = ctx();
    other.actor = id("ai:other");
    assert_ne!(base, other.digest(4, &rules), "another actor");
    // a rule set is a set: order does not matter
    let mut b = pump_rule();
    b.rule_id = "pump-cooldown".into();
    assert_eq!(rule_set_digest(&[pump_rule(), b.clone()]), rule_set_digest(&[b, pump_rule()]));
}

#[test]
fn a_record_s_signing_bytes_cover_its_verdict() {
    let r = pump_rule();
    let pass = record(&r, [1; 32], HistoryVerdict::PassThrough);
    let deny = record(&r, [1; 32], HistoryVerdict::LimitExceeded);
    assert_ne!(pass.signing_bytes(), deny.signing_bytes());
    let signed = SignedConstraint { constraint: pass, sig: [3; 64] };
    let json = serde_json::to_string(&signed).unwrap();
    assert_eq!(serde_json::from_str::<SignedConstraint>(&json).unwrap(), signed);
}

/// SAFE-10: a valid, bound, fresh PASS-THROUGH passes; everything else
/// refuses, with its cause.
#[test]
fn safe_10_passes_only_a_valid_bound_fresh_pass_through() {
    let rule = pump_rule();
    let rules = [rule.clone()];
    let c = ctx();
    let digest = c.digest(4, &rules);
    let run = |records: Vec<CheckedHistoryConstraint>, now: u64| {
        check(&rules, &digest, &c.resource, &c.capability, &Evaluated::Records(records), now)
    };
    let cause = |r: Result<(), Refusal>| r.err().map(|e| e.cause());
    assert_eq!(run(vec![record(&rule, digest, HistoryVerdict::PassThrough)], NOW + 1), Ok(()));
    assert_eq!(cause(run(vec![record(&rule, digest, HistoryVerdict::LimitExceeded)], NOW)), Some("LIMIT_EXCEEDED"));
    assert_eq!(
        cause(run(vec![record(&rule, digest, HistoryVerdict::InsufficientHistory)], NOW)),
        Some("INSUFFICIENT_HISTORY")
    );
    let unavailable = Some("EVALUATOR_UNAVAILABLE");
    assert_eq!(cause(run(vec![], NOW)), unavailable, "no record");
    assert_eq!(cause(run(vec![record(&rule, [0; 32], HistoryVerdict::PassThrough)], NOW)), unavailable, "replayed");
    let mut stale = record(&rule, digest, HistoryVerdict::PassThrough);
    stale.rule_version = 0;
    assert_eq!(cause(run(vec![stale], NOW)), unavailable, "another version");
    let mut forged = record(&rule, digest, HistoryVerdict::PassThrough);
    forged.rule_digest = [0; 32];
    assert_eq!(cause(run(vec![forged], NOW)), unavailable, "another definition");
    let pass = record(&rule, digest, HistoryVerdict::PassThrough);
    assert_eq!(cause(run(vec![pass.clone()], NOW + 5_000)), unavailable, "expired");
    assert_eq!(cause(run(vec![pass.clone()], NOW - 1)), unavailable, "from the future");
    let mut long = pass.clone();
    long.expires_at_ms = NOW + 60_000;
    assert_eq!(cause(run(vec![long], NOW + 1)), unavailable, "lives too long");
    let mut elsewhere = pass;
    elsewhere.resource = id("resource:fan");
    assert_eq!(cause(run(vec![elsewhere], NOW)), unavailable, "another resource");
    let down = check(&rules, &digest, &c.resource, &c.capability, &Evaluated::Unavailable("timed out".into()), NOW);
    assert_eq!(cause(down), unavailable);
    // no rule governs the action: nothing is checked, nothing is added
    assert_eq!(check(&[], &digest, &c.resource, &c.capability, &Evaluated::Unavailable("down".into()), NOW), Ok(()));
}

/// Every rule needs its record; one refusal is enough.
#[test]
fn every_rule_needs_its_own_pass_through() {
    let a = pump_rule();
    let mut b = pump_rule();
    b.rule_id = "pump-cooldown".into();
    b.predicate = HistoryPredicate::MinOffBeforeMs { limit_ms: 300_000 };
    let rules = [a.clone(), b.clone()];
    let c = ctx();
    let digest = c.digest(1, &rules);
    let both = |vb| {
        let records = vec![record(&a, digest, HistoryVerdict::PassThrough), record(&b, digest, vb)];
        check(&rules, &digest, &c.resource, &c.capability, &Evaluated::Records(records), NOW)
    };
    assert_eq!(both(HistoryVerdict::PassThrough), Ok(()));
    assert!(
        matches!(both(HistoryVerdict::LimitExceeded), Err(Refusal::LimitExceeded { rule_id, .. }) if rule_id == "pump-cooldown")
    );
    let only_a = vec![record(&a, digest, HistoryVerdict::PassThrough)];
    let r = check(&rules, &digest, &c.resource, &c.capability, &Evaluated::Records(only_a), NOW);
    assert!(matches!(r, Err(Refusal::EvaluatorUnavailable(why)) if why.contains("pump-cooldown")));
}
