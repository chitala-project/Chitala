use chitala_history_check::HistoryVerdict::{InsufficientHistory, LimitExceeded, PassThrough};
use chitala_identity::{test_seed, verify};
use chitala_model::payload;

use super::*;

const MIN: u64 = 60_000;
const NOW: u64 = 1_000 * MIN;

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}

fn pump() -> EntityId {
    id("device:pump")
}

fn rule(predicate: HistoryPredicate, max_unknown_ms: u64) -> HistoryRule {
    HistoryRule {
        rule_id: "pump".into(),
        version: 1,
        capability: CapabilityId::parse("switch.turn_on").unwrap(),
        key: "on".into(),
        value: ParamValue::Bool(true),
        predicate,
        max_unknown_ms,
    }
}

/// A history from `(minutes before now, state)`: `Some(on)`, or `None` for
/// the pump going unobservable.
fn history(events: &[(u64, Option<bool>)]) -> Vec<Record> {
    events
        .iter()
        .map(|(ago, on)| {
            let at = NOW - ago * MIN;
            match on {
                Some(v) => Record::Observed { device: pump(), at, observed_at: at, state: payload([("on", *v)]) },
                None => Record::Unobservable { device: pump(), at },
            }
        })
        .collect()
}

fn verdict(r: &HistoryRule, events: &[(u64, Option<bool>)]) -> (HistoryVerdict, u64) {
    let m = measure(r, &history(events), &pump(), NOW);
    (m.verdict, m.measured_value / if m.measured_value > 1_000 { MIN } else { 1 })
}

const CONTINUOUS_30: HistoryPredicate = HistoryPredicate::MaxContinuousMs { limit_ms: 30 * MIN };

/// The Project Lead's example: ON 20, unknown 15, ON 5 is "possibly 40",
/// neither "certainly 40" nor "only 25": INSUFFICIENT_HISTORY against 30.
#[test]
fn a_run_broken_by_unknown_time_is_possibly_the_whole_of_it() {
    let r = rule(CONTINUOUS_30, 20 * MIN);
    let lead = [(60, Some(false)), (40, Some(true)), (20, None), (5, Some(true))];
    assert_eq!(verdict(&r, &lead).0, InsufficientHistory);
    assert_eq!(verdict(&r, &[(60, Some(false)), (35, Some(true))]), (LimitExceeded, 30), "known: at the limit");
    assert_eq!(verdict(&r, &[(60, Some(false)), (10, Some(true))]), (PassThrough, 10));
    // off at some point in the window: bounded, even with a little unknown
    assert_eq!(verdict(&r, &[(60, Some(true)), (20, Some(false)), (12, None), (10, Some(true))]).0, PassThrough);
    // but no more unknown than the rule allows
    let strict = rule(CONTINUOUS_30, MIN);
    assert_eq!(
        verdict(&strict, &[(60, Some(true)), (20, Some(false)), (12, None), (10, Some(true))]).0,
        InsufficientHistory
    );
    // never observed: nothing is known
    assert_eq!(verdict(&r, &[]).0, InsufficientHistory);
}

#[test]
fn off_time_counts_only_from_when_it_was_known_off() {
    let r = rule(HistoryPredicate::MinOffBeforeMs { limit_ms: 5 * MIN }, 0);
    assert_eq!(verdict(&r, &[(60, Some(true)), (10, Some(false))]), (PassThrough, 5));
    assert_eq!(verdict(&r, &[(60, Some(true)), (2, Some(false))]), (LimitExceeded, 2), "on two minutes ago");
    assert_eq!(verdict(&r, &[(60, Some(true)), (3, None), (2, Some(false))]).0, InsufficientHistory, "maybe on");
    assert_eq!(verdict(&r, &[(60, Some(true))]).0, LimitExceeded, "on now");
}

/// Entries cannot be bounded through a gap (Project Lead, 2026-10-07): any
/// unknown time in the window, even a second, is INSUFFICIENT_HISTORY.
#[test]
fn entries_are_never_bounded_through_a_gap() {
    let r = rule(HistoryPredicate::MaxEntries { limit: 6, window_ms: 60 * MIN }, 60 * MIN);
    let starts = |n: u64| -> Vec<(u64, Option<bool>)> {
        let mut e = vec![(90, Some(false))];
        for i in 0..n {
            e.push((50 - i * 6, Some(true)));
            e.push((47 - i * 6, Some(false)));
        }
        e
    };
    assert_eq!(verdict(&r, &starts(3)), (PassThrough, 3));
    assert_eq!(verdict(&r, &starts(6)), (LimitExceeded, 6));
    // off, then a gap, then off again: it may have started any number of times
    let gap = [(90, Some(false)), (30, None), (20, Some(false))];
    assert_eq!(verdict(&r, &gap).0, InsufficientHistory);
    let mut tiny = history(&[(90, Some(false))]);
    tiny.push(Record::Unobservable { device: pump(), at: NOW - 10 * MIN });
    tiny.push(Record::Observed {
        device: pump(),
        at: NOW - 10 * MIN + 1_000,
        observed_at: 0,
        state: payload([("on", false)]),
    });
    assert_eq!(
        measure(&r, &tiny, &pump(), NOW).verdict,
        InsufficientHistory,
        "a one-second gap, whatever max_unknown_ms"
    );
}

#[test]
fn time_in_the_value_counts_unknown_as_in_it() {
    let r = rule(HistoryPredicate::MaxInValueMs { limit_ms: 60 * MIN, window_ms: 240 * MIN }, 240 * MIN);
    assert_eq!(verdict(&r, &[(300, Some(false)), (100, Some(true)), (60, Some(false))]), (PassThrough, 40));
    assert_eq!(verdict(&r, &[(300, Some(false)), (100, Some(true)), (30, Some(false))]), (LimitExceeded, 70));
    // 40 in it, 30 unknown: possibly 70
    assert_eq!(
        verdict(&r, &[(300, Some(false)), (100, Some(true)), (60, None), (30, Some(false))]).0,
        InsufficientHistory
    );
}

/// The evaluator signs one record per rule: over the chain's head, bound to
/// the request; a broken chain is INSUFFICIENT_HISTORY for every rule.
#[test]
fn the_evaluator_signs_a_bound_record_per_rule() {
    let key = Keypair::from_seed(&test_seed("service:history"));
    let ev = Evaluator::new(id("service:history"), "0.4.0", key.clone());
    let r = rule(CONTINUOUS_30, 20 * MIN);
    let req = EvalRequest {
        evaluation_context_digest: [5; 32],
        resource: id("resource:pump"),
        device: pump(),
        capability: r.capability.clone(),
        rules: vec![r.clone()],
        now_ms: NOW,
    };
    let records = history(&[(60, Some(false)), (10, Some(true))]);
    let log = Chained { records, head: [8; 32], intact: true, tail: None };
    let signed = ev.evaluate(&req, &log);
    assert_eq!(signed.len(), 1);
    let c = &signed[0].constraint;
    assert_eq!((c.verdict, c.rule_version, c.rule_digest, c.evidence_digest), (PassThrough, 1, r.digest(), [8; 32]));
    assert_eq!((c.evaluation_context_digest, c.evaluated_at_ms, c.expires_at_ms), ([5; 32], NOW, NOW + 5_000));
    assert!(verify(&key.public_key(), &c.signing_bytes(), &signed[0].sig), "signed by the evaluator's key");
    let broken = Chained { intact: false, ..log };
    assert_eq!(ev.evaluate(&req, &broken)[0].constraint.verdict, InsufficientHistory, "a broken chain proves nothing");
    let json = serde_json::to_string(&req).unwrap();
    assert_eq!(serde_json::from_str::<EvalRequest>(&json).unwrap(), req);
}
