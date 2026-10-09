use super::*;
use serde_json::{json, Value};

/// RFC 7396: a merge patch; null removes a member.
fn merge(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(t), Value::Object(p)) => {
            for (k, v) in p {
                if v.is_null() {
                    t.remove(k);
                } else {
                    merge(t.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
        }
        (t, p) => *t = p.clone(),
    }
}

/// The language-neutral vectors of `specs/evidence/vectors.json`: each case
/// decodes and validates as it says.
#[test]
fn the_test_vectors_hold() {
    let doc: Value = serde_json::from_str(include_str!("../../../specs/evidence/vectors.json")).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        let mut e = doc["base"].clone();
        merge(&mut e, &case["patch"]);
        let now = case["now_ms"].as_u64().or(doc["now_ms"].as_u64()).unwrap();
        let got = match decode(serde_json::to_vec(&e).unwrap().as_slice(), now) {
            Ok(_) => "ok",
            Err(err) => err.code(),
        };
        assert_eq!(got, case["expect"].as_str().unwrap(), "{}", case["name"]);
    }
}

fn piece(source: &str, reading: Reading, valid_until_ms: u64) -> Checked {
    let e = Evidence {
        kind: "obstacle".into(),
        subject: ResourceId::parse("resource:robot").unwrap(),
        source: EntityId::parse(source).unwrap(),
        observed_at_ms: 1_000,
        received_at_ms: 1_000,
        valid_until_ms,
        scope: Scope::Whole,
        reading,
        quality: Quality { confidence_per_mille: 900, accuracy: None },
        provenance: Provenance { adapter: "test".into(), path: vec![], signed_by_source: true, attested: false },
    };
    validate(e, 1_000).unwrap()
}

fn known(b: bool) -> Reading {
    Reading::Known { value: Measured::Bool(b) }
}

fn robot() -> ResourceId {
    ResourceId::parse("resource:robot").unwrap()
}

/// Sources that agree, agree; those that do not know are listed apart.
#[test]
fn agreement_names_who_agreed_and_who_did_not_know() {
    let pieces = [
        piece("device:lidar", known(false), 5_000),
        piece("device:bumper", known(false), 5_000),
        piece("device:camera", Reading::Unknown { reason: "dark".into() }, 5_000),
    ];
    match combine(&pieces, &robot(), "obstacle", 2_000).unwrap() {
        Combined::Agreed { value, sources, unknown } => {
            assert_eq!(value, Measured::Bool(false));
            assert_eq!(sources.len(), 2);
            assert_eq!(unknown, vec![EntityId::parse("device:camera").unwrap()]);
        }
        other => panic!("{other:?}"),
    }
}

/// Sources that disagree are a conflict: nothing is picked, not even the
/// more confident or the safer value.
#[test]
fn a_conflict_stays_a_conflict() {
    let pieces = [piece("device:lidar", known(false), 5_000), piece("device:bumper", known(true), 5_000)];
    assert!(matches!(combine(&pieces, &robot(), "obstacle", 2_000).unwrap(), Combined::Conflict { .. }));
}

/// Expired evidence is no evidence: a source whose piece expired counts as
/// one that does not know, and with nothing else, the whole is unknown.
#[test]
fn expired_evidence_is_no_evidence() {
    let pieces = [piece("device:lidar", known(false), 1_500), piece("device:bumper", known(true), 1_500)];
    match combine(&pieces, &robot(), "obstacle", 2_000).unwrap() {
        Combined::Unknown { sources } => assert_eq!(sources.len(), 2),
        other => panic!("{other:?}"),
    }
}

/// Other kinds and other subjects are left out; too many pieces are refused.
#[test]
fn only_one_kind_about_one_subject_and_within_a_bound() {
    let pieces = [piece("device:lidar", known(true), 5_000)];
    let other = ResourceId::parse("resource:door").unwrap();
    assert!(matches!(combine(&pieces, &other, "obstacle", 2_000).unwrap(), Combined::Unknown { .. }));
    assert!(matches!(combine(&pieces, &robot(), "localization", 2_000).unwrap(), Combined::Unknown { .. }));
    let many: Vec<Checked> = (0..=limits::MAX_COMBINED).map(|_| piece("device:lidar", known(true), 5_000)).collect();
    assert_eq!(combine(&many, &robot(), "obstacle", 2_000).unwrap_err(), EvidenceError::TooMany);
}

/// Evidence round-trips through its JSON form, and its form is the one the
/// vectors use.
#[test]
fn evidence_round_trips_in_the_form_of_the_vectors() {
    let p = piece("device:lidar", known(false), 5_000);
    let v = serde_json::to_value(p.evidence()).unwrap();
    assert_eq!(v["reading"], json!({"status": "known", "value": {"type": "bool", "value": false}}));
    assert_eq!(v["scope"], json!({"type": "whole"}));
    let back: Evidence = serde_json::from_value(v).unwrap();
    assert_eq!(&back, p.evidence());
}
