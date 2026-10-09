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

fn code(r: &Result<Checked, EvidenceError>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(err) => err.code(),
    }
}

/// The language-neutral vectors of `specs/evidence/vectors.json`. Each case
/// gives the same result by both paths to a `Checked`: decoded from bytes,
/// and validated as an `Evidence` built in memory. Evidence that passes
/// decodes again from its own encoding.
#[test]
fn the_test_vectors_hold_by_decode_and_by_validate() {
    let doc: Value = serde_json::from_str(include_str!("../../../specs/evidence/vectors.json")).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 40);
    for case in cases {
        let name = &case["name"];
        let expect = case["expect"].as_str().unwrap();
        let mut e = doc["base"].clone();
        merge(&mut e, &case["patch"]);
        let now = case["now_ms"].as_u64().or(doc["now_ms"].as_u64()).unwrap();
        let decoded = decode(&serde_json::to_vec(&e).unwrap(), now);
        assert_eq!(code(&decoded), expect, "decode: {name}");
        let validated = match serde_json::from_value::<Evidence>(e) {
            Ok(built) => code(&validate(built, now)),
            Err(_) => "malformed",
        };
        assert_eq!(validated, expect, "validate: {name}");
        if let Ok(checked) = decoded {
            let again = decode(&serde_json::to_vec(checked.evidence()).unwrap(), now);
            assert_eq!(code(&again), "ok", "its own encoding: {name}");
        }
    }
}

/// Every field within its own bound, the whole above the encoded bound: both
/// paths refuse it, so no `Checked` exists that `decode` would refuse.
#[test]
fn the_encoded_bound_holds_on_every_path() {
    let doc: Value = serde_json::from_str(include_str!("../../../specs/evidence/vectors.json")).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "every field within its bound, the whole above 4096 bytes")
        .unwrap();
    let mut v = doc["base"].clone();
    merge(&mut v, &case["patch"]);
    let e: Evidence = serde_json::from_value(v).unwrap();
    let bytes = serde_json::to_vec(&e).unwrap();
    assert!(bytes.len() > limits::MAX_ENCODED_BYTES, "{}", bytes.len());
    let mut within = e.clone();
    within.provenance.path.truncate(1);
    assert!(validate(within, 1_500).is_ok(), "each field is within its own bound");
    assert_eq!(validate(e, 1_500).unwrap_err(), EvidenceError::TooLarge);
    assert_eq!(decode(&bytes, 1_500).unwrap_err(), EvidenceError::TooLarge);
}

fn robot() -> ResourceId {
    ResourceId::parse("resource:robot").unwrap()
}

fn left() -> Scope {
    Scope::Region { points_mm: vec![[-1_000, 0], [0, 0], [0, 1_000], [-1_000, 1_000]] }
}

fn right() -> Scope {
    Scope::Region { points_mm: vec![[0, 0], [1_000, 0], [1_000, 1_000], [0, 1_000]] }
}

fn whole() -> Scope {
    Scope::Whole {}
}

fn known(b: bool) -> Reading {
    Reading::Known { value: Measured::Bool(b) }
}

/// A piece about the robot's obstacles, checked at `observed_at_ms`.
fn piece(source: &str, scope: Scope, reading: Reading, observed_at_ms: u64, valid_until_ms: u64) -> Checked {
    let e = Evidence {
        kind: "obstacle".into(),
        subject: robot(),
        source: EntityId::parse(source).unwrap(),
        observed_at_ms,
        received_at_ms: observed_at_ms,
        valid_until_ms,
        scope,
        reading,
        quality: Quality { confidence_per_mille: 900, accuracy: None },
        provenance: Provenance { adapter: "test".into(), path: vec![], signed_by_source: true, attested: false },
    };
    validate(e, observed_at_ms).unwrap()
}

fn ask(pieces: &[Checked], scope: &Scope, now_ms: u64) -> Combination {
    combine(pieces, &robot(), "obstacle", scope, now_ms).unwrap()
}

fn reasons(c: &Combination) -> Vec<LeftOut> {
    c.left_out.iter().map(|(_, why)| *why).collect()
}

/// Sources that agree, agree; one that does not know is counted, and says
/// so; every piece is kept whole.
#[test]
fn agreement_keeps_every_piece_whole() {
    let pieces = [
        piece("device:lidar", whole(), known(false), 1_000, 5_000),
        piece("device:bumper", whole(), known(false), 1_000, 4_000),
        piece("device:camera", whole(), Reading::Unknown { reason: "dark".into() }, 1_000, 6_000),
    ];
    let c = ask(&pieces, &whole(), 2_000);
    assert_eq!(c.verdict, Verdict::Agreed(Measured::Bool(false)));
    assert_eq!(c.counted, pieces.to_vec());
    assert!(c.left_out.is_empty());
    assert_eq!(c.sources().len(), 3);
}

/// Sources that disagree are a conflict: nothing is picked, not even the
/// more confident or the safer value.
#[test]
fn a_conflict_stays_a_conflict() {
    let pieces = [
        piece("device:lidar", whole(), known(false), 1_000, 5_000),
        piece("device:bumper", whole(), known(true), 1_000, 5_000),
    ];
    let c = ask(&pieces, &whole(), 2_000);
    assert_eq!(c.verdict, Verdict::Conflict);
    assert_eq!(c.counted.len(), 2);
}

/// Evidence about one scope says nothing about another: two clear halves
/// are not a clear whole, and an obstacle in one half is no conflict with a
/// clear other half. A piece left out for its scope is still returned.
#[test]
fn only_pieces_over_the_same_scope_are_compared() {
    let pieces = [
        piece("device:lidar", left(), known(false), 1_000, 5_000),
        piece("device:camera", right(), known(false), 1_000, 5_000),
    ];
    let c = ask(&pieces, &whole(), 2_000);
    assert_eq!(c.verdict, Verdict::Unknown);
    assert_eq!(reasons(&c), vec![LeftOut::OtherScope, LeftOut::OtherScope]);

    let c = ask(&pieces, &left(), 2_000);
    assert_eq!(c.verdict, Verdict::Agreed(Measured::Bool(false)));
    assert_eq!(c.scope, left());
    assert_eq!(c.counted, vec![pieces[0].clone()]);

    let mixed = [
        piece("device:lidar", left(), known(true), 1_000, 5_000),
        piece("device:camera", right(), known(false), 1_000, 5_000),
        piece("device:bumper", whole(), known(false), 1_000, 5_000),
    ];
    let c = ask(&mixed, &whole(), 2_000);
    assert_eq!(c.verdict, Verdict::Agreed(Measured::Bool(false)));
    assert_eq!(c.left_out[0], (mixed[0].clone(), LeftOut::OtherScope), "the obstacle on the left is not lost");
}

/// One region is the same region from whatever corner, in either direction;
/// a question over a malformed region is refused.
#[test]
fn a_region_is_the_same_from_any_corner_and_either_direction() {
    let turned = Scope::Region { points_mm: vec![[1_000, 1_000], [1_000, 0], [0, 0], [0, 1_000]] };
    let pieces = [
        piece("device:lidar", right(), known(false), 1_000, 5_000),
        piece("device:camera", turned, known(false), 1_000, 5_000),
    ];
    let c = ask(&pieces, &right(), 2_000);
    assert_eq!(c.counted.len(), 2);
    let crossed = Scope::Region { points_mm: vec![[0, 0], [1_000, 1_000], [1_000, 0], [0, 1_000]] };
    assert_eq!(combine(&pieces, &robot(), "obstacle", &crossed, 2_000).unwrap_err(), EvidenceError::BadRegion);
}

/// A source counts once, by its latest observation. Its older pieces are
/// superseded, and never come back when the latest expires; the same
/// observation twice is counted once.
#[test]
fn a_source_counts_once_by_its_latest_observation() {
    let older = piece("device:lidar", whole(), known(false), 1_000, 9_000);
    let newer = piece("device:lidar", whole(), known(true), 2_000, 3_000);
    let c = ask(&[older.clone(), newer.clone()], &whole(), 2_500);
    assert_eq!(c.verdict, Verdict::Agreed(Measured::Bool(true)));
    assert_eq!(c.counted, vec![newer.clone()]);
    assert_eq!(c.left_out, vec![(older.clone(), LeftOut::Superseded)]);

    let c = ask(&[older.clone(), newer.clone()], &whole(), 3_500);
    assert_eq!(c.verdict, Verdict::Unknown, "the older reading never comes back");
    assert_eq!(reasons(&c), vec![LeftOut::Superseded, LeftOut::Expired]);

    let again = piece("device:lidar", whole(), known(true), 2_000, 3_000);
    let c = ask(&[newer.clone(), again], &whole(), 2_500);
    assert_eq!(c.counted.len(), 1);
    assert_eq!(reasons(&c), vec![LeftOut::Repeated]);
    assert_eq!(c.sources().len(), 1, "two records of one source are one source");
}

/// A source that says two things about one moment contradicts itself: both
/// are counted, and it is a conflict.
#[test]
fn a_source_that_contradicts_itself_is_a_conflict() {
    let pieces = [
        piece("device:lidar", whole(), known(false), 2_000, 5_000),
        piece("device:lidar", whole(), known(true), 2_000, 5_000),
    ];
    let c = ask(&pieces, &whole(), 2_500);
    assert_eq!(c.verdict, Verdict::Conflict);
    assert_eq!(c.sources().len(), 1);
}

/// A combination holds until the first counted piece expires, and not
/// before it was made. With nothing counted, it holds at no time.
#[test]
fn a_combination_holds_until_its_first_piece_expires() {
    let pieces = [
        piece("device:lidar", whole(), known(false), 1_000, 5_000),
        piece("device:bumper", whole(), known(false), 1_000, 4_000),
    ];
    let c = ask(&pieces, &whole(), 2_000);
    assert_eq!(c.valid_until_ms, 4_000);
    assert!(c.holds_at(2_000) && c.holds_at(3_999));
    assert!(!c.holds_at(4_000));
    assert!(!c.holds_at(1_999), "not before it was made");

    let c = ask(&[], &whole(), 2_000);
    assert_eq!(c.verdict, Verdict::Unknown);
    assert!(!c.holds_at(2_000));
}

/// Expired evidence is no evidence: left out, and with nothing else, the
/// whole is unknown.
#[test]
fn expired_evidence_is_no_evidence() {
    let pieces = [
        piece("device:lidar", whole(), known(false), 1_000, 1_500),
        piece("device:bumper", whole(), known(true), 1_000, 1_500),
    ];
    let c = ask(&pieces, &whole(), 2_000);
    assert_eq!(c.verdict, Verdict::Unknown);
    assert_eq!(reasons(&c), vec![LeftOut::Expired, LeftOut::Expired]);
}

/// When the node's clock goes back, before a piece was checked: combining
/// is refused, and the piece is valid at no such time.
#[test]
fn a_clock_that_went_back_is_refused() {
    let p = piece("device:lidar", whole(), known(false), 2_000, 5_000);
    assert!(!p.valid_at(1_999));
    assert_eq!(
        combine(std::slice::from_ref(&p), &robot(), "obstacle", &whole(), 1_999).unwrap_err(),
        EvidenceError::TimeWentBack
    );
}

/// Other kinds and other subjects are not part of the question; too many
/// pieces are refused.
#[test]
fn only_one_kind_about_one_subject_and_within_a_bound() {
    let pieces = [piece("device:lidar", whole(), known(true), 1_000, 5_000)];
    let door = ResourceId::parse("resource:door").unwrap();
    let c = combine(&pieces, &door, "obstacle", &whole(), 2_000).unwrap();
    assert!(c.counted.is_empty() && c.left_out.is_empty());
    let c = combine(&pieces, &robot(), "localization", &whole(), 2_000).unwrap();
    assert!(c.counted.is_empty() && c.left_out.is_empty());
    let many = vec![pieces[0].clone(); limits::MAX_COMBINED + 1];
    assert_eq!(combine(&many, &robot(), "obstacle", &whole(), 2_000).unwrap_err(), EvidenceError::TooMany);
}

/// Evidence round-trips through its JSON form, and its form is the one the
/// vectors use.
#[test]
fn evidence_round_trips_in_the_form_of_the_vectors() {
    let p = piece("device:lidar", whole(), known(false), 1_000, 5_000);
    let v = serde_json::to_value(p.evidence()).unwrap();
    assert_eq!(v["reading"], json!({"status": "known", "value": {"type": "bool", "value": false}}));
    assert_eq!(v["scope"], json!({"type": "whole"}));
    assert_eq!(v["quality"], json!({"confidence_per_mille": 900}), "an absent accuracy is left out");
    let back: Evidence = serde_json::from_value(v).unwrap();
    assert_eq!(&back, p.evidence());
}
