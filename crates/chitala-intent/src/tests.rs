use super::*;
use chitala_csme::{Csme, CONTENT_TYPE};
use chitala_identity::test_seed;
use chitala_model::payload;

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}
fn key(s: &str) -> Keypair {
    Keypair::from_seed(&test_seed(s))
}

fn unlock(actor: &str, for_: &str) -> Intent {
    Intent::new(
        new_intent_id(chitala_platform::memory::test_entropy()),
        id(actor),
        id(for_),
        CapabilityId::parse("lock.unlock").unwrap(),
        ResourceId::new("front-door").unwrap(),
        1_000_000,
        60_000,
    )
}

fn keys(k: &KeyId) -> Option<(EntityId, PublicKey)> {
    ["ai:assistant", "ai:kid-assistant", "person:alice"]
        .into_iter()
        .map(|p| (id(p), key(p).public_key()))
        .find(|(_, pk)| chitala_identity::key_id_of(pk) == *k)
}

#[test]
fn round_trip_and_signature() {
    let mut i = unlock("ai:assistant", "person:alice");
    i.params = payload([("note", "x")]);
    i.context.purpose = Some("let the plumber in".into());
    i.constraints.max_risk = Some(RiskClass::High);
    i.constraints.no_escalation = true;
    i.authority = Some(vec![1, 2, 3]);
    let bytes = i.sign(&key("ai:assistant"));
    let s = SignedIntent::parse(&bytes).unwrap();
    let me = id("ai:assistant");
    assert!(matches!(s.open(&me, &key("person:alice").public_key(), &keys), Err(OpenError::Signature(_))));
    assert!(matches!(
        s.open(&id("person:alice"), &key("ai:assistant").public_key(), &keys),
        Err(OpenError::SignerMismatch { .. })
    ));
    let v = s.open(&me, &key("ai:assistant").public_key(), &keys).unwrap();
    assert_eq!(v.intent(), &i);
    assert_eq!(v.digest(), &i.digest());
}

#[test]
fn intents_are_not_commands() {
    // an intent signature is never accepted as a CSME request, and vice versa
    let bytes = unlock("ai:assistant", "person:alice").sign(&key("ai:assistant"));
    assert!(SignedEnvelope::parse(&bytes).is_err());
    assert_eq!(chitala_csme::content_type_of(&bytes).as_deref(), Some(INTENT_CONTENT_TYPE));
    let csme = Csme {
        message_id: [1; 16],
        correlation_id: None,
        source: id("service:cli"),
        destination: id("device:front-door"),
        actor: id("ai:assistant"),
        capability: CapabilityId::parse("lock.unlock").unwrap(),
        capability_version: 1,
        message_type: chitala_model::MessageType::Command,
        issued_at_ms: 1,
        expires_at_ms: 2,
        context_ref: None,
        authority: None,
        risk: RiskClass::High,
        payload: Payload::new(),
    }
    .sign(&key("ai:assistant"));
    assert!(SignedIntent::parse(&csme).is_err());
    assert_eq!(chitala_csme::content_type_of(&csme).as_deref(), Some(CONTENT_TYPE));
    // and an approval is neither
    let a = approval(&unlock("ai:assistant", "person:alice")).sign(&key("person:alice"));
    assert!(SignedIntent::parse(&a).is_err());
    assert!(SignedApproval::parse(&bytes).is_err());
}

#[test]
fn shape_rules() {
    let bad = |mutate: &dyn Fn(&mut Intent)| {
        let mut i = unlock("ai:assistant", "person:alice");
        mutate(&mut i);
        Intent::from_cbor(&i.to_cbor()).unwrap_err()
    };
    // intents serve humans; persons act for themselves
    bad(&|i| i.on_behalf_of = id("ai:other"));
    bad(&|i| i.actor = id("person:bob"));
    bad(&|i| i.actor = id("resource:front-door"));
    // the deadline is after the request and within the lifetime cap
    assert_eq!(bad(&|i| i.constraints.deadline_ms = i.requested_at_ms).code, DenyCode::Expired);
    assert_eq!(
        bad(&|i| i.constraints.deadline_ms = i.requested_at_ms + MAX_INTENT_LIFETIME_MS + 1).code,
        DenyCode::LifetimeTooLong
    );
    bad(&|i| i.context.purpose = Some("x".repeat(MAX_PURPOSE_LEN + 1)));
    // a person acting for themselves is fine
    let me = unlock("person:alice", "person:alice");
    assert_eq!(Intent::from_cbor(&me.to_cbor()).unwrap(), me);
}

#[test]
fn strict_wire_form() {
    let i = unlock("ai:assistant", "person:alice");
    let Value::Map(mut m) = ciborium::de::from_reader::<Value, _>(i.to_cbor().as_slice()).unwrap() else { panic!() };
    // unknown key
    let mut extra = m.clone();
    extra.push((uint(15), uint(1)));
    let enc = encode_deterministic(&Value::Map(extra)).unwrap();
    assert!(Intent::from_cbor(&enc).is_err());
    // explicit `no_escalation: false` is not canonical
    let mut f = m.clone();
    f.push((uint(12), Value::Bool(false)));
    assert!(Intent::from_cbor(&encode_deterministic(&Value::Map(f)).unwrap()).is_err());
    // a resource must be a resource id, the actor an entity id
    for (k, v) in m.iter_mut() {
        if *k == uint(6) {
            *v = Value::Text("device:front-door".into());
        }
    }
    assert!(Intent::from_cbor(&encode_deterministic(&Value::Map(m)).unwrap()).is_err());
    // non-canonical encoding of a valid body
    let mut body = i.to_cbor();
    body[0] = 0xbf; // indefinite-length map header
    assert!(Intent::from_cbor(&body).is_err());
}

#[test]
fn relay_chains_are_verified() {
    let a = unlock("ai:kid-assistant", "person:alice");
    let a_bytes = a.sign(&key("ai:kid-assistant"));
    let mut b = unlock("ai:assistant", "person:alice");
    b.context.cause = Some(a_bytes.clone());
    let v = open_signed(&b.sign(&key("ai:assistant")), &keys).unwrap();
    let chain = v.chain();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].actor, id("ai:kid-assistant"));
    assert_eq!(v.cause().unwrap().digest(), &a.digest());

    let relay = |cause: Vec<u8>| {
        let mut b = unlock("ai:assistant", "person:alice");
        b.context.cause = Some(cause);
        open_signed(&b.sign(&key("ai:assistant")), &keys)
    };
    let is_cause = |r: Result<VerifiedIntent, OpenError>, needle: &str| match r {
        Err(OpenError::Cause(e)) => assert!(e.contains(needle), "{e}"),
        other => panic!("expected a cause error, got {other:?}"),
    };
    // a link signed by someone other than its actor
    is_cause(relay(a.sign(&key("ai:assistant"))), "signed by");
    // unknown key
    is_cause(relay(a.sign(&key("ai:stranger"))), "not enrolled");
    // tampered cause
    let mut t = a_bytes.clone();
    let n = t.len();
    t[n - 70] ^= 1;
    assert!(matches!(relay(t), Err(OpenError::Cause(_))));
    // depth cap: the intent plus MAX_CAUSE_DEPTH causes
    let mut bytes = a_bytes;
    for _ in 1..MAX_CAUSE_DEPTH {
        let mut next = unlock("ai:assistant", "person:alice");
        next.context.cause = Some(bytes);
        bytes = next.sign(&key("ai:assistant"));
    }
    assert!(relay(bytes.clone()).is_ok());
    let mut next = unlock("ai:assistant", "person:alice");
    next.context.cause = Some(bytes);
    is_cause(relay(next.sign(&key("ai:assistant"))), "chain longer");
}

fn approval(i: &Intent) -> Approval {
    Approval {
        intent: i.id,
        intent_digest: i.digest(),
        approver: id("person:alice"),
        verdict: Verdict::Approve,
        issued_at_ms: 1_000_100,
        expires_at_ms: 1_060_000,
        note: Some("ok, plumber".into()),
    }
}

#[test]
fn approvals() {
    let i = unlock("ai:assistant", "person:alice");
    let a = approval(&i);
    let bytes = a.sign(&key("person:alice"));
    let s = SignedApproval::parse(&bytes).unwrap();
    let alice = id("person:alice");
    assert_eq!(s.open(&alice, &key("person:alice").public_key()).unwrap().approval(), &a);
    assert!(matches!(s.open(&alice, &key("person:bob").public_key()), Err(OpenError::Signature(_))));
    assert!(matches!(
        s.open(&id("person:bob"), &key("person:alice").public_key()),
        Err(OpenError::SignerMismatch { .. })
    ));
    // only humans approve
    let mut ai = a.clone();
    ai.approver = id("ai:assistant");
    assert!(Approval::from_cbor(&ai.to_cbor()).is_err());
    let mut long = a.clone();
    long.expires_at_ms = long.issued_at_ms + MAX_APPROVAL_LIFETIME_MS + 1;
    assert!(Approval::from_cbor(&long.to_cbor()).is_err());
    // the digest pins the exact intent: any change to it changes the digest
    let mut other = i.clone();
    other.params = payload([("x", 1i64)]);
    assert_ne!(other.digest(), a.intent_digest);
    assert_eq!(parse_id_hex(&id_hex(&i.id)), Some(i.id));
    assert_eq!(parse_id_hex("zz"), None);
}
