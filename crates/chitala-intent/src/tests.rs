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

fn thermostat_lease(max_uses: u32, duration_ms: u64) -> Intent {
    let mut i = unlock("ai:assistant", "person:alice");
    i.action = CapabilityId::parse("climate.set_target_temperature").unwrap();
    i.resource = ResourceId::new("thermostat").unwrap();
    i.lease = Some(LeaseClause::Request(LeaseTerms {
        max_uses,
        duration_ms,
        envelope: [("celsius".to_string(), (20, 24))].into_iter().collect(),
    }));
    i
}

fn raw(i: &Intent) -> Vec<(Value, Value)> {
    let Value::Map(m) = ciborium::de::from_reader::<Value, _>(i.to_cbor().as_slice()).unwrap() else { panic!() };
    m
}

fn rebuilt(m: Vec<(Value, Value)>) -> Result<Intent, DecodeError> {
    Intent::from_cbor(&encode_deterministic(&Value::Map(m)).unwrap())
}

/// Spec 21: a lease clause makes the intent version 2; without one an intent
/// is version 1 byte for byte, so existing digests and approvals stand.
#[test]
fn lease_clauses_on_the_wire() {
    let plain = unlock("ai:assistant", "person:alice");
    assert!(raw(&plain).contains(&(uint(1), uint(1))));
    assert!(!raw(&plain).iter().any(|(k, _)| *k == uint(15) || *k == uint(16)));

    let ask = thermostat_lease(3, 3_600_000);
    assert!(raw(&ask).contains(&(uint(1), uint(2))));
    assert_eq!(Intent::from_cbor(&ask.to_cbor()).unwrap(), ask);
    // the terms are part of what an approval binds to
    let mut wider = ask.clone();
    wider.lease = Some(LeaseClause::Request(LeaseTerms {
        max_uses: 4,
        ..match &ask.lease {
            Some(LeaseClause::Request(t)) => t.clone(),
            _ => unreachable!(),
        }
    }));
    assert_ne!(ask.digest(), wider.digest());

    let mut use_ = unlock("ai:assistant", "person:alice");
    use_.lease = Some(LeaseClause::Use([7; 16]));
    assert_eq!(Intent::from_cbor(&use_.to_cbor()).unwrap(), use_);

    // version 1 with a lease key, version 2 without one, both keys at once
    let mut m = raw(&ask);
    m.retain(|(k, _)| *k != uint(1));
    m.push((uint(1), uint(1)));
    assert_eq!(rebuilt(m).unwrap_err().code, DenyCode::Version);
    let mut m = raw(&plain);
    m.retain(|(k, _)| *k != uint(1));
    m.push((uint(1), uint(2)));
    assert_eq!(rebuilt(m).unwrap_err().code, DenyCode::Version);
    let mut m = raw(&ask);
    m.push((uint(16), Value::Bytes(vec![7; 16])));
    assert!(rebuilt(m).is_err());
    // a lease id is exactly 16 bytes
    let mut m = raw(&use_);
    for (k, v) in m.iter_mut() {
        if *k == uint(16) {
            *v = Value::Bytes(vec![7; 15]);
        }
    }
    assert!(rebuilt(m).is_err());
}

#[test]
fn lease_terms_have_limits() {
    for (uses, ms) in [(0, 60_000), (LEASE_MAX_USES + 1, 60_000), (1, 999), (1, LEASE_MAX_DURATION_MS + 1)] {
        assert!(Intent::from_cbor(&thermostat_lease(uses, ms).to_cbor()).is_err(), "{uses} uses, {ms} ms");
    }
    assert!(Intent::from_cbor(&thermostat_lease(LEASE_MAX_USES, LEASE_MAX_DURATION_MS).to_cbor()).is_ok());
    let with_env = |envelope: Vec<(&str, (i64, i64))>| {
        let mut i = thermostat_lease(2, 60_000);
        i.lease = Some(LeaseClause::Request(LeaseTerms {
            max_uses: 2,
            duration_ms: 60_000,
            envelope: envelope.into_iter().map(|(n, r)| (n.to_string(), r)).collect(),
        }));
        Intent::from_cbor(&i.to_cbor())
    };
    assert!(with_env(vec![("celsius", (24, 20))]).is_err(), "min > max");
    assert!(with_env(vec![("", (1, 2))]).is_err(), "empty name");
    let nine: Vec<(String, (i64, i64))> = (0..9).map(|n| (format!("p{n}"), (0, 1))).collect();
    let mut i = thermostat_lease(2, 60_000);
    i.lease = Some(LeaseClause::Request(LeaseTerms {
        max_uses: 2,
        duration_ms: 60_000,
        envelope: nine.into_iter().collect(),
    }));
    assert!(Intent::from_cbor(&i.to_cbor()).is_err(), "more than 8 envelope parameters");
    // an explicit empty envelope is not canonical; malformed ranges are refused
    let ask = thermostat_lease(2, 60_000);
    let set_terms = |terms: Value| {
        let mut m = raw(&ask);
        for (k, v) in m.iter_mut() {
            if *k == uint(15) {
                *v = terms.clone();
            }
        }
        rebuilt(m)
    };
    assert!(set_terms(Value::Map(vec![(uint(1), uint(2)), (uint(2), uint(60_000)), (uint(3), Value::Map(vec![]))]))
        .is_err());
    let one = Value::Map(vec![(Value::Text("celsius".into()), Value::Array(vec![Value::Integer(20.into())]))]);
    assert!(set_terms(Value::Map(vec![(uint(1), uint(2)), (uint(2), uint(60_000)), (uint(3), one)])).is_err());
    assert!(set_terms(Value::Map(vec![(uint(1), uint(2))])).is_err(), "missing duration");
    // a lease is asked for first-hand only
    let mut relayed = thermostat_lease(2, 60_000);
    relayed.context.cause = Some(vec![1, 2, 3]);
    assert!(relayed.validate().is_err());
}

fn evening_plan() -> Intent {
    let mut i = unlock("ai:assistant", "person:alice");
    i.action = CapabilityId::parse("lock.lock").unwrap();
    i.then = vec![
        PlanStep::new(
            CapabilityId::parse("climate.set_target_temperature").unwrap(),
            ResourceId::new("thermostat").unwrap(),
            payload([("celsius", 21i64)]),
        ),
        PlanStep::new(
            CapabilityId::parse("light.turn_off").unwrap(),
            ResourceId::new("living-room-light").unwrap(),
            Payload::new(),
        ),
    ];
    i
}

/// Spec 23: follow-up steps make the intent version 2 and are part of what is
/// signed; each step is derived as an intent of its own, bound to the plan.
#[test]
fn plans_on_the_wire_and_their_steps() {
    let plan = evening_plan();
    assert!(raw(&plan).contains(&(uint(1), uint(2))));
    assert_eq!(Intent::from_cbor(&plan.to_cbor()).unwrap(), plan);
    let v = open_signed(&plan.sign(&key("ai:assistant")), &keys).unwrap();
    assert_eq!(v.plan_len(), 3);
    assert!(v.plan_step(3).is_none());

    let steps: Vec<VerifiedIntent> = (0..3).map(|k| v.plan_step(k).unwrap()).collect();
    // a step may carry its own token; otherwise it uses the plan intent's
    let mut tokens = plan.clone();
    tokens.authority = Some(vec![1; 8]);
    tokens.then[0].authority = Some(vec![2; 8]);
    assert_eq!(Intent::from_cbor(&tokens.to_cbor()).unwrap(), tokens);
    let t = open_signed(&tokens.sign(&key("ai:assistant")), &keys).unwrap();
    let auth = |k: usize| t.plan_step(k).unwrap().intent().authority.clone();
    assert_eq!((auth(0), auth(1), auth(2)), (Some(vec![1; 8]), Some(vec![2; 8]), Some(vec![1; 8])));
    assert_eq!(steps[0].intent().action.as_str(), "lock.lock");
    assert_eq!(steps[1].intent().params, payload([("celsius", 21i64)]));
    assert_eq!(steps[2].intent().resource.local(), "living-room-light");
    for s in &steps {
        let i = s.intent();
        // the plan's actor, person, token and deadline; one action, no plan, no relay
        assert_eq!((&i.actor, &i.on_behalf_of), (&plan.actor, &plan.on_behalf_of));
        assert_eq!(i.constraints.deadline_ms, plan.constraints.deadline_ms);
        assert!(i.then.is_empty() && i.lease.is_none() && s.cause().is_none() && s.plan_len() == 0);
        // its own id and digest: an approval of a step answers that step only,
        // never the plan and never a stand-alone intent with the same content
        assert_ne!(i.id, plan.id);
        assert_ne!(s.digest(), v.digest());
        assert_ne!(s.digest(), &i.digest());
    }
    assert_ne!(steps[0].intent().id, steps[1].intent().id);
    // derivation is deterministic, and bound to the signed plan
    assert_eq!(v.plan_step(1).unwrap(), steps[1]);
    let mut other = plan.clone();
    other.then[1].params = payload([("x", 1i64)]);
    let w = open_signed(&other.sign(&key("ai:assistant")), &keys).unwrap();
    assert_ne!(w.plan_step(0).unwrap().digest(), steps[0].digest(), "a change anywhere in the plan changes every step");
    // a single action is no plan
    let single = open_signed(&unlock("ai:assistant", "person:alice").sign(&key("ai:assistant")), &keys).unwrap();
    assert_eq!(single.plan_len(), 0);
    assert!(single.plan_step(0).is_none());
}

#[test]
fn plans_have_limits() {
    // at most PLAN_MAX_STEPS steps, the intent included
    let mut long = evening_plan();
    long.then = (0..PLAN_MAX_STEPS).map(|_| long.then[1].clone()).collect();
    assert!(Intent::from_cbor(&long.to_cbor()).is_err());
    long.then.truncate(PLAN_MAX_STEPS - 1);
    assert!(Intent::from_cbor(&long.to_cbor()).is_ok());
    // not with a lease, not through a relay
    let mut leased = evening_plan();
    leased.lease = Some(LeaseClause::Use([7; 16]));
    assert!(Intent::from_cbor(&leased.to_cbor()).is_err());
    let mut relayed = evening_plan();
    relayed.context.cause = Some(unlock("ai:kid-assistant", "person:alice").sign(&key("ai:kid-assistant")));
    assert!(Intent::from_cbor(&relayed.to_cbor()).is_err());
    // an empty array, or version 1 with steps, is not a plan
    let mut m = raw(&evening_plan());
    for (k, v) in m.iter_mut() {
        if *k == uint(17) {
            *v = Value::Array(vec![]);
        }
    }
    assert!(rebuilt(m).is_err());
    let mut m = raw(&evening_plan());
    m.retain(|(k, _)| *k != uint(1));
    m.push((uint(1), uint(1)));
    assert_eq!(rebuilt(m).unwrap_err().code, DenyCode::Version);
    // a step has exactly its keys, and empty params are omitted
    let mut m = raw(&evening_plan());
    for (k, v) in m.iter_mut() {
        if *k == uint(17) {
            let Value::Array(steps) = v else { panic!() };
            let Value::Map(step) = &mut steps[0] else { panic!() };
            step.push((uint(5), uint(1)));
        }
    }
    assert!(rebuilt(m).is_err());
    let mut m = raw(&evening_plan());
    for (k, v) in m.iter_mut() {
        if *k == uint(17) {
            let Value::Array(steps) = v else { panic!() };
            let Value::Map(step) = &mut steps[1] else { panic!() };
            step.push((uint(3), Value::Map(vec![])));
        }
    }
    assert!(rebuilt(m).is_err());
}
