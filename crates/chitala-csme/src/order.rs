//! Execution orders and receipts: the boundary between the trusted core and
//! the adapter hosts (specs `specs/19-execution-boundary.md`, `specs/10-twin-and-events.md`
//! §"Adapter isolation"; Blueprint A.3, v8 §12).
//!
//! An order is the **only** message that makes an adapter host act on a device.
//! The Trusted Execution Boundary (`chitala-boundary`) mints it from an
//! authority decision and a safety clearance, signs it with its own session key
//! and binds it to one adapter host instance. The adapter host executes only
//! orders that
//!
//! - carry content type `application/chitala-order` (no other Chitala
//!   signature can be replayed as an order),
//! - are signed by the order key it was given at start-up,
//! - name its own executor session,
//! - are fresh (`issued_at ≤ now + skew`, `now < expires_at`, lifetime ≤ 30 s),
//! - carry parameters that match their parameter digest, and
//! - have not been executed before (single use).
//!
//! The order body is a deterministic-CBOR map with exactly these keys:
//!
//! | key | field | type |
//! |----:|-------|------|
//! | 1 | version (= 2) | uint |
//! | 2 | order id: 128 random bits, single use (the order's nonce) | bstr(16) |
//! | 3 | executor: session of the one adapter host instance that may execute it | bstr(16) |
//! | 4 | subject: id of the authorized intent or request | bstr(16) |
//! | 5 | subject digest: the intent digest approvals sign (spec 15), or SHA-256 of the signed request | bstr(32) |
//! | 6 | actor | tstr |
//! | 7 | resource | tstr |
//! | 8 | device | tstr |
//! | 9 | capability | tstr |
//! | 10 | capability version | uint |
//! | 11 | parameters (omitted when empty) | map |
//! | 12 | parameter digest: SHA-256 of the deterministic CBOR of the parameters | bstr(32) |
//! | 13 | context digest: the authority context of the decision (spec 19) | bstr(32) |
//! | 14 | authority epoch at the decision | uint |
//! | 15 | evidence: audit sequence number of the decision record | uint |
//! | 16 | cleared at: time of the safety clearance (ms) | uint |
//! | 17 | issued at (ms) | uint |
//! | 18 | expires at (ms) | uint |
//!
//! After executing, the adapter host answers with an [`ExecutionReceipt`] bound
//! to the exact order bytes and to the state it reports.

use chitala_identity::{key_id_of, Keypair, PublicKey};
use chitala_model::{CapabilityId, DenyCode, EntityId, Payload};
use ciborium::value::Value;
use sha2::{Digest, Sha256};

use crate::{
    decode_err, encode_deterministic, entity, err, id16, payload_of, payload_value, sign_payload_as, text, uint,
    uint_of, DecodeError, SignedEnvelope, ID_LEN,
};

pub const ORDER_CONTENT_TYPE: &str = "application/chitala-order";
pub const ORDER_VERSION: u64 = 2;
/// Default validity of an order after it is issued.
pub const ORDER_TTL_MS: u64 = 10_000;
/// Longest lifetime an adapter host accepts.
pub const MAX_ORDER_LIFETIME_MS: u64 = 30_000;

pub type Digest32 = [u8; 32];

/// SHA-256 of the deterministic CBOR of a payload (parameters, reported state).
pub fn payload_digest(p: &Payload) -> Digest32 {
    let bytes = encode_deterministic(&payload_value(p)).expect("a payload is always encodable");
    Sha256::digest(bytes).into()
}

/// SHA-256 of a signed message exactly as sent (order, intent, request).
pub fn message_digest(bytes: &[u8]) -> Digest32 {
    Sha256::digest(bytes).into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOrder {
    pub id: [u8; ID_LEN],
    pub executor: [u8; ID_LEN],
    pub subject: [u8; ID_LEN],
    pub subject_digest: Digest32,
    pub actor: EntityId,
    /// The governed resource (`resource:…`) the action is on.
    pub resource: EntityId,
    pub device: EntityId,
    pub capability: CapabilityId,
    pub capability_version: u32,
    pub params: Payload,
    pub params_digest: Digest32,
    pub context_digest: Digest32,
    pub epoch: u64,
    pub evidence_seq: u64,
    pub cleared_at_ms: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

fn digest32(v: Value, name: &str) -> Result<Digest32, DecodeError> {
    match v {
        Value::Bytes(b) => b.try_into().map_err(|_| decode_err(format!("{name} must be 32 bytes"))),
        _ => Err(decode_err(format!("{name} must be a byte string"))),
    }
}

impl ExecOrder {
    fn to_value(&self) -> Value {
        let mut m = vec![
            (uint(1), uint(ORDER_VERSION)),
            (uint(2), Value::Bytes(self.id.to_vec())),
            (uint(3), Value::Bytes(self.executor.to_vec())),
            (uint(4), Value::Bytes(self.subject.to_vec())),
            (uint(5), Value::Bytes(self.subject_digest.to_vec())),
            (uint(6), Value::Text(self.actor.to_string())),
            (uint(7), Value::Text(self.resource.to_string())),
            (uint(8), Value::Text(self.device.to_string())),
            (uint(9), Value::Text(self.capability.to_string())),
            (uint(10), uint(self.capability_version as u64)),
        ];
        if !self.params.is_empty() {
            m.push((uint(11), payload_value(&self.params)));
        }
        m.extend([
            (uint(12), Value::Bytes(self.params_digest.to_vec())),
            (uint(13), Value::Bytes(self.context_digest.to_vec())),
            (uint(14), uint(self.epoch)),
            (uint(15), uint(self.evidence_seq)),
            (uint(16), uint(self.cleared_at_ms)),
            (uint(17), uint(self.issued_at_ms)),
            (uint(18), uint(self.expires_at_ms)),
        ]);
        Value::Map(m)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        encode_deterministic(&self.to_value()).expect("an order is always encodable")
    }

    /// Sign with the boundary's order key.
    pub fn sign(&self, order_key: &Keypair) -> Vec<u8> {
        sign_payload_as(self.to_cbor(), order_key, ORDER_CONTENT_TYPE)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let value: Value =
            ciborium::de::from_reader_with_recursion_limit(bytes, 8).map_err(|e| decode_err(format!("CBOR: {e}")))?;
        if encode_deterministic(&value).map_err(decode_err)? != bytes {
            return Err(err(DenyCode::NonCanonical, "order is not in deterministic CBOR form"));
        }
        let Value::Map(entries) = value else {
            return Err(decode_err("order must be a CBOR map"));
        };
        let mut fields: [Option<Value>; 19] = Default::default();
        for (k, v) in entries {
            let k = match k {
                Value::Integer(i) => u64::try_from(i).ok().filter(|k| (1..=18).contains(k)),
                _ => None,
            }
            .ok_or_else(|| decode_err("orders have exactly the keys 1..18"))?;
            fields[k as usize] = Some(v);
        }
        let mut take = |k: usize, name: &str| fields[k].take().ok_or_else(|| decode_err(format!("missing {name}")));
        if uint_of(take(1, "version")?)? != ORDER_VERSION {
            return Err(err(DenyCode::Version, "unsupported order version"));
        }
        let id = id16(take(2, "order id")?, "order id")?;
        let executor = id16(take(3, "executor")?, "executor")?;
        let subject = id16(take(4, "subject")?, "subject")?;
        let subject_digest = digest32(take(5, "subject digest")?, "subject digest")?;
        let actor = entity(take(6, "actor")?, "actor")?;
        let resource = entity(take(7, "resource")?, "resource")?;
        let device = entity(take(8, "device")?, "device")?;
        let capability = CapabilityId::parse(&text(take(9, "capability")?, "capability", 128)?)
            .map_err(|e| decode_err(e.to_string()))?;
        let capability_version = u32::try_from(uint_of(take(10, "capability version")?)?)
            .map_err(|_| decode_err("capability version out of range"))?;
        let params = fields[11].take().map(payload_of).transpose()?.unwrap_or_default();
        let mut take = |k: usize, name: &str| fields[k].take().ok_or_else(|| decode_err(format!("missing {name}")));
        let params_digest = digest32(take(12, "parameter digest")?, "parameter digest")?;
        let context_digest = digest32(take(13, "context digest")?, "context digest")?;
        let epoch = uint_of(take(14, "epoch")?)?;
        let evidence_seq = uint_of(take(15, "evidence")?)?;
        let cleared_at_ms = uint_of(take(16, "cleared at")?)?;
        let issued_at_ms = uint_of(take(17, "issued at")?)?;
        let expires_at_ms = uint_of(take(18, "expires at")?)?;
        Ok(Self {
            id,
            executor,
            subject,
            subject_digest,
            actor,
            resource,
            device,
            capability,
            capability_version,
            params,
            params_digest,
            context_digest,
            epoch,
            evidence_seq,
            cleared_at_ms,
            issued_at_ms,
            expires_at_ms,
        })
    }

    /// Parse, require the pinned order key, verify the signature, decode and
    /// check that the parameters match their digest. Executor binding,
    /// freshness and single use are the caller's job (it owns the session, the
    /// clock and the replay set).
    pub fn open(bytes: &[u8], order_key: &PublicKey) -> Result<Self, DecodeError> {
        let env = SignedEnvelope::parse_as(bytes, ORDER_CONTENT_TYPE)?;
        if env.key_id() != &key_id_of(order_key) {
            return Err(err(DenyCode::UnknownKey, "order is not signed by the pinned order key"));
        }
        env.verify(order_key)?;
        let order = Self::from_cbor(env.payload())?;
        if payload_digest(&order.params) != order.params_digest {
            return Err(decode_err("order parameters do not match their digest"));
        }
        Ok(order)
    }
}

/// What an adapter host reports after executing an order: bound to the exact
/// order bytes it executed, to its own executor session and to the state it
/// reports. A receipt that does not match the order is not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReceipt {
    pub order: [u8; ID_LEN],
    /// SHA-256 of the signed order bytes as received.
    pub order_digest: Digest32,
    pub executor: [u8; ID_LEN],
    pub device: EntityId,
    pub capability: CapabilityId,
    pub executed_at_ms: u64,
    /// [`payload_digest`] of the reported state.
    pub state_digest: Digest32,
}

impl ExecutionReceipt {
    /// The receipt for `order` (received as `order_bytes`) that produced `state`.
    pub fn for_order(order: &ExecOrder, order_bytes: &[u8], state: &Payload, executed_at_ms: u64) -> Self {
        Self {
            order: order.id,
            order_digest: message_digest(order_bytes),
            executor: order.executor,
            device: order.device.clone(),
            capability: order.capability.clone(),
            executed_at_ms,
            state_digest: payload_digest(state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Csme;
    use chitala_identity::test_seed;
    use chitala_model::{payload, MessageType, RiskClass};

    fn key() -> Keypair {
        Keypair::from_seed(&test_seed("boundary"))
    }

    fn sample() -> ExecOrder {
        let params = payload([("brightness_pct", 30i64)]);
        ExecOrder {
            id: [7; 16],
            executor: [9; 16],
            subject: [3; 16],
            subject_digest: [4; 32],
            actor: EntityId::parse("ai:assistant").unwrap(),
            resource: EntityId::parse("resource:living-room-light").unwrap(),
            device: EntityId::parse("device:living-room-light").unwrap(),
            capability: CapabilityId::parse("light.set_brightness").unwrap(),
            capability_version: 1,
            params_digest: payload_digest(&params),
            params,
            context_digest: [5; 32],
            epoch: 2,
            evidence_seq: 11,
            cleared_at_ms: 999,
            issued_at_ms: 1_000,
            expires_at_ms: 11_000,
        }
    }

    #[test]
    fn round_trip_and_key_pinning() {
        let bytes = sample().sign(&key());
        assert_eq!(ExecOrder::open(&bytes, &key().public_key()).unwrap(), sample());
        let other = Keypair::from_seed(&test_seed("service:other"));
        assert_eq!(ExecOrder::open(&bytes, &other.public_key()).unwrap_err().code, DenyCode::UnknownKey);
        // an order signed by another key but claiming the pinned kid fails the signature
        let forged = sample().sign(&other);
        assert!(ExecOrder::open(&forged, &key().public_key()).is_err());
    }

    #[test]
    fn parameters_must_match_their_digest() {
        let mut o = sample();
        o.params = payload([("brightness_pct", 100i64)]);
        let bytes = o.sign(&key());
        assert!(ExecOrder::open(&bytes, &key().public_key()).is_err(), "params changed after the digest");
    }

    #[test]
    fn a_request_signature_is_never_an_order() {
        // even a CSME signed by the order key itself is not an order (content type)
        let csme = Csme {
            message_id: [7; 16],
            correlation_id: None,
            source: EntityId::parse("service:node").unwrap(),
            destination: EntityId::parse("device:living-room-light").unwrap(),
            actor: EntityId::parse("service:node").unwrap(),
            capability: CapabilityId::parse("light.turn_on").unwrap(),
            capability_version: 1,
            message_type: MessageType::Command,
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
            context_ref: None,
            authority: None,
            risk: RiskClass::Low,
            payload: Payload::new(),
        };
        let bytes = csme.sign(&key());
        assert!(ExecOrder::open(&bytes, &key().public_key()).is_err());
        // and an order is never a CSME
        assert!(crate::open(&sample().sign(&key()), &key().public_key()).is_err());
    }

    #[test]
    fn strict_decoding() {
        let mut body = sample().to_cbor();
        body.push(0);
        assert_eq!(ExecOrder::from_cbor(&body).unwrap_err().code, DenyCode::NonCanonical);
        let Value::Map(mut m) = sample().to_value() else { unreachable!() };
        m.push((uint(19), uint(1)));
        let extra = encode_deterministic(&Value::Map(m)).unwrap();
        assert!(ExecOrder::from_cbor(&extra).is_err(), "unknown keys are rejected in orders");
        let Value::Map(mut m) = sample().to_value() else { unreachable!() };
        m[0] = (uint(1), uint(1));
        let v1 = encode_deterministic(&Value::Map(m)).unwrap();
        assert_eq!(ExecOrder::from_cbor(&v1).unwrap_err().code, DenyCode::Version, "version 1 orders are refused");
    }

    #[test]
    fn receipts_bind_the_exact_order_and_state() {
        let bytes = sample().sign(&key());
        let state = payload([("on", true)]);
        let r = ExecutionReceipt::for_order(&sample(), &bytes, &state, 1_500);
        assert_eq!(r.order, sample().id);
        assert_eq!(r.executor, sample().executor);
        assert_eq!(r.order_digest, message_digest(&bytes));
        assert_eq!(r.state_digest, payload_digest(&state));
        assert_ne!(r.state_digest, payload_digest(&payload([("on", false)])));
    }
}
