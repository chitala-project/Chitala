//! Execution orders: the boundary between the trusted core and the adapter host
//! (spec `specs/10-twin-and-events.md` §"Cô lập adapter", Blueprint A.3, v8 §12).
//!
//! When the Reference Monitor allows a device action, the node turns it into an
//! order signed with the **node key** and hands it to the adapter host, a separate
//! process. The adapter host executes only orders that
//!
//! - carry content type `application/chitala-order` (a CSME or any other Chitala
//!   signature can never be replayed as an order),
//! - are signed by the node key pinned at start-up,
//! - are fresh (`decided_at ≤ now + skew`, `now < expires_at`, lifetime ≤ 30 s) and
//! - have not been executed before (single use, checked by the adapter host).
//!
//! The order body is a deterministic-CBOR map:
//!
//! | key | field | type |
//! |----:|-------|------|
//! | 1 | version (= 1) | uint |
//! | 2 | order id = message id of the authorizing request | bstr(16) |
//! | 3 | actor | tstr |
//! | 4 | target device | tstr |
//! | 5 | capability | tstr |
//! | 6 | capability version | uint |
//! | 7 | decided at (ms) | uint |
//! | 8 | expires at (ms) | uint |
//! | 9 | payload (omitted when empty) | map |

use chitala_identity::{key_id_of, Keypair, PublicKey};
use chitala_model::{CapabilityId, DenyCode, EntityId, Payload};
use ciborium::value::Value;

use crate::{
    decode_err, encode_deterministic, entity, err, id16, payload_of, payload_value, sign_payload_as, text, uint,
    uint_of, DecodeError, SignedEnvelope, ID_LEN,
};

pub const ORDER_CONTENT_TYPE: &str = "application/chitala-order";
pub const ORDER_VERSION: u64 = 1;
/// Default validity of an order after the decision.
pub const ORDER_TTL_MS: u64 = 10_000;
/// Longest lifetime an adapter host accepts.
pub const MAX_ORDER_LIFETIME_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOrder {
    pub id: [u8; ID_LEN],
    pub actor: EntityId,
    pub target: EntityId,
    pub capability: CapabilityId,
    pub capability_version: u32,
    pub decided_at_ms: u64,
    pub expires_at_ms: u64,
    pub payload: Payload,
}

impl ExecOrder {
    fn to_value(&self) -> Value {
        let mut m = vec![
            (uint(1), uint(ORDER_VERSION)),
            (uint(2), Value::Bytes(self.id.to_vec())),
            (uint(3), Value::Text(self.actor.to_string())),
            (uint(4), Value::Text(self.target.to_string())),
            (uint(5), Value::Text(self.capability.to_string())),
            (uint(6), uint(self.capability_version as u64)),
            (uint(7), uint(self.decided_at_ms)),
            (uint(8), uint(self.expires_at_ms)),
        ];
        if !self.payload.is_empty() {
            m.push((uint(9), payload_value(&self.payload)));
        }
        Value::Map(m)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        encode_deterministic(&self.to_value()).expect("an order is always encodable")
    }

    /// Sign with the node key.
    pub fn sign(&self, node_key: &Keypair) -> Vec<u8> {
        sign_payload_as(self.to_cbor(), node_key, ORDER_CONTENT_TYPE)
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
        let mut fields: [Option<Value>; 10] = Default::default();
        for (k, v) in entries {
            let k = match k {
                Value::Integer(i) => u64::try_from(i).ok().filter(|k| (1..=9).contains(k)),
                _ => None,
            }
            .ok_or_else(|| decode_err("orders have exactly the keys 1..9"))?;
            fields[k as usize] = Some(v);
        }
        let mut take = |k: usize, name: &str| fields[k].take().ok_or_else(|| decode_err(format!("missing {name}")));
        if uint_of(take(1, "version")?)? != ORDER_VERSION {
            return Err(err(DenyCode::Version, "unsupported order version"));
        }
        let id = id16(take(2, "order id")?, "order id")?;
        let actor = entity(take(3, "actor")?, "actor")?;
        let target = entity(take(4, "target")?, "target")?;
        let capability = CapabilityId::parse(&text(take(5, "capability")?, "capability", 128)?)
            .map_err(|e| decode_err(e.to_string()))?;
        let capability_version = u32::try_from(uint_of(take(6, "capability version")?)?)
            .map_err(|_| decode_err("capability version out of range"))?;
        let decided_at_ms = uint_of(take(7, "decided at")?)?;
        let expires_at_ms = uint_of(take(8, "expires at")?)?;
        let payload = fields[9].take().map(payload_of).transpose()?.unwrap_or_default();
        Ok(Self { id, actor, target, capability, capability_version, decided_at_ms, expires_at_ms, payload })
    }

    /// Parse, require the pinned node key, verify, decode. Freshness and single
    /// use are the caller's job (it owns the clock and the replay set).
    pub fn open(bytes: &[u8], node_key: &PublicKey) -> Result<Self, DecodeError> {
        let env = SignedEnvelope::parse_as(bytes, ORDER_CONTENT_TYPE)?;
        if env.key_id() != &key_id_of(node_key) {
            return Err(err(DenyCode::UnknownKey, "order is not signed by the pinned node key"));
        }
        env.verify(node_key)?;
        Self::from_cbor(env.payload())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Csme;
    use chitala_identity::test_seed;
    use chitala_model::{payload, MessageType, RiskClass};

    fn node() -> Keypair {
        Keypair::from_seed(&test_seed("service:node"))
    }

    fn sample() -> ExecOrder {
        ExecOrder {
            id: [7; 16],
            actor: EntityId::parse("ai:assistant").unwrap(),
            target: EntityId::parse("device:living-room-light").unwrap(),
            capability: CapabilityId::parse("light.set_brightness").unwrap(),
            capability_version: 1,
            decided_at_ms: 1_000,
            expires_at_ms: 11_000,
            payload: payload([("brightness_pct", 30i64)]),
        }
    }

    #[test]
    fn round_trip_and_key_pinning() {
        let bytes = sample().sign(&node());
        assert_eq!(ExecOrder::open(&bytes, &node().public_key()).unwrap(), sample());
        let other = Keypair::from_seed(&test_seed("service:other"));
        assert_eq!(ExecOrder::open(&bytes, &other.public_key()).unwrap_err().code, DenyCode::UnknownKey);
        // an order signed by another key but claiming the node's kid fails the signature
        let forged = sample().sign(&other);
        assert!(ExecOrder::open(&forged, &node().public_key()).is_err());
    }

    #[test]
    fn a_request_signature_is_never_an_order() {
        // even a CSME signed by the node key itself is not an order (content type)
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
        let bytes = csme.sign(&node());
        assert!(ExecOrder::open(&bytes, &node().public_key()).is_err());
        // and an order is never a CSME
        assert!(crate::open(&sample().sign(&node()), &node().public_key()).is_err());
    }

    #[test]
    fn strict_decoding() {
        let mut body = sample().to_cbor();
        body.push(0);
        assert_eq!(ExecOrder::from_cbor(&body).unwrap_err().code, DenyCode::NonCanonical);
        let Value::Map(mut m) = sample().to_value() else { unreachable!() };
        m.push((uint(10), uint(1)));
        let extra = encode_deterministic(&Value::Map(m)).unwrap();
        assert!(ExecOrder::from_cbor(&extra).is_err(), "unknown keys are rejected in orders");
    }
}
