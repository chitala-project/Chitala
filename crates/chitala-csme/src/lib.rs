//! Chitala Secure Message Envelope v1 (spec `specs/07-csme.md`, Blueprint v4 §3).
//!
//! Wire form: a tagged `COSE_Sign1` (RFC 9052) whose protected header carries
//! `alg = Ed25519 (-19)`, `content type = "application/chitala-csme"` and the 16-byte
//! key id of the signer. The payload is a deterministic-CBOR map with integer keys:
//!
//! | key | field | type |
//! |----:|-------|------|
//! | 1 | protocol version | uint (= 1) |
//! | 2 | message id (also the anti-replay nonce) | bstr(16) |
//! | 3 | correlation id | bstr(16), optional |
//! | 4 | source endpoint | tstr entity id |
//! | 5 | destination / target | tstr entity id |
//! | 6 | actor (MUST be the signer) | tstr entity id |
//! | 7 | capability id | tstr |
//! | 8 | capability version | uint |
//! | 9 | message type | uint |
//! | 10 | issued at (ms) | uint |
//! | 11 | expires at (ms) | uint |
//! | 12 | context ref | tstr ≤ 128, optional |
//! | 13 | authority ref (capability token) | bstr, optional |
//! | 14 | risk (safety class) | uint |
//! | 15 | payload | map tstr → bool/int/tstr, omitted when empty |
//! | 16 | critical extensions | array of uint, optional |
//!
//! Unknown keys are ignored unless listed in key 16, in which case the envelope is
//! rejected (`E_CRITICAL_EXT`): optional extensions degrade gracefully, critical
//! ones fail closed (v4 §7).
//!
//! The signature is verified *before* the payload is parsed, so the CBOR parser
//! never sees bytes from an unauthenticated sender.

#![forbid(unsafe_code)]

use chitala_identity::{verify, KeyId, Keypair, PublicKey, KEY_ID_LEN};
use chitala_model::{CapabilityId, DenyCode, EntityId, MessageType, ParamValue, Payload, RiskClass};
use ciborium::value::{Integer, Value};
use coset::{iana, CoseSign1, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use rand::RngCore;

pub mod order;

pub const CSME_VERSION: u64 = 1;
pub const CONTENT_TYPE: &str = "application/chitala-csme";
pub const ID_LEN: usize = 16;
/// Whole COSE structure.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
pub const MAX_CONTEXT_LEN: usize = 128;
pub const MAX_AUTHORITY_BYTES: usize = 4096;
pub const MAX_PAYLOAD_ENTRIES: usize = 32;
pub const MAX_PARAM_NAME_LEN: usize = 64;
pub const MAX_TEXT_LEN: usize = 4096;
const MAX_DEPTH: usize = 8;

/// Integer keys of the CSME map.
pub mod key {
    pub const VERSION: u64 = 1;
    pub const MESSAGE_ID: u64 = 2;
    pub const CORRELATION_ID: u64 = 3;
    pub const SOURCE: u64 = 4;
    pub const DESTINATION: u64 = 5;
    pub const ACTOR: u64 = 6;
    pub const CAPABILITY: u64 = 7;
    pub const CAPABILITY_VERSION: u64 = 8;
    pub const MESSAGE_TYPE: u64 = 9;
    pub const ISSUED_AT: u64 = 10;
    pub const EXPIRES_AT: u64 = 11;
    pub const CONTEXT_REF: u64 = 12;
    pub const AUTHORITY: u64 = 13;
    pub const RISK: u64 = 14;
    pub const PAYLOAD: u64 = 15;
    pub const CRITICAL: u64 = 16;
    pub const MAX_KNOWN: u64 = 16;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct DecodeError {
    pub code: DenyCode,
    pub reason: String,
}

pub(crate) fn err(code: DenyCode, reason: impl Into<String>) -> DecodeError {
    DecodeError { code, reason: reason.into() }
}

pub(crate) fn decode_err(reason: impl Into<String>) -> DecodeError {
    err(DenyCode::Decode, reason)
}

/// A fresh random 128-bit message id.
pub fn new_message_id() -> [u8; ID_LEN] {
    let mut id = [0u8; ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Csme {
    pub message_id: [u8; ID_LEN],
    pub correlation_id: Option<[u8; ID_LEN]>,
    pub source: EntityId,
    pub destination: EntityId,
    pub actor: EntityId,
    pub capability: CapabilityId,
    pub capability_version: u32,
    pub message_type: MessageType,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub context_ref: Option<String>,
    pub authority: Option<Vec<u8>>,
    pub risk: RiskClass,
    pub payload: Payload,
}

// ───────────────────────── deterministic CBOR ─────────────────────────

fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// Encode `v` in RFC 8949 §4.2.1 core deterministic form. Only the subset used by
/// CSME is accepted: integers, byte/text strings, arrays, maps and booleans.
/// Map keys are sorted by their encoded bytes; duplicate keys are an error.
pub fn encode_deterministic(v: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    encode_into(v, &mut out, 0)?;
    Ok(out)
}

fn encode_into(v: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("nesting too deep".into());
    }
    match v {
        Value::Integer(i) => {
            let i: i128 = (*i).into();
            if i >= 0 {
                write_head(out, 0, u64::try_from(i).map_err(|_| "integer out of range")?);
            } else {
                write_head(out, 1, u64::try_from(-1 - i).map_err(|_| "integer out of range")?);
            }
        }
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            write_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let mut kb = Vec::new();
                encode_into(k, &mut kb, depth + 1)?;
                let mut vb = Vec::new();
                encode_into(v, &mut vb, depth + 1)?;
                encoded.push((kb, vb));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err("duplicate map key".into());
            }
            write_head(out, 5, encoded.len() as u64);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Float(_) => return Err("floating point values are not allowed".into()),
        Value::Null => return Err("null is not allowed".into()),
        Value::Tag(..) => return Err("tags are not allowed".into()),
        _ => return Err("unsupported CBOR item".into()),
    }
    Ok(())
}

pub(crate) fn uint(n: u64) -> Value {
    Value::Integer(Integer::from(n))
}

pub(crate) fn payload_value(p: &Payload) -> Value {
    Value::Map(
        p.iter()
            .map(|(k, v)| {
                let v = match v {
                    ParamValue::Bool(b) => Value::Bool(*b),
                    ParamValue::Int(i) => Value::Integer(Integer::from(*i)),
                    ParamValue::Text(t) => Value::Text(t.clone()),
                };
                (Value::Text(k.clone()), v)
            })
            .collect(),
    )
}

// ───────────────────────────── encoding ─────────────────────────────

impl Csme {
    fn to_value(&self) -> Value {
        let mut m: Vec<(Value, Value)> = vec![
            (uint(key::VERSION), uint(CSME_VERSION)),
            (uint(key::MESSAGE_ID), Value::Bytes(self.message_id.to_vec())),
            (uint(key::SOURCE), Value::Text(self.source.to_string())),
            (uint(key::DESTINATION), Value::Text(self.destination.to_string())),
            (uint(key::ACTOR), Value::Text(self.actor.to_string())),
            (uint(key::CAPABILITY), Value::Text(self.capability.to_string())),
            (uint(key::CAPABILITY_VERSION), uint(self.capability_version as u64)),
            (uint(key::MESSAGE_TYPE), uint(self.message_type.code() as u64)),
            (uint(key::ISSUED_AT), uint(self.issued_at_ms)),
            (uint(key::EXPIRES_AT), uint(self.expires_at_ms)),
            (uint(key::RISK), uint(self.risk.code() as u64)),
        ];
        if let Some(cid) = self.correlation_id {
            m.push((uint(key::CORRELATION_ID), Value::Bytes(cid.to_vec())));
        }
        if let Some(ctx) = &self.context_ref {
            m.push((uint(key::CONTEXT_REF), Value::Text(ctx.clone())));
        }
        if let Some(auth) = &self.authority {
            m.push((uint(key::AUTHORITY), Value::Bytes(auth.clone())));
        }
        if !self.payload.is_empty() {
            m.push((uint(key::PAYLOAD), payload_value(&self.payload)));
        }
        Value::Map(m)
    }

    /// Canonical CBOR bytes of the envelope body (the COSE payload).
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_deterministic(&self.to_value()).expect("a Csme is always encodable")
    }

    /// Sign with the actor's key and return the tagged `COSE_Sign1` bytes.
    pub fn sign(&self, signer: &Keypair) -> Vec<u8> {
        sign_payload(self.to_cbor(), signer)
    }

    /// Parse and validate the canonical CBOR body.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let value: Value = ciborium::de::from_reader_with_recursion_limit(bytes, MAX_DEPTH)
            .map_err(|e| decode_err(format!("CBOR: {e}")))?;
        let canonical = encode_deterministic(&value).map_err(decode_err)?;
        if canonical != bytes {
            return Err(err(DenyCode::NonCanonical, "envelope is not in deterministic CBOR form"));
        }
        let Value::Map(entries) = value else {
            return Err(decode_err("envelope must be a CBOR map"));
        };

        let mut fields: [Option<Value>; key::MAX_KNOWN as usize + 1] = Default::default();
        for (k, v) in entries {
            let k: u64 = match k {
                Value::Integer(i) => u64::try_from(i).map_err(|_| decode_err("negative map key"))?,
                _ => return Err(decode_err("map keys must be unsigned integers")),
            };
            if (1..=key::MAX_KNOWN).contains(&k) {
                fields[k as usize] = Some(v);
            }
            // unknown keys: ignored unless marked critical (checked below)
        }

        match fields[key::VERSION as usize].take() {
            Some(Value::Integer(i)) if u64::try_from(i) == Ok(CSME_VERSION) => {}
            Some(_) => return Err(err(DenyCode::Version, "unsupported protocol version")),
            None => return Err(err(DenyCode::Version, "missing protocol version")),
        }
        if let Some(crit) = fields[key::CRITICAL as usize].take() {
            let Value::Array(items) = crit else {
                return Err(decode_err("critical extensions must be an array"));
            };
            for item in items {
                let k = match item {
                    Value::Integer(i) => u64::try_from(i).map_err(|_| decode_err("bad critical key"))?,
                    _ => return Err(decode_err("bad critical key")),
                };
                if !(1..=key::MAX_KNOWN).contains(&k) {
                    return Err(err(DenyCode::CriticalExtension, format!("unknown critical extension {k}")));
                }
            }
        }

        let mut take = |k: u64| fields[k as usize].take();
        let need = |v: Option<Value>, name: &str| v.ok_or_else(|| decode_err(format!("missing {name}")));

        let message_id = id16(need(take(key::MESSAGE_ID), "message id")?, "message id")?;
        let correlation_id = take(key::CORRELATION_ID).map(|v| id16(v, "correlation id")).transpose()?;
        let source = entity(need(take(key::SOURCE), "source")?, "source")?;
        let destination = entity(need(take(key::DESTINATION), "destination")?, "destination")?;
        let actor = entity(need(take(key::ACTOR), "actor")?, "actor")?;
        let capability = CapabilityId::parse(&text(need(take(key::CAPABILITY), "capability")?, "capability", 128)?)
            .map_err(|e| decode_err(e.to_string()))?;
        let capability_version = u32::try_from(uint_of(need(take(key::CAPABILITY_VERSION), "capability version")?)?)
            .map_err(|_| decode_err("capability version out of range"))?;
        let typ = uint_of(need(take(key::MESSAGE_TYPE), "message type")?)?;
        let message_type = MessageType::from_code(typ)
            .ok_or_else(|| err(DenyCode::UnsupportedType, format!("unknown message type {typ}")))?;
        let issued_at_ms = uint_of(need(take(key::ISSUED_AT), "issued at")?)?;
        let expires_at_ms = uint_of(need(take(key::EXPIRES_AT), "expires at")?)?;
        let context_ref = take(key::CONTEXT_REF).map(|v| text(v, "context ref", MAX_CONTEXT_LEN)).transpose()?;
        let authority = take(key::AUTHORITY)
            .map(|v| match v {
                Value::Bytes(b) if !b.is_empty() && b.len() <= MAX_AUTHORITY_BYTES => Ok(b),
                _ => Err(decode_err("authority ref must be a non-empty byte string ≤ 4096 bytes")),
            })
            .transpose()?;
        let risk_code = uint_of(need(take(key::RISK), "risk")?)?;
        let risk =
            RiskClass::from_code(risk_code).ok_or_else(|| decode_err(format!("unknown risk class {risk_code}")))?;
        let payload = take(key::PAYLOAD).map(payload_of).transpose()?.unwrap_or_default();

        Ok(Csme {
            message_id,
            correlation_id,
            source,
            destination,
            actor,
            capability,
            capability_version,
            message_type,
            issued_at_ms,
            expires_at_ms,
            context_ref,
            authority,
            risk,
            payload,
        })
    }
}

pub(crate) fn id16(v: Value, name: &str) -> Result<[u8; ID_LEN], DecodeError> {
    match v {
        Value::Bytes(b) if b.len() == ID_LEN => Ok(b.try_into().expect("length checked")),
        _ => Err(decode_err(format!("{name} must be a {ID_LEN}-byte string"))),
    }
}

pub(crate) fn text(v: Value, name: &str, max: usize) -> Result<String, DecodeError> {
    match v {
        Value::Text(t) if t.chars().count() <= max => Ok(t),
        Value::Text(_) => Err(decode_err(format!("{name} longer than {max} characters"))),
        _ => Err(decode_err(format!("{name} must be a text string"))),
    }
}

pub(crate) fn entity(v: Value, name: &str) -> Result<EntityId, DecodeError> {
    EntityId::parse(&text(v, name, 200)?).map_err(|e| decode_err(format!("{name}: {e}")))
}

pub(crate) fn uint_of(v: Value) -> Result<u64, DecodeError> {
    match v {
        Value::Integer(i) => u64::try_from(i).map_err(|_| decode_err("expected an unsigned integer")),
        _ => Err(decode_err("expected an unsigned integer")),
    }
}

pub(crate) fn payload_of(v: Value) -> Result<Payload, DecodeError> {
    let Value::Map(entries) = v else {
        return Err(decode_err("payload must be a map"));
    };
    if entries.len() > MAX_PAYLOAD_ENTRIES {
        return Err(decode_err("too many payload entries"));
    }
    let mut out = Payload::new();
    for (k, v) in entries {
        let k = text(k, "parameter name", MAX_PARAM_NAME_LEN)?;
        let v = match v {
            Value::Bool(b) => ParamValue::Bool(b),
            Value::Integer(i) => {
                ParamValue::Int(i64::try_from(i).map_err(|_| decode_err(format!("{k}: integer out of range")))?)
            }
            Value::Text(t) if t.len() <= MAX_TEXT_LEN => ParamValue::Text(t),
            _ => return Err(decode_err(format!("{k}: payload values must be bool, int or text"))),
        };
        out.insert(k, v);
    }
    Ok(out)
}

// ───────────────────────────── COSE ─────────────────────────────

fn sign_payload(payload: Vec<u8>, signer: &Keypair) -> Vec<u8> {
    sign_payload_as(payload, signer, CONTENT_TYPE)
}

/// COSE_Sign1 (Ed25519) with an explicit content type. Distinct content types
/// keep signatures of different message kinds from being reinterpreted (v4 §14).
pub(crate) fn sign_payload_as(payload: Vec<u8>, signer: &Keypair, content_type: &str) -> Vec<u8> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::Ed25519)
        .content_type(content_type.to_string())
        .key_id(signer.key_id().to_vec())
        .build();
    CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |tbs| signer.sign(tbs).to_vec())
        .build()
        .to_tagged_vec()
        .expect("COSE_Sign1 is always encodable")
}

/// A parsed `COSE_Sign1` whose signature has not been checked yet.
#[derive(Debug, Clone)]
pub struct SignedEnvelope {
    key_id: KeyId,
    cose: CoseSign1,
}

impl SignedEnvelope {
    /// Structural checks only: size, COSE shape, protected header.
    pub fn parse(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::parse_as(bytes, CONTENT_TYPE)
    }

    /// [`SignedEnvelope::parse`] for another Chitala message kind.
    pub fn parse_as(bytes: &[u8], content_type: &str) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(decode_err(format!("envelope larger than {MAX_ENVELOPE_BYTES} bytes")));
        }
        let cose = CoseSign1::from_tagged_slice(bytes).map_err(|e| decode_err(format!("COSE: {e:?}")))?;
        let h = &cose.protected.header;
        if h.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::Ed25519)) {
            return Err(err(DenyCode::Algorithm, "alg must be Ed25519 (-19)"));
        }
        if !h.crit.is_empty() {
            return Err(err(DenyCode::CriticalExtension, "critical COSE header parameters are not supported"));
        }
        if h.content_type != Some(coset::ContentType::Text(content_type.to_string())) {
            return Err(decode_err(format!("content type must be {content_type}")));
        }
        if !h.rest.is_empty() || !h.iv.is_empty() || !h.partial_iv.is_empty() || !h.counter_signatures.is_empty() {
            return Err(decode_err("unexpected protected header parameters"));
        }
        if !cose.unprotected.is_empty() {
            return Err(decode_err("unprotected header must be empty"));
        }
        let key_id: KeyId =
            h.key_id.as_slice().try_into().map_err(|_| decode_err(format!("kid must be {KEY_ID_LEN} bytes")))?;
        if cose.payload.is_none() {
            return Err(decode_err("detached payloads are not supported"));
        }
        Ok(Self { key_id, cose })
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Verify the Ed25519 signature over the COSE `Sig_structure`.
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), DecodeError> {
        self.cose
            .verify_signature(b"", |sig, data| if verify(public_key, data, sig) { Ok(()) } else { Err(()) })
            .map_err(|_| err(DenyCode::BadSignature, "signature verification failed"))
    }

    /// Payload bytes. Only parse them after [`SignedEnvelope::verify`] succeeded.
    pub fn payload(&self) -> &[u8] {
        self.cose.payload.as_deref().unwrap_or_default()
    }
}

/// Parse, verify against `public_key`, then decode — for clients and tests that
/// already know the signer. The Reference Monitor runs these steps itself.
pub fn open(bytes: &[u8], public_key: &PublicKey) -> Result<Csme, DecodeError> {
    let env = SignedEnvelope::parse(bytes)?;
    env.verify(public_key)?;
    Csme::from_cbor(env.payload())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_identity::test_seed;
    use chitala_model::payload;

    fn alice() -> Keypair {
        Keypair::from_seed(&test_seed("person:alice"))
    }

    fn sample() -> Csme {
        Csme {
            message_id: [0x11; 16],
            correlation_id: None,
            source: EntityId::parse("service:cli").unwrap(),
            destination: EntityId::parse("device:living-room-light").unwrap(),
            actor: EntityId::parse("person:alice").unwrap(),
            capability: CapabilityId::parse("light.set_brightness").unwrap(),
            capability_version: 1,
            message_type: MessageType::Command,
            issued_at_ms: 1_790_000_000_000,
            expires_at_ms: 1_790_000_030_000,
            context_ref: Some("task:42".into()),
            authority: None,
            risk: RiskClass::Low,
            payload: payload([("brightness_pct", 40i64)]),
        }
    }

    /// Rebuild a COSE_Sign1 around arbitrary payload bytes (to test the decoder).
    fn resign(body: Vec<u8>) -> Vec<u8> {
        sign_payload(body, &alice())
    }

    fn body_with(extra: Vec<(Value, Value)>, drop: &[u64]) -> Vec<u8> {
        let Value::Map(mut m) = sample().to_value() else { unreachable!() };
        m.retain(|(k, _)| !drop.iter().any(|d| *k == uint(*d)));
        m.extend(extra);
        encode_deterministic(&Value::Map(m)).unwrap()
    }

    #[test]
    fn sign_open_round_trip() {
        let msg = sample();
        let bytes = msg.sign(&alice());
        assert_eq!(open(&bytes, &alice().public_key()).unwrap(), msg);
        let env = SignedEnvelope::parse(&bytes).unwrap();
        assert_eq!(env.key_id(), &alice().key_id());
        // Ed25519 is deterministic: same message, same bytes
        assert_eq!(bytes, msg.sign(&alice()));
    }

    #[test]
    fn wrong_key_or_tampering_fails() {
        let bytes = sample().sign(&alice());
        let bob = Keypair::from_seed(&test_seed("person:bob"));
        assert_eq!(open(&bytes, &bob.public_key()).unwrap_err().code, DenyCode::BadSignature);
        // flip one bit in the payload region
        let mut t = bytes.clone();
        let pos = t.len() - 70;
        t[pos] ^= 1;
        let code = open(&t, &alice().public_key()).unwrap_err().code;
        assert!(matches!(code, DenyCode::BadSignature | DenyCode::Decode), "{code}");
    }

    #[test]
    fn structural_rejections() {
        assert_eq!(SignedEnvelope::parse(b"\x00").unwrap_err().code, DenyCode::Decode);
        assert_eq!(SignedEnvelope::parse(&vec![0u8; MAX_ENVELOPE_BYTES + 1]).unwrap_err().code, DenyCode::Decode);
        // EdDSA (-8, deprecated) is rejected in favour of fully-specified Ed25519
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .content_type(CONTENT_TYPE.to_string())
            .key_id(alice().key_id().to_vec())
            .build();
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(sample().to_cbor())
            .create_signature(b"", |tbs| alice().sign(tbs).to_vec())
            .build()
            .to_tagged_vec()
            .unwrap();
        assert_eq!(SignedEnvelope::parse(&cose).unwrap_err().code, DenyCode::Algorithm);
    }

    #[test]
    fn non_canonical_is_rejected() {
        // the same map with keys out of order
        let Value::Map(mut m) = sample().to_value() else { unreachable!() };
        let mut body = Vec::new();
        m.sort_by_key(|a| std::cmp::Reverse(a.0.as_integer()));
        ciborium::ser::into_writer(&Value::Map(m), &mut body).unwrap();
        let bytes = resign(body);
        assert_eq!(open(&bytes, &alice().public_key()).unwrap_err().code, DenyCode::NonCanonical);
        // trailing garbage after the map
        let mut body = sample().to_cbor();
        body.push(0x00);
        assert_eq!(open(&resign(body), &alice().public_key()).unwrap_err().code, DenyCode::NonCanonical);
        // a non-shortest integer: version 1 encoded as 0x18 0x01
        let canonical = sample().to_cbor();
        assert_eq!(&canonical[..3], &[0xad, 0x01, 0x01]); // map(13), key 1, value 1
        let mut long_int = vec![0xad, 0x01, 0x18, 0x01];
        long_int.extend_from_slice(&canonical[3..]);
        assert_eq!(open(&resign(long_int), &alice().public_key()).unwrap_err().code, DenyCode::NonCanonical);
    }

    #[test]
    fn version_and_extensions() {
        let pk = alice().public_key();
        let v2 = body_with(vec![(uint(key::VERSION), uint(2))], &[key::VERSION]);
        assert_eq!(open(&resign(v2), &pk).unwrap_err().code, DenyCode::Version);
        let missing = body_with(vec![], &[key::VERSION]);
        assert_eq!(open(&resign(missing), &pk).unwrap_err().code, DenyCode::Version);
        // unknown optional extension → ignored
        let ext = body_with(vec![(uint(1000), Value::Text("hello".into()))], &[]);
        assert_eq!(open(&resign(ext), &pk).unwrap(), sample());
        // the same extension marked critical → fail closed
        let crit = body_with(
            vec![(uint(1000), Value::Text("hello".into())), (uint(key::CRITICAL), Value::Array(vec![uint(1000)]))],
            &[],
        );
        assert_eq!(open(&resign(crit), &pk).unwrap_err().code, DenyCode::CriticalExtension);
        // critical marking of a known key is fine
        let known = body_with(vec![(uint(key::CRITICAL), Value::Array(vec![uint(key::RISK)]))], &[]);
        assert!(open(&resign(known), &pk).is_ok());
    }

    /// (extra entries, keys to drop, expected code)
    type Case = (Vec<(Value, Value)>, &'static [u64], DenyCode);

    #[test]
    fn field_validation() {
        let pk = alice().public_key();
        let cases: Vec<Case> = vec![
            (vec![], &[key::ACTOR], DenyCode::Decode),
            (vec![(uint(key::MESSAGE_TYPE), uint(99))], &[key::MESSAGE_TYPE], DenyCode::UnsupportedType),
            (vec![(uint(key::RISK), uint(9))], &[key::RISK], DenyCode::Decode),
            (vec![(uint(key::ACTOR), Value::Text("robot:x".into()))], &[key::ACTOR], DenyCode::Decode),
            (vec![(uint(key::MESSAGE_ID), Value::Bytes(vec![1; 8]))], &[key::MESSAGE_ID], DenyCode::Decode),
            (
                vec![(uint(key::PAYLOAD), Value::Map(vec![(Value::Text("x".into()), Value::Float(1.5))]))],
                &[key::PAYLOAD],
                DenyCode::Decode,
            ),
            (
                vec![(
                    uint(key::PAYLOAD),
                    Value::Map(vec![(Value::Text("x".into()), Value::Integer(Integer::from(u64::MAX)))]),
                )],
                &[key::PAYLOAD],
                DenyCode::Decode,
            ),
            (vec![(Value::Text("k".into()), uint(1))], &[], DenyCode::Decode),
        ];
        for (extra, drop, code) in cases {
            let body = match encode_deterministic(&{
                let Value::Map(mut m) = sample().to_value() else { unreachable!() };
                m.retain(|(k, _)| !drop.iter().any(|d| *k == uint(*d)));
                m.extend(extra.clone());
                Value::Map(m)
            }) {
                Ok(b) => b,
                Err(_) => continue, // floats cannot even be encoded deterministically
            };
            assert_eq!(open(&resign(body), &pk).unwrap_err().code, code, "{extra:?}");
        }
    }

    #[test]
    fn float_payload_is_rejected_by_decoder() {
        // hand-encode {15: {"x": 1.5}} merged into a valid body is impossible with our
        // encoder, so build the CBOR with ciborium and check the decoder's verdict
        let Value::Map(mut m) = sample().to_value() else { unreachable!() };
        m.retain(|(k, _)| *k != uint(key::PAYLOAD));
        m.push((uint(key::PAYLOAD), Value::Map(vec![(Value::Text("x".into()), Value::Float(1.5))])));
        m.sort_by_key(|a| a.0.as_integer());
        let mut body = Vec::new();
        ciborium::ser::into_writer(&Value::Map(m), &mut body).unwrap();
        assert_eq!(open(&resign(body), &alice().public_key()).unwrap_err().code, DenyCode::Decode);
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Arbitrary bytes never panic the parser and are never accepted.
            #[test]
            fn garbage_never_opens(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
                prop_assert!(open(&bytes, &alice().public_key()).is_err());
            }

            /// Arbitrary bodies signed by a valid key never panic the decoder.
            #[test]
            fn signed_garbage_never_panics(body in proptest::collection::vec(any::<u8>(), 0..256)) {
                let _ = open(&resign(body), &alice().public_key());
            }

            /// Encoding is a function of the message: decode(encode(m)) == m.
            #[test]
            fn round_trip(brightness in 0i64..=100, iat in 0u64..u64::MAX / 2, ttl in 1u64..60_000,
                          ctx in proptest::option::of("[a-z0-9:]{1,20}")) {
                let mut m = sample();
                m.payload = payload([("brightness_pct", brightness)]);
                m.issued_at_ms = iat;
                m.expires_at_ms = iat + ttl;
                m.context_ref = ctx;
                prop_assert_eq!(Csme::from_cbor(&m.to_cbor()).unwrap(), m);
            }
        }
    }
}
