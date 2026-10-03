//! Intents and human approvals (spec `specs/15-intent.md`).
//!
//! > **Invariant 1.** AI produces Intent. Chitala produces Authority. Only the
//! > trusted execution boundary produces physical Commands.
//!
//! An [`Intent`] is a *request for an outcome*:
//!
//! ```text
//! actor → on_behalf_of → action → resource → context → constraints → requested_at
//! ```
//!
//! It is deliberately not a command. It names a resource, never a device; it
//! carries no capability version, no declared risk and no execution lease. Risk
//! is computed by Chitala, the device is resolved by the resource binding, and
//! the physical command (a node-signed execution order) can only be minted by
//! the trusted boundary from an Authority grant plus a safety clearance. Intents
//! are signed with their own COSE content type, so an intent signature can never
//! be replayed as a CSME request or an execution order.
//!
//! An [`Approval`] is a human's signed answer to an escalated intent. It is bound
//! to the SHA-256 digest of the exact intent bytes it answers.
//!
//! Intent body (deterministic CBOR map, exactly these keys):
//!
//! | key | field | type |
//! |----:|-------|------|
//! | 1 | version (= 1) | uint |
//! | 2 | intent id | bstr(16) |
//! | 3 | actor (MUST be the signer) | tstr entity id |
//! | 4 | on behalf of (a person) | tstr entity id |
//! | 5 | action | tstr capability id |
//! | 6 | resource | tstr `resource:` id |
//! | 7 | params (omitted when empty) | map |
//! | 8 | context: purpose (data, never instructions) | tstr ≤ 280, optional |
//! | 9 | context: cause — the signed intent this one relays | bstr, optional |
//! | 10 | constraints: deadline (ms) | uint |
//! | 11 | constraints: max acceptable risk | uint, optional |
//! | 12 | constraints: no escalation (present only as `true`) | bool, optional |
//! | 13 | requested at (ms) | uint |
//! | 14 | authority: the actor's capability token | bstr, optional |

#![forbid(unsafe_code)]

use chitala_csme::{
    decode_err, encode_deterministic, entity, err, id16, new_message_id, payload_of, payload_value, sign_payload_as,
    text, uint, uint_of, DecodeError, SignedEnvelope, ID_LEN, MAX_AUTHORITY_BYTES, MAX_ENVELOPE_BYTES,
};
use chitala_identity::{KeyId, Keypair, PublicKey};
use chitala_model::{CapabilityId, DenyCode, EntityId, EntityKind, Payload, RiskClass};
use chitala_resource::ResourceId;
use ciborium::value::Value;
use sha2::{Digest as _, Sha256};

pub const INTENT_CONTENT_TYPE: &str = "application/chitala-intent";
pub const APPROVAL_CONTENT_TYPE: &str = "application/chitala-approval";
pub const INTENT_VERSION: u64 = 1;
pub const APPROVAL_VERSION: u64 = 1;
/// Longest `deadline - requested_at`: long enough for a human to answer an
/// escalation, short enough that a forgotten intent cannot fire next week.
pub const MAX_INTENT_LIFETIME_MS: u64 = 600_000;
pub const MAX_APPROVAL_LIFETIME_MS: u64 = 600_000;
pub const MAX_PURPOSE_LEN: usize = 280;
pub const MAX_NOTE_LEN: usize = 280;
/// Longest relay chain: the intent plus at most this many causes.
pub const MAX_CAUSE_DEPTH: usize = 3;

pub type IntentId = [u8; ID_LEN];
pub type Digest = [u8; 32];

/// Fresh random intent id.
pub fn new_intent_id() -> IntentId {
    new_message_id()
}

/// What the requester asks for beyond the outcome itself. Constraints only
/// ever narrow what Chitala may do; they never widen authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraints {
    /// After this instant the intent must not be executed (nor approved).
    pub deadline_ms: u64,
    /// Refuse instead of executing if Chitala rates the action above this.
    pub max_risk: Option<RiskClass>,
    /// Refuse instead of escalating to a human when approval is required.
    pub no_escalation: bool,
}

/// The situation an intent arises in. Content is data, never instructions:
/// nothing in the context can grant authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntentContext {
    /// Why, in the requester's words; recorded for humans and audit only.
    pub purpose: Option<String>,
    /// The signed intent this one relays (agent-to-agent hand-off). Chitala
    /// evaluates the whole chain: a relayed intent never has more authority
    /// than any link of it.
    pub cause: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub id: IntentId,
    pub actor: EntityId,
    pub on_behalf_of: EntityId,
    pub action: CapabilityId,
    pub resource: ResourceId,
    pub params: Payload,
    pub context: IntentContext,
    pub constraints: Constraints,
    pub requested_at_ms: u64,
    /// The actor's capability token (absent for persons acting for themselves).
    pub authority: Option<Vec<u8>>,
}

fn sha256(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

fn reject(reason: impl Into<String>) -> DecodeError {
    decode_err(reason)
}

/// Read a deterministic-CBOR map whose keys are exactly within `1..=max`.
fn strict_map(bytes: &[u8], what: &str, max: u64) -> Result<Vec<Option<Value>>, DecodeError> {
    let value: Value =
        ciborium::de::from_reader_with_recursion_limit(bytes, 8).map_err(|e| decode_err(format!("CBOR: {e}")))?;
    if encode_deterministic(&value).map_err(decode_err)? != bytes {
        return Err(err(DenyCode::NonCanonical, format!("{what} is not in deterministic CBOR form")));
    }
    let Value::Map(entries) = value else {
        return Err(decode_err(format!("{what} must be a CBOR map")));
    };
    let mut fields: Vec<Option<Value>> = vec![None; max as usize + 1];
    for (k, v) in entries {
        let k = match k {
            Value::Integer(i) => u64::try_from(i).ok().filter(|k| (1..=max).contains(k)),
            _ => None,
        }
        .ok_or_else(|| decode_err(format!("{what} has exactly the keys 1..{max}")))?;
        fields[k as usize] = Some(v);
    }
    Ok(fields)
}

fn bytes_field(v: Value, name: &str, max: usize) -> Result<Vec<u8>, DecodeError> {
    match v {
        Value::Bytes(b) if !b.is_empty() && b.len() <= max => Ok(b),
        _ => Err(decode_err(format!("{name} must be a non-empty byte string ≤ {max} bytes"))),
    }
}

fn risk_of(v: Value) -> Result<RiskClass, DecodeError> {
    let code = uint_of(v)?;
    RiskClass::from_code(code).ok_or_else(|| decode_err(format!("unknown risk class {code}")))
}

impl Intent {
    /// An intent with no params, context or optional constraints; valid for
    /// `ttl_ms` from `now_ms`.
    pub fn new(
        actor: EntityId,
        on_behalf_of: EntityId,
        action: CapabilityId,
        resource: ResourceId,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Self {
        Self {
            id: new_intent_id(),
            actor,
            on_behalf_of,
            action,
            resource,
            params: Payload::new(),
            context: IntentContext::default(),
            constraints: Constraints {
                deadline_ms: now_ms.saturating_add(ttl_ms),
                max_risk: None,
                no_escalation: false,
            },
            requested_at_ms: now_ms,
            authority: None,
        }
    }

    /// Shape rules that hold for every intent regardless of the domain.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if !self.actor.kind().is_principal() {
            return Err(reject(format!("actor {} is not a principal", self.actor)));
        }
        if self.on_behalf_of.kind() != EntityKind::Person {
            return Err(reject(format!("on_behalf_of {} is not a person: intents serve humans", self.on_behalf_of)));
        }
        if self.actor.kind() == EntityKind::Person && self.actor != self.on_behalf_of {
            return Err(reject("a person acts only on their own behalf"));
        }
        if self.constraints.deadline_ms <= self.requested_at_ms {
            return Err(err(DenyCode::Expired, "deadline is not after requested_at"));
        }
        if self.constraints.deadline_ms - self.requested_at_ms > MAX_INTENT_LIFETIME_MS {
            return Err(err(DenyCode::LifetimeTooLong, format!("intent lifetime exceeds {MAX_INTENT_LIFETIME_MS} ms")));
        }
        if self.context.purpose.as_ref().is_some_and(|p| p.chars().count() > MAX_PURPOSE_LEN) {
            return Err(reject(format!("purpose longer than {MAX_PURPOSE_LEN} characters")));
        }
        if self.authority.as_ref().is_some_and(|a| a.is_empty() || a.len() > MAX_AUTHORITY_BYTES) {
            return Err(reject("authority must be 1..4096 bytes"));
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let mut m = vec![
            (uint(1), uint(INTENT_VERSION)),
            (uint(2), Value::Bytes(self.id.to_vec())),
            (uint(3), Value::Text(self.actor.to_string())),
            (uint(4), Value::Text(self.on_behalf_of.to_string())),
            (uint(5), Value::Text(self.action.to_string())),
            (uint(6), Value::Text(self.resource.to_string())),
            (uint(10), uint(self.constraints.deadline_ms)),
            (uint(13), uint(self.requested_at_ms)),
        ];
        if !self.params.is_empty() {
            m.push((uint(7), payload_value(&self.params)));
        }
        if let Some(p) = &self.context.purpose {
            m.push((uint(8), Value::Text(p.clone())));
        }
        if let Some(c) = &self.context.cause {
            m.push((uint(9), Value::Bytes(c.clone())));
        }
        if let Some(r) = self.constraints.max_risk {
            m.push((uint(11), uint(r.code() as u64)));
        }
        if self.constraints.no_escalation {
            m.push((uint(12), Value::Bool(true)));
        }
        if let Some(a) = &self.authority {
            m.push((uint(14), Value::Bytes(a.clone())));
        }
        Value::Map(m)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        encode_deterministic(&self.to_value()).expect("an intent is always encodable")
    }

    /// Digest an approval binds to: SHA-256 of the canonical body.
    pub fn digest(&self) -> Digest {
        sha256(&self.to_cbor())
    }

    /// Sign as the actor. The caller is responsible for `actor` matching the key.
    pub fn sign(&self, actor_key: &Keypair) -> Vec<u8> {
        sign_payload_as(self.to_cbor(), actor_key, INTENT_CONTENT_TYPE)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut f = strict_map(bytes, "intent", 14)?;
        let mut take = |k: usize, name: &str| f[k].take().ok_or_else(|| decode_err(format!("missing {name}")));
        if uint_of(take(1, "version")?)? != INTENT_VERSION {
            return Err(err(DenyCode::Version, "unsupported intent version"));
        }
        let id = id16(take(2, "intent id")?, "intent id")?;
        let actor = entity(take(3, "actor")?, "actor")?;
        let on_behalf_of = entity(take(4, "on_behalf_of")?, "on_behalf_of")?;
        let action =
            CapabilityId::parse(&text(take(5, "action")?, "action", 128)?).map_err(|e| decode_err(e.to_string()))?;
        let resource = ResourceId::from_entity(entity(take(6, "resource")?, "resource")?)
            .map_err(|e| decode_err(e.to_string()))?;
        let deadline_ms = uint_of(take(10, "deadline")?)?;
        let requested_at_ms = uint_of(take(13, "requested_at")?)?;
        let params = f[7].take().map(payload_of).transpose()?.unwrap_or_default();
        let purpose = f[8].take().map(|v| text(v, "purpose", MAX_PURPOSE_LEN)).transpose()?;
        let cause = f[9].take().map(|v| bytes_field(v, "cause", MAX_ENVELOPE_BYTES)).transpose()?;
        let max_risk = f[11].take().map(risk_of).transpose()?;
        let no_escalation = match f[12].take() {
            None => false,
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(decode_err("no_escalation is present only as true")),
        };
        let authority = f[14].take().map(|v| bytes_field(v, "authority", MAX_AUTHORITY_BYTES)).transpose()?;
        let intent = Intent {
            id,
            actor,
            on_behalf_of,
            action,
            resource,
            params,
            context: IntentContext { purpose, cause },
            constraints: Constraints { deadline_ms, max_risk, no_escalation },
            requested_at_ms,
            authority,
        };
        intent.validate()?;
        Ok(intent)
    }
}

/// Why a signed intent or approval could not be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The signature does not verify with the signer's key.
    Signature(DecodeError),
    /// The body is malformed or breaks a shape rule.
    Body(DecodeError),
    /// The body names someone other than the signer.
    SignerMismatch { claimed: EntityId, signer: EntityId },
    /// A relayed intent in the chain is not authentic or well-formed.
    Cause(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Signature(e) | OpenError::Body(e) => write!(f, "{}", e.reason),
            OpenError::SignerMismatch { claimed, signer } => write!(f, "claims {claimed} but is signed by {signer}"),
            OpenError::Cause(e) => write!(f, "{e}"),
        }
    }
}

/// Key lookup for opening relay chains: key id → enrolled principal and key.
pub type KeyLookup<'a> = &'a dyn Fn(&KeyId) -> Option<(EntityId, PublicKey)>;

/// A parsed intent envelope whose signature has not been checked yet.
pub struct SignedIntent {
    env: SignedEnvelope,
}

impl SignedIntent {
    pub fn parse(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self { env: SignedEnvelope::parse_as(bytes, INTENT_CONTENT_TYPE)? })
    }

    pub fn key_id(&self) -> &KeyId {
        self.env.key_id()
    }

    /// Verify the signature of `signer` (whose key id matched), decode the body,
    /// require `actor == signer`, then open every relayed cause with `keys`.
    /// This is the only way to obtain a [`VerifiedIntent`].
    pub fn open(&self, signer: &EntityId, key: &PublicKey, keys: KeyLookup<'_>) -> Result<VerifiedIntent, OpenError> {
        self.open_at(signer, key, keys, 0)
    }

    fn open_at(
        &self,
        signer: &EntityId,
        key: &PublicKey,
        keys: KeyLookup<'_>,
        depth: usize,
    ) -> Result<VerifiedIntent, OpenError> {
        self.env.verify(key).map_err(OpenError::Signature)?;
        let intent = Intent::from_cbor(self.env.payload()).map_err(OpenError::Body)?;
        if &intent.actor != signer {
            return Err(OpenError::SignerMismatch { claimed: intent.actor, signer: signer.clone() });
        }
        let cause = match &intent.context.cause {
            Some(inner) => Some(Box::new(open_cause(inner, keys, depth + 1)?)),
            None => None,
        };
        Ok(VerifiedIntent { digest: sha256(self.env.payload()), intent, cause })
    }
}

fn open_cause(bytes: &[u8], keys: KeyLookup<'_>, depth: usize) -> Result<VerifiedIntent, OpenError> {
    let cause = |e: String| OpenError::Cause(e);
    if depth > MAX_CAUSE_DEPTH {
        return Err(cause(format!("relay chain longer than {MAX_CAUSE_DEPTH} hops")));
    }
    let signed = SignedIntent::parse(bytes).map_err(|e| cause(format!("relayed intent: {}", e.reason)))?;
    let (signer, key) =
        keys(signed.key_id()).ok_or_else(|| cause("a relayed intent is signed by a key not enrolled here".into()))?;
    signed.open_at(&signer, &key, keys, depth).map_err(|e| match e {
        OpenError::Cause(c) => OpenError::Cause(c),
        other => cause(format!("relayed intent of {signer}: {other}")),
    })
}

/// Read an intent's body **without verifying anything**. For a client that
/// must copy a request it is about to relay (the node verifies the chain);
/// never for a decision.
pub fn peek(bytes: &[u8]) -> Result<Intent, DecodeError> {
    let env = SignedEnvelope::parse_as(bytes, INTENT_CONTENT_TYPE)?;
    Intent::from_cbor(env.payload())
}

/// Parse, look up the signer and open — for clients and tests.
pub fn open_signed(bytes: &[u8], keys: KeyLookup<'_>) -> Result<VerifiedIntent, OpenError> {
    let signed = SignedIntent::parse(bytes).map_err(OpenError::Body)?;
    let (signer, key) = keys(signed.key_id())
        .ok_or_else(|| OpenError::Signature(err(DenyCode::UnknownKey, "signer is not enrolled")))?;
    signed.open(&signer, &key, keys)
}

/// An intent whose signature — and every relayed cause's — has been verified,
/// with the digest an approval must name. Only [`SignedIntent::open`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIntent {
    intent: Intent,
    digest: Digest,
    cause: Option<Box<VerifiedIntent>>,
}

impl VerifiedIntent {
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn cause(&self) -> Option<&VerifiedIntent> {
        self.cause.as_deref()
    }

    /// The intent followed by the intents it relays, outermost first.
    pub fn chain(&self) -> Vec<&Intent> {
        let mut out = vec![&self.intent];
        let mut cur = self.cause.as_deref();
        while let Some(c) = cur {
            out.push(&c.intent);
            cur = c.cause.as_deref();
        }
        out
    }
}

// ───────────────────────────── approvals ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Approve,
    Reject,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Approve => "approve",
            Verdict::Reject => "reject",
        }
    }
}

/// A human's signed answer to one escalated intent.
///
/// | key | field | type |
/// |----:|-------|------|
/// | 1 | version (= 1) | uint |
/// | 2 | intent id | bstr(16) |
/// | 3 | intent digest (SHA-256 of the intent body) | bstr(32) |
/// | 4 | approver (MUST be the signer, a person) | tstr |
/// | 5 | verdict: 1 approve, 2 reject | uint |
/// | 6 | issued at (ms) | uint |
/// | 7 | expires at (ms) | uint |
/// | 8 | note | tstr ≤ 280, optional |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub intent: IntentId,
    pub intent_digest: Digest,
    pub approver: EntityId,
    pub verdict: Verdict,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub note: Option<String>,
}

impl Approval {
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.approver.kind() != EntityKind::Person {
            return Err(reject(format!("approver {} is not a person: only humans approve", self.approver)));
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(err(DenyCode::Expired, "approval expires before it is issued"));
        }
        if self.expires_at_ms - self.issued_at_ms > MAX_APPROVAL_LIFETIME_MS {
            return Err(err(DenyCode::LifetimeTooLong, "approval lifetime too long"));
        }
        if self.note.as_ref().is_some_and(|n| n.chars().count() > MAX_NOTE_LEN) {
            return Err(reject("note too long"));
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let mut m = vec![
            (uint(1), uint(APPROVAL_VERSION)),
            (uint(2), Value::Bytes(self.intent.to_vec())),
            (uint(3), Value::Bytes(self.intent_digest.to_vec())),
            (uint(4), Value::Text(self.approver.to_string())),
            (
                uint(5),
                uint(match self.verdict {
                    Verdict::Approve => 1,
                    Verdict::Reject => 2,
                }),
            ),
            (uint(6), uint(self.issued_at_ms)),
            (uint(7), uint(self.expires_at_ms)),
        ];
        if let Some(n) = &self.note {
            m.push((uint(8), Value::Text(n.clone())));
        }
        Value::Map(m)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        encode_deterministic(&self.to_value()).expect("an approval is always encodable")
    }

    pub fn sign(&self, approver_key: &Keypair) -> Vec<u8> {
        sign_payload_as(self.to_cbor(), approver_key, APPROVAL_CONTENT_TYPE)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut f = strict_map(bytes, "approval", 8)?;
        let mut take = |k: usize, name: &str| f[k].take().ok_or_else(|| decode_err(format!("missing {name}")));
        if uint_of(take(1, "version")?)? != APPROVAL_VERSION {
            return Err(err(DenyCode::Version, "unsupported approval version"));
        }
        let intent = id16(take(2, "intent id")?, "intent id")?;
        let intent_digest: Digest = match take(3, "intent digest")? {
            Value::Bytes(b) if b.len() == 32 => b.try_into().expect("length checked"),
            _ => return Err(decode_err("intent digest must be 32 bytes")),
        };
        let approver = entity(take(4, "approver")?, "approver")?;
        let verdict = match uint_of(take(5, "verdict")?)? {
            1 => Verdict::Approve,
            2 => Verdict::Reject,
            v => return Err(decode_err(format!("unknown verdict {v}"))),
        };
        let issued_at_ms = uint_of(take(6, "issued at")?)?;
        let expires_at_ms = uint_of(take(7, "expires at")?)?;
        let note = f[8].take().map(|v| text(v, "note", MAX_NOTE_LEN)).transpose()?;
        let a = Approval { intent, intent_digest, approver, verdict, issued_at_ms, expires_at_ms, note };
        a.validate()?;
        Ok(a)
    }
}

/// A parsed approval envelope whose signature has not been checked yet.
pub struct SignedApproval {
    env: SignedEnvelope,
}

impl SignedApproval {
    pub fn parse(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self { env: SignedEnvelope::parse_as(bytes, APPROVAL_CONTENT_TYPE)? })
    }

    pub fn key_id(&self) -> &KeyId {
        self.env.key_id()
    }

    /// Verify, decode and require `approver == signer`. The only way to obtain
    /// a [`VerifiedApproval`].
    pub fn open(&self, signer: &EntityId, key: &PublicKey) -> Result<VerifiedApproval, OpenError> {
        self.env.verify(key).map_err(OpenError::Signature)?;
        let approval = Approval::from_cbor(self.env.payload()).map_err(OpenError::Body)?;
        if &approval.approver != signer {
            return Err(OpenError::SignerMismatch { claimed: approval.approver, signer: signer.clone() });
        }
        Ok(VerifiedApproval { approval })
    }
}

/// An approval signed by the approver it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApproval {
    approval: Approval,
}

impl VerifiedApproval {
    pub fn approval(&self) -> &Approval {
        &self.approval
    }
}

/// Hex form of an intent id, as used in responses, audit and the CLI.
pub fn id_hex(id: &IntentId) -> String {
    hex::encode(id)
}

pub fn parse_id_hex(s: &str) -> Option<IntentId> {
    hex::decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests;
