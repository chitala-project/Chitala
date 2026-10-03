//! The Trusted Execution Boundary (spec `specs/19-execution-boundary.md`).
//!
//! > AI produces Intent. Chitala produces Authority. **Only the trusted
//! > execution boundary produces physical Commands.** (Invariant 1)
//!
//! Every change of physical state goes one way:
//!
//! ```text
//! Authority (Grant | Authorized) + Safety Clearance
//!        └──────────────┬─────────────┘
//!          TrustedExecutionBoundary::mint      (this crate, the only producer)
//!                       │
//!                 MintedOrder ── signed ExecOrder, single use, one executor
//!                       │
//!          adapter host: OrderGate → DeviceAdapter → device
//!                       │
//!               ExecutionReceipt ── verify_receipt ── audit
//! ```
//!
//! Single path, enforced in three layers:
//!
//! 1. **Types.** [`mint`](TrustedExecutionBoundary::mint) consumes an
//!    [`Authority`] (a [`Grant`] from the Authority Engine or an [`Authorized`]
//!    from the Reference Monitor) and a [`Clearance`] from Safety. None of the
//!    three can be constructed or cloned outside the crate that decides it.
//!    The result, a [`MintedOrder`], cannot be constructed or cloned outside
//!    this crate, and the node's executors accept nothing else.
//! 2. **Keys.** Orders are signed with an order key that exists only inside one
//!    [`TrustedExecutionBoundary`] value: generated from the platform's entropy
//!    when the node starts, never stored, exported or logged. Adapter hosts
//!    accept only that key, so code that does not go through `mint` cannot
//!    produce an order any adapter executes — not even with the node's
//!    identity key — and every order dies with the node process.
//! 3. **CI.** `scripts/check-execution-boundary.py` fails if orders are built,
//!    signed, admitted or dispatched, or device I/O is used, anywhere outside
//!    the allowlisted modules.
//!
//! What the type system guarantees, as tests that must not compile:
//!
//! A minted order cannot be forged…
//! ```compile_fail,E0451
//! let _ = chitala_boundary::MintedOrder { bytes: vec![], expectation: todo!() };
//! ```
//! …or duplicated:
//! ```compile_fail,E0599
//! fn twice(o: chitala_boundary::MintedOrder) -> (chitala_boundary::MintedOrder, chitala_boundary::MintedOrder) {
//!     (o.clone(), o)
//! }
//! ```
//! A safety clearance cannot be duplicated, so it clears one order only:
//! ```compile_fail,E0599
//! fn twice(c: chitala_safety::Clearance) -> (chitala_safety::Clearance, chitala_safety::Clearance) {
//!     (c.clone(), c)
//! }
//! ```
//! A grant cannot be fabricated:
//! ```compile_fail,E0451
//! fn forge() -> chitala_policy::authority::Grant {
//!     chitala_policy::authority::Grant { ..todo!() }
//! }
//! ```
//! The order key cannot be read out of the boundary:
//! ```compile_fail,E0616
//! fn steal(b: &chitala_boundary::TrustedExecutionBoundary) {
//!     let _ = &b.key;
//! }
//! ```

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use chitala_csme::order::{message_digest, payload_digest, Digest32, ExecOrder, ExecutionReceipt, ORDER_TTL_MS};
use chitala_identity::{KeyId, Keypair, PublicKey};
use chitala_model::{CapabilityDef, CapabilityId, CapabilityKind, EntityId, Payload, TargetKind};
use chitala_monitor::Authorized;
use chitala_platform::{random_array, Entropy};
use chitala_policy::authority::Grant;
use chitala_safety::Clearance;
use serde_json::{json, Value};

/// A clearance older than this is not accepted: safety is checked right before
/// the order is minted, not when a human was asked.
pub const CLEARANCE_TTL_MS: u64 = 1_000;
/// Tolerated clock skew between the node and an adapter host in receipts.
pub const RECEIPT_SKEW_MS: u64 = 5_000;
/// Version of the decision context that [`context_digest`] covers (2: the
/// approvers are a list — two-key approvals).
pub const CONTEXT_VERSION: u64 = 2;

pub type ExecutorSession = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BoundaryError {
    #[error("only device actions become physical commands")]
    NotAnAction,
    #[error("the safety clearance belongs to another intent or request")]
    SubjectMismatch,
    #[error("the safety clearance is for a different {0} than the authority")]
    Mismatch(&'static str),
    #[error("the safety clearance is stale")]
    Stale,
}

/// The authority for one physical action. Both kinds are proofs that only the
/// deciding layer can create; [`TrustedExecutionBoundary::mint`] consumes them.
#[derive(Debug)]
pub enum Authority {
    /// The Authority Engine granted an intent (spec 16).
    Intent(Box<Grant>),
    /// The Reference Monitor allowed a signed request of a person or service (spec 08).
    Request(Box<Authorized>),
}

impl Authority {
    /// Id of the intent or request.
    pub fn subject(&self) -> &[u8; 16] {
        match self {
            Authority::Intent(g) => g.intent(),
            Authority::Request(a) => &a.envelope().message_id,
        }
    }

    /// The digest the decision bound: the intent digest approvals sign, or
    /// SHA-256 of the signed request.
    pub fn subject_digest(&self) -> &Digest32 {
        match self {
            Authority::Intent(g) => g.digest(),
            Authority::Request(a) => a.request_digest(),
        }
    }

    pub fn actor(&self) -> &EntityId {
        match self {
            Authority::Intent(g) => g.actor(),
            Authority::Request(a) => a.actor(),
        }
    }

    pub fn def(&self) -> &CapabilityDef {
        match self {
            Authority::Intent(g) => g.def(),
            Authority::Request(a) => a.def(),
        }
    }

    /// The device that executes the action.
    pub fn device(&self) -> &EntityId {
        match self {
            Authority::Intent(g) => g.device(),
            Authority::Request(a) => a.target(),
        }
    }

    pub fn params(&self) -> &Payload {
        match self {
            Authority::Intent(g) => g.params(),
            Authority::Request(a) => a.payload(),
        }
    }

    /// The authority context of the decision. The node records this object in
    /// the decision's audit record; the order carries its [`context_digest`],
    /// so an auditor can tie every order to the context that justified it.
    pub fn context(&self, ctx: &DecisionContext<'_>) -> Value {
        let (kind, on_behalf_of, relayed_from, approved_by, tokens, policy) = match self {
            Authority::Intent(g) => (
                "intent",
                g.on_behalf_of().to_string(),
                g.relayed_from().iter().map(ToString::to_string).collect::<Vec<_>>(),
                g.approved_by().iter().map(ToString::to_string).collect::<Vec<_>>(),
                g.tokens().to_vec(),
                g.policy_reasons().to_vec(),
            ),
            Authority::Request(a) => (
                "request",
                a.actor().to_string(),
                Vec::new(),
                Vec::new(),
                a.token().map(|t| vec![t.revocation_id.clone()]).unwrap_or_default(),
                a.policy_reasons().to_vec(),
            ),
        };
        json!({
            "v": CONTEXT_VERSION,
            "domain": ctx.domain.to_string(),
            "policy_fp": ctx.policy_fingerprint,
            "epoch": ctx.epoch,
            "kind": kind,
            "actor": self.actor().to_string(),
            "on_behalf_of": on_behalf_of,
            "relayed_from": relayed_from,
            "approved_by": approved_by,
            "tokens": tokens,
            "policy": policy,
        })
    }
}

/// The domain-wide state a decision was made in.
#[derive(Debug, Clone, Copy)]
pub struct DecisionContext<'a> {
    pub domain: &'a EntityId,
    pub policy_fingerprint: &'a str,
    /// Authority epoch (bumped by every delegation, revocation and state change).
    pub epoch: u64,
}

/// SHA-256 of the canonical JSON (RFC 8785 subset) of a decision context.
pub fn context_digest(context: &Value) -> Digest32 {
    let text = chitala_audit::canonical_json(context).expect("a decision context is canonicalizable");
    message_digest(text.as_bytes())
}

/// What the node expects back for one order. Only [`TrustedExecutionBoundary::mint`]
/// creates one; holding it grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    order_id: [u8; 16],
    order_digest: Digest32,
    executor: ExecutorSession,
    subject: [u8; 16],
    device: EntityId,
    capability: CapabilityId,
    issued_at_ms: u64,
    expires_at_ms: u64,
    epoch: u64,
}

impl Expectation {
    pub fn order_id(&self) -> &[u8; 16] {
        &self.order_id
    }
    pub fn order_digest(&self) -> &Digest32 {
        &self.order_digest
    }
    pub fn executor(&self) -> &ExecutorSession {
        &self.executor
    }
    pub fn subject(&self) -> &[u8; 16] {
        &self.subject
    }
    pub fn device(&self) -> &EntityId {
        &self.device
    }
    pub fn capability(&self) -> &CapabilityId {
        &self.capability
    }
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    /// The authority epoch the order was decided in.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// A signed execution order, minted for one action and one executor. Neither
/// constructible nor `Clone` outside this crate: executors take it by value.
pub struct MintedOrder {
    bytes: Vec<u8>,
    expectation: Expectation,
}

impl MintedOrder {
    /// The signed order, as the adapter host receives it.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn expectation(&self) -> &Expectation {
        &self.expectation
    }
}

impl fmt::Debug for MintedOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedOrder").field("expectation", &self.expectation).finish_non_exhaustive()
    }
}

/// The only producer of physical commands. One per node process.
pub struct TrustedExecutionBoundary {
    /// The order key. Never leaves this value.
    key: Keypair,
    entropy: Arc<dyn Entropy>,
}

impl fmt::Debug for TrustedExecutionBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedExecutionBoundary")
            .field("order_key_id", &hex_id(&self.key.key_id()))
            .finish_non_exhaustive()
    }
}

fn hex_id(id: &KeyId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

impl TrustedExecutionBoundary {
    /// A boundary with a fresh order key drawn from the platform's entropy.
    pub fn new(entropy: Arc<dyn Entropy>) -> Self {
        let key = Keypair::generate(entropy.as_ref());
        Self { key, entropy }
    }

    /// The public order key adapter hosts pin.
    pub fn order_key(&self) -> PublicKey {
        self.key.public_key()
    }

    pub fn order_key_id(&self) -> KeyId {
        self.key.key_id()
    }

    /// Mint the physical command for one authorized, cleared action, for the
    /// adapter host session `executor`. Consumes the authority and the
    /// clearance: neither can produce a second order.
    pub fn mint(
        &self,
        authority: Authority,
        clearance: Clearance,
        ctx: &DecisionContext<'_>,
        evidence_seq: u64,
        executor: &ExecutorSession,
        now_ms: u64,
    ) -> Result<MintedOrder, BoundaryError> {
        let def = authority.def();
        if def.kind != CapabilityKind::Action || def.target != TargetKind::Device {
            return Err(BoundaryError::NotAnAction);
        }
        if clearance.subject() != authority.subject() {
            return Err(BoundaryError::SubjectMismatch);
        }
        if clearance.device() != authority.device() {
            return Err(BoundaryError::Mismatch("device"));
        }
        if clearance.capability() != &def.id {
            return Err(BoundaryError::Mismatch("capability"));
        }
        if clearance.params() != authority.params() {
            return Err(BoundaryError::Mismatch("parameters"));
        }
        if let Authority::Intent(g) = &authority {
            if clearance.resource() != g.resource() {
                return Err(BoundaryError::Mismatch("resource"));
            }
        }
        if now_ms < clearance.checked_at_ms() || now_ms - clearance.checked_at_ms() > CLEARANCE_TTL_MS {
            return Err(BoundaryError::Stale);
        }

        let params = authority.params().clone();
        let order = ExecOrder {
            id: random_array(self.entropy.as_ref()),
            executor: *executor,
            subject: *authority.subject(),
            subject_digest: *authority.subject_digest(),
            actor: authority.actor().clone(),
            resource: clearance.resource().as_entity().clone(),
            device: clearance.device().clone(),
            capability: def.id.clone(),
            capability_version: def.version,
            params_digest: payload_digest(&params),
            params,
            context_digest: context_digest(&authority.context(ctx)),
            epoch: ctx.epoch,
            evidence_seq,
            cleared_at_ms: clearance.checked_at_ms(),
            issued_at_ms: now_ms,
            expires_at_ms: now_ms + ORDER_TTL_MS,
        };
        let bytes = order.sign(&self.key);
        let expectation = Expectation {
            order_id: order.id,
            order_digest: message_digest(&bytes),
            executor: order.executor,
            subject: order.subject,
            device: order.device,
            capability: order.capability,
            issued_at_ms: order.issued_at_ms,
            expires_at_ms: order.expires_at_ms,
            epoch: order.epoch,
        };
        Ok(MintedOrder { bytes, expectation })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    #[error("the adapter host returned no execution receipt")]
    Missing,
    #[error("the receipt does not match the order on {0}")]
    Mismatch(&'static str),
    #[error("the receipt's state digest does not match the reported state")]
    State,
    #[error("the receipt's execution time lies outside the order's validity")]
    Time,
}

/// Check that an adapter host's receipt answers exactly this order: same order
/// id and bytes, same executor session, device and capability, the reported
/// state, and a time inside the order's validity. A receipt that does not
/// match is not trusted and its state is not applied.
pub fn verify_receipt(
    expect: &Expectation,
    receipt: Option<&ExecutionReceipt>,
    state: &Payload,
) -> Result<(), ReceiptError> {
    let r = receipt.ok_or(ReceiptError::Missing)?;
    if r.order != expect.order_id {
        return Err(ReceiptError::Mismatch("order id"));
    }
    if r.order_digest != expect.order_digest {
        return Err(ReceiptError::Mismatch("order bytes"));
    }
    if r.executor != expect.executor {
        return Err(ReceiptError::Mismatch("executor"));
    }
    if r.device != expect.device {
        return Err(ReceiptError::Mismatch("device"));
    }
    if r.capability != expect.capability {
        return Err(ReceiptError::Mismatch("capability"));
    }
    if r.state_digest != payload_digest(state) {
        return Err(ReceiptError::State);
    }
    if r.executed_at_ms.saturating_add(RECEIPT_SKEW_MS) < expect.issued_at_ms
        || r.executed_at_ms > expect.expires_at_ms.saturating_add(RECEIPT_SKEW_MS)
    {
        return Err(ReceiptError::Time);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
