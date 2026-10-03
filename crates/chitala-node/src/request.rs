//! Client-side request construction.
//!
//! Clients share the capability registry (the semantic layer), so they can fill
//! the capability version, message type and declared risk; the node re-checks
//! every one of them.

use std::sync::Arc;

use chitala_csme::{new_message_id, Csme};
use chitala_identity::Keypair;
use chitala_model::{CapabilityId, CapabilityKind, CapabilityRegistry, EntityId, MessageType, Payload, RiskClass};
use chitala_platform::Entropy;

/// Default request lifetime.
pub const DEFAULT_TTL_MS: u64 = 30_000;

/// Everything a principal needs to sign requests.
pub struct Requester {
    pub actor: EntityId,
    pub key: Keypair,
    /// Endpoint the requests come from (`service:cli`, `service:mcp-broker`).
    pub source: EntityId,
    /// Capability token attached to every request, if any.
    pub token: Option<Vec<u8>>,
    pub ttl_ms: u64,
    /// Message ids come from here: the platform's entropy.
    pub entropy: Arc<dyn Entropy>,
}

impl Requester {
    pub fn new(actor: EntityId, key: Keypair, source: EntityId, entropy: Arc<dyn Entropy>) -> Self {
        Self { actor, key, source, token: None, ttl_ms: DEFAULT_TTL_MS, entropy }
    }

    pub fn with_token(mut self, token: Option<Vec<u8>>) -> Self {
        self.token = token;
        self
    }

    /// Build the envelope (unsigned) for `capability` on `target`.
    pub fn envelope(
        &self,
        registry: &CapabilityRegistry,
        target: &EntityId,
        capability: &CapabilityId,
        payload: Payload,
        now_ms: u64,
    ) -> Csme {
        let (version, risk, kind) = registry.get(capability).map(|d| (d.version, d.risk, d.kind)).unwrap_or((
            1,
            RiskClass::Low,
            CapabilityKind::Action,
        ));
        Csme {
            message_id: new_message_id(&*self.entropy),
            correlation_id: None,
            source: self.source.clone(),
            destination: target.clone(),
            actor: self.actor.clone(),
            capability: capability.clone(),
            capability_version: version,
            message_type: match kind {
                CapabilityKind::Action => MessageType::Command,
                CapabilityKind::Query => MessageType::Query,
            },
            issued_at_ms: now_ms,
            expires_at_ms: now_ms + self.ttl_ms,
            context_ref: None,
            authority: self.token.clone(),
            risk,
            payload,
        }
    }

    /// Build and sign.
    pub fn sign(
        &self,
        registry: &CapabilityRegistry,
        target: &EntityId,
        capability: &CapabilityId,
        payload: Payload,
        now_ms: u64,
    ) -> Vec<u8> {
        self.envelope(registry, target, capability, payload, now_ms).sign(&self.key)
    }
}
