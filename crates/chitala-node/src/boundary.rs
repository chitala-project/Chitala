//! The trusted execution boundary (Invariant 1, spec `specs/15-intent.md`).
//!
//! > AI produces Intent. Chitala produces Authority. **Only the trusted
//! > execution boundary produces physical Commands.**
//!
//! A physical command is a node-signed execution order
//! (`application/chitala-order`), the only message an adapter host executes.
//! On the intent path it is minted here and nowhere else, from two proofs that
//! cannot be forged or reused:
//!
//! - a [`Grant`] — only the Authority Engine creates one, for one intent;
//! - a [`Clearance`] — only the safety layer creates one, for one action.
//!
//! Both are consumed. The clearance must describe exactly the granted action
//! (resource, capability, device, parameters) and be fresh.

use chitala_csme::order::{ExecOrder, ORDER_TTL_MS};
use chitala_model::CapabilityKind;
use chitala_policy::authority::Grant;
use chitala_safety::Clearance;

/// A clearance older than this is not accepted (safety must be checked right
/// before the command is minted, not when a human was asked).
pub const CLEARANCE_TTL_MS: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BoundaryError {
    #[error("only actions become physical commands")]
    NotAnAction,
    #[error("the safety clearance is for a different action than the grant")]
    Mismatch,
    #[error("the safety clearance is stale")]
    Stale,
}

/// Mint the physical command for one granted, cleared action.
pub fn physical_command(grant: Grant, clearance: Clearance, now_ms: u64) -> Result<ExecOrder, BoundaryError> {
    if grant.def().kind != CapabilityKind::Action {
        return Err(BoundaryError::NotAnAction);
    }
    if clearance.resource() != grant.resource()
        || clearance.capability() != &grant.def().id
        || clearance.device() != grant.device()
        || clearance.params() != grant.params()
    {
        return Err(BoundaryError::Mismatch);
    }
    if now_ms < clearance.checked_at_ms() || now_ms - clearance.checked_at_ms() > CLEARANCE_TTL_MS {
        return Err(BoundaryError::Stale);
    }
    Ok(ExecOrder {
        id: *grant.intent(),
        actor: grant.actor().clone(),
        target: grant.device().clone(),
        capability: grant.def().id.clone(),
        capability_version: grant.def().version,
        decided_at_ms: now_ms,
        expires_at_ms: now_ms + ORDER_TTL_MS,
        payload: grant.params().clone(),
    })
}
