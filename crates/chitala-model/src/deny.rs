//! Deny codes returned by the Reference Monitor (spec §08-reference-monitor).
//! The string form is part of the conformance contract and appears in test vectors.

use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! deny_codes {
    ($($variant:ident => $s:expr,)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum DenyCode {
            $(#[serde(rename = $s)] $variant,)+
        }

        impl DenyCode {
            pub const ALL: &'static [DenyCode] = &[$(DenyCode::$variant,)+];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(DenyCode::$variant => $s,)+
                }
            }

            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $($s => Some(DenyCode::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

deny_codes! {
    // envelope / COSE
    Decode => "E_DECODE",
    NonCanonical => "E_NON_CANONICAL",
    Version => "E_VERSION",
    CriticalExtension => "E_CRITICAL_EXT",
    Algorithm => "E_ALG",
    // identity
    UnknownKey => "E_UNKNOWN_KEY",
    ActorKeyMismatch => "E_ACTOR_KEY_MISMATCH",
    BadSignature => "E_BAD_SIGNATURE",
    PrincipalState => "E_PRINCIPAL_STATE",
    RateLimited => "E_RATE_LIMITED",
    // freshness / replay
    UnsupportedType => "E_UNSUPPORTED_TYPE",
    NotYetValid => "E_NOT_YET_VALID",
    Expired => "E_EXPIRED",
    LifetimeTooLong => "E_LIFETIME_TOO_LONG",
    Replay => "E_REPLAY",
    // capability / target
    UnknownTarget => "E_UNKNOWN_TARGET",
    UnknownCapability => "E_UNKNOWN_CAPABILITY",
    CapabilityVersion => "E_CAPABILITY_VERSION",
    UnsupportedByTarget => "E_UNSUPPORTED_BY_TARGET",
    KindMismatch => "E_KIND_MISMATCH",
    RiskMismatch => "E_RISK_MISMATCH",
    PayloadInvalid => "E_PAYLOAD_INVALID",
    SafetyEnvelope => "E_SAFETY_ENVELOPE",
    // authority
    TokenMissing => "E_TOKEN_MISSING",
    TokenInvalid => "E_TOKEN_INVALID",
    TokenRevoked => "E_TOKEN_REVOKED",
    TokenDenied => "E_TOKEN_DENIED",
    PolicyDenied => "E_POLICY_DENIED",
    PolicyError => "E_POLICY_ERROR",
    // intent path (specs 15–17): AI produces Intent, Chitala produces Authority
    IntentRequired => "E_INTENT_REQUIRED",
    UnknownResource => "E_UNKNOWN_RESOURCE",
    OnBehalfOf => "E_ON_BEHALF_OF",
    Provenance => "E_PROVENANCE",
    Constraint => "E_CONSTRAINT",
    ApprovalInvalid => "E_APPROVAL_INVALID",
    ApprovalRejected => "E_APPROVAL_REJECTED",
    Safety => "E_SAFETY",
    // a two-key resource: one person alone cannot act (submit an intent so a
    // second person can approve)
    TwoKeyRequired => "E_TWO_KEY_REQUIRED",
    // execution leases (spec 21)
    LeaseDenied => "E_LEASE_DENIED",
    LeaseUnknown => "E_LEASE_UNKNOWN",
    LeaseMismatch => "E_LEASE_MISMATCH",
    LeaseEnvelope => "E_LEASE_ENVELOPE",
    LeaseExhausted => "E_LEASE_EXHAUSTED",
    LeaseExpired => "E_LEASE_EXPIRED",
    LeaseRevoked => "E_LEASE_REVOKED",
    // plans (spec 23): a plan the plan rules refuse (too many running)
    PlanDenied => "E_PLAN_DENIED",
    Internal => "E_INTERNAL",
}

impl fmt::Display for DenyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Execution failures after the Reference Monitor has allowed a request
/// (spec §11-node-ipc "Execution errors"). An allowed request can still fail:
/// the device may be offline or refuse through a local invariant
/// (Security Constitution C5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecCode {
    /// The device or its backend could not be reached: the command was not
    /// delivered, so it did not execute.
    #[serde(rename = "X_DEVICE_UNAVAILABLE")]
    DeviceUnavailable,
    /// The device refused it through a local invariant: it did not execute.
    #[serde(rename = "X_DEVICE_REFUSED")]
    DeviceRefused,
    /// The adapter could not map or run it: it did not execute.
    #[serde(rename = "X_ADAPTER")]
    Adapter,
    /// The command may have executed and nobody can say: it was delivered,
    /// then the connection broke, no result came in time, or the backend
    /// failed after it started. Chitala observes the world to decide (spec 22).
    #[serde(rename = "X_EXECUTION_UNKNOWN")]
    ExecutionUnknown,
    #[serde(rename = "X_INVALID_ARGUMENT")]
    InvalidArgument,
    #[serde(rename = "X_DELEGATION_DENIED")]
    DelegationDenied,
    /// The adapter host refused an execution order (bad signature, stale, replayed).
    #[serde(rename = "X_ORDER_REJECTED")]
    OrderRejected,
    /// The adapter host's execution receipt does not match the order it was
    /// given: its report is not trusted and not applied.
    #[serde(rename = "X_RECEIPT_INVALID")]
    ReceiptInvalid,
    #[serde(rename = "X_NOT_PERMITTED")]
    NotPermitted,
    #[serde(rename = "X_INTERNAL")]
    Internal,
}

impl ExecCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecCode::DeviceUnavailable => "X_DEVICE_UNAVAILABLE",
            ExecCode::DeviceRefused => "X_DEVICE_REFUSED",
            ExecCode::Adapter => "X_ADAPTER",
            ExecCode::ExecutionUnknown => "X_EXECUTION_UNKNOWN",
            ExecCode::InvalidArgument => "X_INVALID_ARGUMENT",
            ExecCode::DelegationDenied => "X_DELEGATION_DENIED",
            ExecCode::OrderRejected => "X_ORDER_REJECTED",
            ExecCode::ReceiptInvalid => "X_RECEIPT_INVALID",
            ExecCode::NotPermitted => "X_NOT_PERMITTED",
            ExecCode::Internal => "X_INTERNAL",
        }
    }
}

impl fmt::Display for ExecCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for c in DenyCode::ALL {
            assert_eq!(DenyCode::parse(c.as_str()), Some(*c));
            assert!(c.as_str().starts_with("E_"));
        }
        assert_eq!(
            serde_json::to_string(&ExecCode::DeviceRefused).unwrap(),
            format!("\"{}\"", ExecCode::DeviceRefused.as_str())
        );
    }
}
