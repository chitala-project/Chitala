//! Capability tokens (spec `specs/05-capability-token.md`).
//!
//! A token is a Biscuit token signed by the *domain authority key* (never by a
//! global key: Security Constitution C7). Its authority block is holder-bound and
//! lists explicit `right(target, capability)` facts:
//!
//! ```text
//! chitala_token(1);
//! holder("ai:assistant");  issuer("person:alice");  depth(1);
//! expires_ms(1759489200000);
//! right("device:living-room-light", "light.turn_on");
//! parent("<revocation id of the parent token>");      // only for re-delegations
//! check if time($t), $t < 2025-10-03T11:00:00Z;
//! ```
//!
//! Attenuation blocks appended by the holder can only add checks, so a holder can
//! narrow a token offline but never widen it (v8 §8: no privilege amplification).
//! Handing a right to *another* principal is server-mediated: the domain authority
//! issues a fresh token after checking child ⊆ parent, expiry ≤ parent expiry and
//! depth ≤ [`MAX_DELEGATION_DEPTH`].

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_auth::builder::{fact, string, BlockBuilder, Term};
use biscuit_auth::{
    Algorithm, AuthorizerBuilder, AuthorizerLimits, Biscuit, KeyPair as BiscuitKeyPair, PrivateKey,
    PublicKey as BiscuitPublicKey, UnverifiedBiscuit,
};
use chitala_identity::{Keypair, PublicKey};
use chitala_model::{CapabilityId, EntityId};
use serde::{Deserialize, Serialize};

/// Value of the `chitala_token(..)` fact. Bumped on incompatible changes.
pub const TOKEN_FORMAT: i64 = 1;
/// Maximum length of a delegation chain (root grant = depth 1).
pub const MAX_DELEGATION_DEPTH: u8 = 3;
/// Tokens larger than this are rejected before parsing.
pub const MAX_TOKEN_BYTES: usize = 4096;
/// Maximum number of rights in one token.
pub const MAX_RIGHTS: usize = 32;
/// Maximum number of blocks (authority + attenuations).
pub const MAX_BLOCKS: usize = 8;

fn limits() -> AuthorizerLimits {
    AuthorizerLimits {
        max_facts: 1_000,
        max_iterations: 100,
        // generous enough for debug builds; datalog here is tiny
        max_time: Duration::from_millis(200),
    }
}

fn date(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

/// Token expiries are aligned to whole seconds because Biscuit dates have
/// second precision; with `$t < exp` this makes the check exact.
fn align_expiry(ms: u64) -> u64 {
    ms / 1000 * 1000
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Right {
    pub target: EntityId,
    pub capability: CapabilityId,
}

impl Right {
    pub fn new(target: EntityId, capability: CapabilityId) -> Self {
        Self { target, capability }
    }
}

impl std::fmt::Display for Right {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.target, self.capability)
    }
}

/// What a new token should say.
#[derive(Debug, Clone)]
pub struct Grant {
    pub holder: EntityId,
    /// The principal on whose authority the token is issued (the delegator).
    pub issuer: EntityId,
    pub rights: Vec<Right>,
    pub not_after_ms: u64,
}

#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub bytes: Vec<u8>,
    pub base64: String,
    /// Hex revocation id of the authority block; identifies the token.
    pub revocation_id: String,
    pub expires_at_ms: u64,
    pub depth: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// → `E_TOKEN_INVALID`
    #[error("token is malformed or not signed by this domain: {0}")]
    Invalid(String),
    /// → `E_TOKEN_REVOKED`
    #[error("token has been revoked")]
    Revoked,
    /// → `E_TOKEN_DENIED`
    #[error("token does not grant this request: {0}")]
    Denied(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    #[error("{0} is not the holder of the parent token")]
    NotHolder(EntityId),
    #[error("right {0} is not granted by the parent token")]
    NotSubset(Right),
    #[error("delegation depth {0} exceeds the maximum of {MAX_DELEGATION_DEPTH}")]
    TooDeep(u8),
    #[error("the parent token has expired")]
    ParentExpired,
    #[error("an attenuated token cannot be re-delegated; use the original token")]
    AttenuatedParent,
    #[error("expiry must be in the future")]
    InvalidExpiry,
    #[error("a principal cannot delegate to itself")]
    SelfDelegation,
    #[error("a token must carry between 1 and {MAX_RIGHTS} rights")]
    RightsCount,
    #[error("token construction failed: {0}")]
    Build(String),
}

fn to_biscuit_private(kp: &Keypair) -> BiscuitKeyPair {
    let sk = PrivateKey::from_bytes(&kp.seed(), Algorithm::Ed25519)
        .expect("32-byte Ed25519 seed is always a valid private key");
    BiscuitKeyPair::from(&sk)
}

fn to_biscuit_public(pk: &PublicKey) -> BiscuitPublicKey {
    BiscuitPublicKey::from_bytes(pk, Algorithm::Ed25519).expect("32-byte Ed25519 public key is always accepted")
}

/// The domain's token issuer. Holds the domain authority private key.
pub struct TokenAuthority {
    kp: BiscuitKeyPair,
    public_key: PublicKey,
}

impl TokenAuthority {
    pub fn new(authority_key: &Keypair) -> Self {
        Self { kp: to_biscuit_private(authority_key), public_key: authority_key.public_key() }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn verifier(&self) -> TokenVerifier {
        TokenVerifier::new(&self.public_key)
    }

    /// Issue a root grant (depth 1). The caller is responsible for having checked
    /// that `grant.issuer` itself holds every right (spec §05 "Root grants").
    pub fn issue(&self, grant: &Grant, now_ms: u64) -> Result<IssuedToken, DelegationError> {
        self.build(grant, 1, &[], now_ms)
    }

    /// Server-mediated re-delegation of (a subset of) `parent` by its holder.
    pub fn delegate(
        &self,
        parent: &VerifiedToken,
        delegator: &EntityId,
        child: &Grant,
        now_ms: u64,
    ) -> Result<IssuedToken, DelegationError> {
        if parent.holder != *delegator {
            return Err(DelegationError::NotHolder(delegator.clone()));
        }
        if parent.block_count > 1 {
            return Err(DelegationError::AttenuatedParent);
        }
        if now_ms >= parent.expires_at_ms {
            return Err(DelegationError::ParentExpired);
        }
        for r in &child.rights {
            if !parent.rights.contains(r) {
                return Err(DelegationError::NotSubset(r.clone()));
            }
            // defense in depth: the parent must actually authorize the right now
            parent
                .authorize(delegator, &r.target, &r.capability, now_ms)
                .map_err(|_| DelegationError::NotSubset(r.clone()))?;
        }
        let depth = parent.depth.saturating_add(1);
        if depth > MAX_DELEGATION_DEPTH {
            return Err(DelegationError::TooDeep(depth));
        }
        let grant = Grant {
            holder: child.holder.clone(),
            issuer: delegator.clone(),
            rights: child.rights.clone(),
            not_after_ms: child.not_after_ms.min(parent.expires_at_ms),
        };
        let mut chain = parent.parents.clone();
        chain.push(parent.revocation_id.clone());
        self.build(&grant, depth, &chain, now_ms)
    }

    fn build(&self, grant: &Grant, depth: u8, parents: &[String], now_ms: u64) -> Result<IssuedToken, DelegationError> {
        if grant.holder == grant.issuer {
            return Err(DelegationError::SelfDelegation);
        }
        let rights: BTreeSet<&Right> = grant.rights.iter().collect();
        if rights.is_empty() || rights.len() > MAX_RIGHTS {
            return Err(DelegationError::RightsCount);
        }
        let exp = align_expiry(grant.not_after_ms);
        if exp <= now_ms {
            return Err(DelegationError::InvalidExpiry);
        }
        let build_err = |e: biscuit_auth::error::Token| DelegationError::Build(e.to_string());

        let params = HashMap::from([
            ("fmt".to_string(), Term::from(TOKEN_FORMAT)),
            ("holder".to_string(), Term::from(grant.holder.to_string())),
            ("issuer".to_string(), Term::from(grant.issuer.to_string())),
            ("depth".to_string(), Term::from(depth as i64)),
            ("exp_ms".to_string(), Term::from(exp as i64)),
            ("exp".to_string(), Term::from(date(exp))),
        ]);
        let mut builder = Biscuit::builder()
            .code_with_params(
                r#"
                chitala_token({fmt});
                holder({holder});
                issuer({issuer});
                depth({depth});
                expires_ms({exp_ms});
                check if time($t), $t < {exp};
                "#,
                params,
                HashMap::new(),
            )
            .map_err(build_err)?;
        for r in rights {
            builder = builder
                .fact(fact("right", &[string(&r.target.to_string()), string(r.capability.as_str())]))
                .map_err(build_err)?;
        }
        for p in parents {
            builder = builder.fact(fact("parent", &[string(p)])).map_err(build_err)?;
        }
        let biscuit = builder.build(&self.kp).map_err(build_err)?;
        let bytes = biscuit.to_vec().map_err(build_err)?;
        let base64 = biscuit.to_base64().map_err(build_err)?;
        let revocation_id = hex::encode(&biscuit.revocation_identifiers()[0]);
        Ok(IssuedToken { bytes, base64, revocation_id, expires_at_ms: exp, depth })
    }
}

/// Decode the URL-safe base64 text form of a token without verifying it.
pub fn bytes_from_base64(text: &str) -> Result<Vec<u8>, TokenError> {
    let text = text.trim();
    if text.len() > MAX_TOKEN_BYTES * 4 / 3 + 4 {
        return Err(TokenError::Invalid("token too large".into()));
    }
    UnverifiedBiscuit::from_base64(text).and_then(|t| t.to_vec()).map_err(|e| TokenError::Invalid(e.to_string()))
}

/// Holder-side, offline narrowing. Every `Some` restriction becomes a check in a
/// new block; `None` leaves that dimension as it is.
#[derive(Debug, Clone, Default)]
pub struct Restriction {
    pub targets: Option<Vec<EntityId>>,
    pub capabilities: Option<Vec<CapabilityId>>,
    pub not_after_ms: Option<u64>,
}

pub fn attenuate(token: &[u8], domain_key: &PublicKey, restriction: &Restriction) -> Result<Vec<u8>, TokenError> {
    let invalid = |e: biscuit_auth::error::Token| TokenError::Invalid(e.to_string());
    let biscuit = Biscuit::from(token, to_biscuit_public(domain_key)).map_err(invalid)?;
    let mut block = BlockBuilder::new();
    if let Some(targets) = &restriction.targets {
        let set: BTreeSet<Term> = targets.iter().map(|t| Term::from(t.to_string())).collect();
        block = block
            .code_with_params(
                "check if target($t), {set}.contains($t);",
                HashMap::from([("set".to_string(), Term::Set(set))]),
                HashMap::new(),
            )
            .map_err(invalid)?;
    }
    if let Some(caps) = &restriction.capabilities {
        let set: BTreeSet<Term> = caps.iter().map(|c| Term::from(c.as_str())).collect();
        block = block
            .code_with_params(
                "check if capability($c), {set}.contains($c);",
                HashMap::from([("set".to_string(), Term::Set(set))]),
                HashMap::new(),
            )
            .map_err(invalid)?;
    }
    if let Some(ms) = restriction.not_after_ms {
        block = block
            .code_with_params(
                "check if time($t), $t < {exp};",
                HashMap::from([("exp".to_string(), Term::from(date(align_expiry(ms))))]),
                HashMap::new(),
            )
            .map_err(invalid)?;
    }
    biscuit.append(block).and_then(|b| b.to_vec()).map_err(invalid)
}

/// Verifies signatures against the domain authority public key.
#[derive(Clone)]
pub struct TokenVerifier {
    root: BiscuitPublicKey,
}

impl TokenVerifier {
    pub fn new(domain_key: &PublicKey) -> Self {
        Self { root: to_biscuit_public(domain_key) }
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<VerifiedToken, TokenError> {
        if bytes.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::Invalid(format!("token larger than {MAX_TOKEN_BYTES} bytes")));
        }
        let invalid = |e: biscuit_auth::error::Token| TokenError::Invalid(e.to_string());
        let biscuit = Biscuit::from(bytes, self.root).map_err(invalid)?;
        if biscuit.block_count() > MAX_BLOCKS {
            return Err(TokenError::Invalid(format!("more than {MAX_BLOCKS} blocks")));
        }
        // Introspection queries only see authority-block facts, so attenuation
        // blocks cannot inject rights or change the holder.
        let mut a = AuthorizerBuilder::new().set_limits(limits()).build(&biscuit).map_err(invalid)?;
        let one_str = |a: &mut biscuit_auth::Authorizer, rule: &str| -> Result<String, TokenError> {
            let mut v: Vec<(String,)> = a.query(rule).map_err(invalid)?;
            if v.len() != 1 {
                return Err(TokenError::Invalid(format!("expected exactly one result for {rule}")));
            }
            Ok(v.remove(0).0)
        };
        let one_int = |a: &mut biscuit_auth::Authorizer, rule: &str| -> Result<i64, TokenError> {
            let mut v: Vec<(i64,)> = a.query(rule).map_err(invalid)?;
            if v.len() != 1 {
                return Err(TokenError::Invalid(format!("expected exactly one result for {rule}")));
            }
            Ok(v.remove(0).0)
        };
        let fmt = one_int(&mut a, "data($v) <- chitala_token($v)")?;
        if fmt != TOKEN_FORMAT {
            return Err(TokenError::Invalid(format!("unsupported token format {fmt}")));
        }
        let parse_id = |s: String| EntityId::parse(&s).map_err(|e| TokenError::Invalid(e.to_string()));
        let holder = parse_id(one_str(&mut a, "data($v) <- holder($v)")?)?;
        let issuer = parse_id(one_str(&mut a, "data($v) <- issuer($v)")?)?;
        let depth = one_int(&mut a, "data($v) <- depth($v)")?;
        let depth = u8::try_from(depth)
            .ok()
            .filter(|d| (1..=MAX_DELEGATION_DEPTH).contains(d))
            .ok_or_else(|| TokenError::Invalid(format!("bad depth {depth}")))?;
        let expires_at_ms = u64::try_from(one_int(&mut a, "data($v) <- expires_ms($v)")?)
            .map_err(|_| TokenError::Invalid("negative expiry".into()))?;
        let raw_rights: Vec<(String, String)> = a.query("data($t, $c) <- right($t, $c)").map_err(invalid)?;
        if raw_rights.is_empty() || raw_rights.len() > MAX_RIGHTS {
            return Err(TokenError::Invalid("bad number of rights".into()));
        }
        let mut rights = Vec::with_capacity(raw_rights.len());
        for (t, c) in raw_rights {
            rights.push(Right {
                target: parse_id(t)?,
                capability: CapabilityId::parse(&c).map_err(|e| TokenError::Invalid(e.to_string()))?,
            });
        }
        rights.sort();
        let parents: Vec<(String,)> = a.query("data($p) <- parent($p)").map_err(invalid)?;
        let mut parents: Vec<String> = parents.into_iter().map(|(p,)| p).collect();
        parents.sort();
        let rids: Vec<String> = biscuit.revocation_identifiers().iter().map(hex::encode).collect();
        Ok(VerifiedToken {
            revocation_id: rids[0].clone(),
            block_revocation_ids: rids,
            block_count: biscuit.block_count(),
            biscuit,
            holder,
            issuer,
            depth,
            expires_at_ms,
            rights,
            parents,
        })
    }
}

/// A token whose signature chain has been verified. Authorization of a concrete
/// request is a separate step ([`VerifiedToken::authorize`]).
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    biscuit: Biscuit,
    pub holder: EntityId,
    pub issuer: EntityId,
    pub depth: u8,
    pub expires_at_ms: u64,
    pub rights: Vec<Right>,
    /// Revocation ids of all ancestors (root first is not guaranteed; sorted).
    pub parents: Vec<String>,
    /// Revocation id of the authority block — the token's identity.
    pub revocation_id: String,
    /// Revocation ids of every block (authority first).
    pub block_revocation_ids: Vec<String>,
    pub block_count: usize,
}

impl VerifiedToken {
    /// Evaluate all blocks (authority + attenuations) for one concrete request.
    /// The token is holder-bound: `actor` must be the holder.
    pub fn authorize(
        &self,
        actor: &EntityId,
        target: &EntityId,
        capability: &CapabilityId,
        now_ms: u64,
    ) -> Result<(), TokenError> {
        if *actor != self.holder {
            return Err(TokenError::Denied(format!("token is bound to {}, not {actor}", self.holder)));
        }
        if now_ms >= self.expires_at_ms {
            return Err(TokenError::Denied("token expired".into()));
        }
        let params = HashMap::from([
            ("actor".to_string(), Term::from(actor.to_string())),
            ("target".to_string(), Term::from(target.to_string())),
            ("capability".to_string(), Term::from(capability.as_str())),
            ("now".to_string(), Term::from(date(now_ms))),
        ]);
        let denied = |e: biscuit_auth::error::Token| TokenError::Denied(e.to_string());
        let mut a = AuthorizerBuilder::new()
            .set_limits(limits())
            .code_with_params(
                r#"
                actor({actor});
                target({target});
                capability({capability});
                time({now});
                allow if actor($a), holder($a), target($t), capability($c), right($t, $c);
                "#,
                params,
                HashMap::new(),
            )
            .map_err(denied)?
            .build(&self.biscuit)
            .map_err(denied)?;
        a.authorize().map(|_| ()).map_err(|e| match e {
            biscuit_auth::error::Token::FailedLogic(biscuit_auth::error::Logic::NoMatchingPolicy { .. }) => {
                TokenError::Denied(format!("no right {target}/{capability}"))
            }
            other => denied(other),
        })
    }

    /// Every id whose revocation invalidates this token: all of its blocks and
    /// all ancestors in the delegation chain (cascade revocation).
    pub fn revocation_ids(&self) -> impl Iterator<Item = &str> {
        self.block_revocation_ids.iter().chain(self.parents.iter()).map(String::as_str)
    }

    /// Human-readable Datalog of all blocks (for `chitala token inspect`).
    pub fn print(&self) -> String {
        self.biscuit.print()
    }
}

/// Revoked token ids of a domain. Persisted by the node; checked on every use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    revoked: BTreeSet<String>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `false` if the id was already revoked.
    pub fn revoke(&mut self, revocation_id: &str) -> bool {
        self.revoked.insert(revocation_id.to_ascii_lowercase())
    }

    pub fn contains(&self, revocation_id: &str) -> bool {
        self.revoked.contains(&revocation_id.to_ascii_lowercase())
    }

    pub fn is_revoked(&self, token: &VerifiedToken) -> bool {
        token.revocation_ids().any(|id| self.revoked.contains(id))
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.revoked.iter().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_identity::test_seed;

    const NOW: u64 = 1_790_000_000_000;

    fn id(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }
    fn cap(s: &str) -> CapabilityId {
        CapabilityId::parse(s).unwrap()
    }
    fn right(t: &str, c: &str) -> Right {
        Right::new(id(t), cap(c))
    }
    fn authority() -> TokenAuthority {
        TokenAuthority::new(&Keypair::from_seed(&test_seed("domain:home/authority")))
    }
    fn grant(holder: &str, rights: Vec<Right>, ttl_ms: u64) -> Grant {
        Grant { holder: id(holder), issuer: id("person:alice"), rights, not_after_ms: NOW + ttl_ms }
    }

    #[test]
    fn holder_bound_and_scoped() {
        let auth = authority();
        let t =
            auth.issue(&grant("ai:assistant", vec![right("device:light-1", "light.turn_on")], 600_000), NOW).unwrap();
        let v = auth.verifier().verify(&t.bytes).unwrap();
        assert_eq!(v.holder, id("ai:assistant"));
        assert_eq!(v.depth, 1);
        assert_eq!(v.revocation_id, t.revocation_id);
        let ai = id("ai:assistant");
        assert!(v.authorize(&ai, &id("device:light-1"), &cap("light.turn_on"), NOW).is_ok());
        // other capability, other target, other actor, after expiry
        assert!(v.authorize(&ai, &id("device:light-1"), &cap("light.turn_off"), NOW).is_err());
        assert!(v.authorize(&ai, &id("device:light-2"), &cap("light.turn_on"), NOW).is_err());
        assert!(v.authorize(&id("ai:other"), &id("device:light-1"), &cap("light.turn_on"), NOW).is_err());
        assert!(v.authorize(&ai, &id("device:light-1"), &cap("light.turn_on"), NOW + 600_000).is_err());
        assert!(v.authorize(&ai, &id("device:light-1"), &cap("light.turn_on"), NOW + 599_999).is_ok());
    }

    #[test]
    fn foreign_or_tampered_tokens_are_invalid() {
        let auth = authority();
        let other = TokenAuthority::new(&Keypair::from_seed(&test_seed("domain:evil/authority")));
        let t = other.issue(&grant("ai:assistant", vec![right("device:light-1", "lock.unlock")], 60_000), NOW).unwrap();
        assert!(matches!(auth.verifier().verify(&t.bytes), Err(TokenError::Invalid(_))));

        let mut good = auth
            .issue(&grant("ai:assistant", vec![right("device:light-1", "light.turn_on")], 60_000), NOW)
            .unwrap()
            .bytes;
        let mid = good.len() / 2;
        good[mid] ^= 0x01;
        assert!(auth.verifier().verify(&good).is_err());
        assert!(auth.verifier().verify(&[]).is_err());
        assert!(auth.verifier().verify(&vec![0u8; MAX_TOKEN_BYTES + 1]).is_err());
    }

    #[test]
    fn base64_round_trip() {
        let auth = authority();
        let t =
            auth.issue(&grant("ai:assistant", vec![right("device:light-1", "light.turn_on")], 60_000), NOW).unwrap();
        let bytes = bytes_from_base64(&t.base64).unwrap();
        assert_eq!(auth.verifier().verify(&bytes).unwrap().revocation_id, t.revocation_id);
        assert!(bytes_from_base64("not a token").is_err());
    }

    #[test]
    fn attenuation_only_narrows() {
        let auth = authority();
        let pk = auth.public_key();
        let t = auth
            .issue(
                &grant(
                    "ai:assistant",
                    vec![right("device:light-1", "light.turn_on"), right("device:light-1", "light.set_brightness")],
                    600_000,
                ),
                NOW,
            )
            .unwrap();
        let narrowed = attenuate(
            &t.bytes,
            &pk,
            &Restriction { capabilities: Some(vec![cap("light.turn_on")]), ..Default::default() },
        )
        .unwrap();
        let v = auth.verifier().verify(&narrowed).unwrap();
        let ai = id("ai:assistant");
        assert_eq!(v.block_count, 2);
        assert!(v.authorize(&ai, &id("device:light-1"), &cap("light.turn_on"), NOW).is_ok());
        assert!(v.authorize(&ai, &id("device:light-1"), &cap("light.set_brightness"), NOW).is_err());

        // a shorter expiry in an attenuation block is enforced
        let short =
            attenuate(&t.bytes, &pk, &Restriction { not_after_ms: Some(NOW + 10_000), ..Default::default() }).unwrap();
        let v = auth.verifier().verify(&short).unwrap();
        assert!(v.authorize(&ai, &id("device:light-1"), &cap("light.turn_on"), NOW + 9_000).is_ok());
        assert!(v.authorize(&ai, &id("device:light-1"), &cap("light.turn_on"), NOW + 11_000).is_err());
    }

    #[test]
    fn attenuation_block_cannot_inject_rights_or_holder() {
        let auth = authority();
        let t =
            auth.issue(&grant("ai:assistant", vec![right("device:light-1", "light.turn_on")], 600_000), NOW).unwrap();
        let b = Biscuit::from(&t.bytes, to_biscuit_public(&auth.public_key())).unwrap();
        let evil = BlockBuilder::new()
            .code(
                r#"
                right("device:front-door", "lock.unlock");
                holder("ai:intruder");
                right($t, $c) <- target($t), capability($c);
                "#,
            )
            .unwrap();
        let forged = b.append(evil).unwrap().to_vec().unwrap();
        let v = auth.verifier().verify(&forged).unwrap();
        assert_eq!(v.holder, id("ai:assistant"));
        assert_eq!(v.rights, vec![right("device:light-1", "light.turn_on")]);
        let ai = id("ai:assistant");
        assert!(v.authorize(&ai, &id("device:front-door"), &cap("lock.unlock"), NOW).is_err());
        assert!(v.authorize(&id("ai:intruder"), &id("device:light-1"), &cap("light.turn_on"), NOW).is_err());
    }

    #[test]
    fn delegation_rules() {
        let auth = authority();
        let v = auth.verifier();
        let parent = auth
            .issue(
                &Grant {
                    holder: id("person:bob"),
                    issuer: id("person:alice"),
                    rights: vec![right("device:light-1", "light.turn_on"), right("device:light-1", "light.turn_off")],
                    not_after_ms: NOW + 3_600_000,
                },
                NOW,
            )
            .unwrap();
        let parent = v.verify(&parent.bytes).unwrap();
        let bob = id("person:bob");

        // subset with a longer ttl → expiry clipped to the parent's
        let child = auth
            .delegate(
                &parent,
                &bob,
                &grant("ai:assistant", vec![right("device:light-1", "light.turn_on")], 7_200_000),
                NOW,
            )
            .unwrap();
        assert_eq!(child.expires_at_ms, parent.expires_at_ms);
        assert_eq!(child.depth, 2);
        let child_v = v.verify(&child.bytes).unwrap();
        assert_eq!(child_v.issuer, bob);
        assert_eq!(child_v.parents, vec![parent.revocation_id.clone()]);

        // amplification
        let err = auth
            .delegate(&parent, &bob, &grant("ai:assistant", vec![right("device:door", "lock.unlock")], 60_000), NOW)
            .unwrap_err();
        assert!(matches!(err, DelegationError::NotSubset(_)));
        // only the holder may delegate
        let err = auth
            .delegate(&parent, &id("person:mallory"), &grant("ai:assistant", parent.rights.clone(), 60_000), NOW)
            .unwrap_err();
        assert!(matches!(err, DelegationError::NotHolder(_)));
        // no self delegation
        let err = auth.delegate(&parent, &bob, &grant("person:bob", parent.rights.clone(), 60_000), NOW).unwrap_err();
        assert_eq!(err, DelegationError::SelfDelegation);
        // expired parent
        let err = auth
            .delegate(&parent, &bob, &grant("ai:assistant", parent.rights.clone(), 60_000), NOW + 3_600_000)
            .unwrap_err();
        assert_eq!(err, DelegationError::ParentExpired);
        // attenuated parents cannot be re-delegated (their checks would be lost)
        let att = attenuate(
            &v.verify(&child.bytes).unwrap().biscuit.to_vec().unwrap(),
            &auth.public_key(),
            &Restriction { not_after_ms: Some(NOW + 1_000), ..Default::default() },
        )
        .unwrap();
        let att = v.verify(&att).unwrap();
        let err =
            auth.delegate(&att, &id("ai:assistant"), &grant("ai:helper", att.rights.clone(), 60_000), NOW).unwrap_err();
        assert_eq!(err, DelegationError::AttenuatedParent);
    }

    #[test]
    fn depth_is_bounded() {
        let auth = authority();
        let v = auth.verifier();
        let rights = vec![right("device:light-1", "light.turn_on")];
        let names = ["person:p0", "person:p1", "person:p2", "person:p3", "person:p4"];
        let mut tok = v
            .verify(
                &auth
                    .issue(
                        &Grant {
                            holder: id(names[1]),
                            issuer: id(names[0]),
                            rights: rights.clone(),
                            not_after_ms: NOW + 60_000,
                        },
                        NOW,
                    )
                    .unwrap()
                    .bytes,
            )
            .unwrap();
        for i in 2..=MAX_DELEGATION_DEPTH as usize {
            let next = auth.delegate(&tok, &id(names[i - 1]), &grant(names[i], rights.clone(), 60_000), NOW).unwrap();
            tok = v.verify(&next.bytes).unwrap();
            assert_eq!(tok.depth as usize, i);
        }
        let err = auth
            .delegate(&tok, &id(names[MAX_DELEGATION_DEPTH as usize]), &grant(names[4], rights, 60_000), NOW)
            .unwrap_err();
        assert_eq!(err, DelegationError::TooDeep(MAX_DELEGATION_DEPTH + 1));
    }

    #[test]
    fn revocation_cascades_to_children() {
        let auth = authority();
        let v = auth.verifier();
        let parent = v
            .verify(
                &auth
                    .issue(
                        &Grant {
                            holder: id("person:bob"),
                            issuer: id("person:alice"),
                            rights: vec![right("device:light-1", "light.turn_on")],
                            not_after_ms: NOW + 60_000,
                        },
                        NOW,
                    )
                    .unwrap()
                    .bytes,
            )
            .unwrap();
        let child = auth
            .delegate(&parent, &id("person:bob"), &grant("ai:assistant", parent.rights.clone(), 60_000), NOW)
            .unwrap();
        let child = v.verify(&child.bytes).unwrap();
        let mut rl = RevocationList::new();
        assert!(!rl.is_revoked(&child));
        assert!(rl.revoke(&parent.revocation_id.to_uppercase()));
        assert!(!rl.revoke(&parent.revocation_id));
        assert!(rl.is_revoked(&parent));
        assert!(rl.is_revoked(&child));
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        const TARGETS: [&str; 3] = ["device:a", "device:b", "device:c"];
        const CAPS: [&str; 3] = ["light.turn_on", "light.turn_off", "lock.unlock"];

        fn all_rights() -> Vec<Right> {
            TARGETS.iter().flat_map(|t| CAPS.iter().map(move |c| right(t, c))).collect()
        }

        fn subset(mask: u16) -> Vec<Right> {
            all_rights().into_iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, r)| r).collect()
        }

        proptest! {
            #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

            /// v8 §8: child_scope ⊆ parent_scope and child_expiry ≤ parent_expiry,
            /// and a delegated token never authorizes anything the parent does not.
            #[test]
            fn delegation_never_amplifies(parent_mask in 1u16..512, child_mask in 1u16..512,
                                          parent_ttl in 1u64..100_000, child_ttl in 1u64..200_000) {
                let auth = authority();
                let v = auth.verifier();
                let parent_rights = subset(parent_mask);
                let child_rights = subset(child_mask);
                let parent = v.verify(&auth.issue(&Grant {
                    holder: id("person:bob"), issuer: id("person:alice"),
                    rights: parent_rights.clone(), not_after_ms: NOW + parent_ttl * 1000,
                }, NOW).unwrap().bytes).unwrap();
                let res = auth.delegate(&parent, &id("person:bob"),
                    &grant("ai:assistant", child_rights.clone(), child_ttl * 1000), NOW);
                let is_subset = child_rights.iter().all(|r| parent_rights.contains(r));
                prop_assert_eq!(res.is_ok(), is_subset);
                if let Ok(child) = res {
                    prop_assert!(child.expires_at_ms <= parent.expires_at_ms);
                    let child = v.verify(&child.bytes).unwrap();
                    let ai = id("ai:assistant");
                    for r in all_rights() {
                        let allowed = child.authorize(&ai, &r.target, &r.capability, NOW).is_ok();
                        prop_assert!(!allowed || parent_rights.contains(&r));
                        prop_assert_eq!(allowed, child_rights.contains(&r));
                    }
                }
            }
        }
    }
}
