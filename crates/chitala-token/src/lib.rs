//! Capability tokens (spec `specs/05-capability-token.md`).
//!
//! A token is a Biscuit token signed by the *domain authority key* (never by a
//! global key: Security Constitution C7). Its authority block (format 2) binds it
//! to one holder **and that holder's key**, to the person it may act for, to a
//! time window, and lists explicit `right(target, capability)` facts:
//!
//! ```text
//! chitala_token(2);
//! holder("ai:assistant");  holder_key("<hex key id>");   // proof of possession
//! issuer("person:alice");  depth(1);  redelegate(0);     // 0 = non-transferable
//! for("person:alice");                                    // context: acts only for alice
//! not_before_ms(…);  expires_ms(…);  issued_epoch(41);   // window; revocation epoch
//! chain("person:alice");                                  // every issuer up to the root
//! right("resource:living-room", "light.turn_on");
//! parent("<revocation id of the parent token>");          // only for re-delegations
//! check if time($t), $t < 2026-10-04T11:00:00Z;
//! ```
//!
//! Attenuation blocks appended by the holder can only add checks, so a holder can
//! narrow a token offline but never widen it (v8 §8: no privilege amplification).
//! Handing a right to *another* principal is server-mediated: the domain authority
//! issues a fresh token after checking child ⊆ parent, the parent's re-delegation
//! budget, expiry ≤ parent expiry, a window inside the parent's, the same or a
//! narrower `for` binding, and depth ≤ [`MAX_DELEGATION_DEPTH`].

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_auth::builder::{fact, string, BlockBuilder, Term};
use biscuit_auth::datalog::SymbolTable;
use biscuit_auth::{
    Algorithm, AuthorizerBuilder, AuthorizerLimits, Biscuit, KeyPair as BiscuitKeyPair, PrivateKey,
    PublicKey as BiscuitPublicKey, UnverifiedBiscuit,
};
use chitala_identity::{KeyId, Keypair, PublicKey};
use chitala_model::{CapabilityId, EntityId, EntityKind};
use chitala_platform::{random_array, Entropy};
use serde::{Deserialize, Serialize};

/// Value of the `chitala_token(..)` fact. Bumped on incompatible changes;
/// tokens of any other format are refused.
pub const TOKEN_FORMAT: i64 = 2;
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
    /// Key id of the holder's enrolled key. The token works only in a message
    /// signed with that key (proof of possession): a stolen token is useless,
    /// and re-enrolling a principal with a new key retires its old tokens.
    pub holder_key: KeyId,
    /// The principal on whose authority the token is issued (the delegator).
    pub issuer: EntityId,
    pub rights: Vec<Right>,
    /// Start of the validity window (0 = from issue).
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    /// How many further hops the holder may hand the right on (0 = the token
    /// is non-transferable).
    pub redelegate: u8,
    /// For an AI holder: the persons it may use the token for (context
    /// binding). Must be empty for persons, devices and services, who
    /// represent nobody but themselves.
    pub for_persons: Vec<EntityId>,
    /// The domain's revocation epoch at issue: revoking "everything issued
    /// before epoch N" for a principal or the whole domain is one floor.
    pub issued_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub bytes: Vec<u8>,
    pub base64: String,
    /// Hex revocation id of the authority block; identifies the token.
    pub revocation_id: String,
    pub expires_at_ms: u64,
    pub depth: u8,
    /// The persons the token may act for (empty: unbound).
    pub for_persons: Vec<EntityId>,
    pub redelegate: u8,
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
    #[error("the parent token is non-transferable: its holder may not hand it on")]
    NotTransferable,
    #[error("the parent token is bound to acting for {0}; it can only be handed to another agent acting for them")]
    BindingWidened(String),
    #[error("the parent token cannot be used by its holder right now: {0}")]
    ParentUnusable(String),
    #[error("binding: {0}")]
    Binding(String),
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

/// The single-use key pair Biscuit chains each block to, drawn from the
/// platform's entropy instead of the OS RNG Biscuit would use on its own.
fn ephemeral(entropy: &dyn Entropy) -> BiscuitKeyPair {
    let seed: [u8; 32] = random_array(entropy);
    let sk = PrivateKey::from_bytes(&seed, Algorithm::Ed25519).expect("any 32 bytes are an Ed25519 seed");
    BiscuitKeyPair::from(&sk)
}

fn to_biscuit_public(pk: &PublicKey) -> BiscuitPublicKey {
    BiscuitPublicKey::from_bytes(pk, Algorithm::Ed25519).expect("32-byte Ed25519 public key is always accepted")
}

/// The domain's token issuer. Holds the domain authority private key.
pub struct TokenAuthority {
    kp: BiscuitKeyPair,
    public_key: PublicKey,
    entropy: Arc<dyn Entropy>,
}

impl TokenAuthority {
    /// `entropy` is the platform's (PAL, spec 18); tokens are reproducible for a
    /// deterministic source, which makes test vectors possible.
    pub fn new(authority_key: &Keypair, entropy: Arc<dyn Entropy>) -> Self {
        Self { kp: to_biscuit_private(authority_key), public_key: authority_key.public_key(), entropy }
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
        self.build(grant, 1, &[], &grant.for_persons, std::slice::from_ref(&grant.issuer), now_ms)
    }

    /// Server-mediated re-delegation of (a subset of) `parent` by its holder,
    /// who proves possession with the key `delegator_key` (the key that signed
    /// the delegation request).
    pub fn delegate(
        &self,
        parent: &VerifiedToken,
        delegator: &EntityId,
        delegator_key: &KeyId,
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
        if parent.redelegate == 0 {
            return Err(DelegationError::NotTransferable);
        }
        // the binding never widens: a token that acts for someone stays one,
        // for the same people or fewer
        let binding = if parent.for_persons.is_empty() {
            child.for_persons.clone()
        } else if child.holder.kind() != EntityKind::Ai {
            return Err(DelegationError::BindingWidened(names(&parent.for_persons)));
        } else if child.for_persons.is_empty() {
            parent.for_persons.clone()
        } else if child.for_persons.iter().all(|p| parent.for_persons.contains(p)) {
            child.for_persons.clone()
        } else {
            return Err(DelegationError::BindingWidened(names(&parent.for_persons)));
        };
        for r in &child.rights {
            if !parent.rights.contains(r) {
                return Err(DelegationError::NotSubset(r.clone()));
            }
            // defense in depth: the parent must actually authorize the right now,
            // for its holder, with the holder's key
            let use_ = Presentation {
                actor: delegator,
                key_id: delegator_key,
                on_behalf_of: parent.for_persons.first(),
                target: &r.target,
                capability: &r.capability,
                now_ms,
            };
            parent.authorize(&use_).map_err(|e| DelegationError::ParentUnusable(e.to_string()))?;
        }
        let depth = parent.depth.saturating_add(1);
        if depth > MAX_DELEGATION_DEPTH {
            return Err(DelegationError::TooDeep(depth));
        }
        let grant = Grant {
            holder: child.holder.clone(),
            holder_key: child.holder_key,
            issuer: delegator.clone(),
            rights: child.rights.clone(),
            not_before_ms: child.not_before_ms.max(parent.not_before_ms),
            not_after_ms: child.not_after_ms.min(parent.expires_at_ms),
            redelegate: child.redelegate.min(parent.redelegate - 1),
            issued_epoch: child.issued_epoch,
            for_persons: binding.clone(),
        };
        let mut parents = parent.parents.clone();
        parents.push(parent.revocation_id.clone());
        let mut chain = parent.chain.clone();
        chain.push(delegator.clone());
        self.build(&grant, depth, &parents, &binding, &chain, now_ms)
    }

    fn build(
        &self,
        grant: &Grant,
        depth: u8,
        parents: &[String],
        binding: &[EntityId],
        chain: &[EntityId],
        now_ms: u64,
    ) -> Result<IssuedToken, DelegationError> {
        if grant.holder == grant.issuer {
            return Err(DelegationError::SelfDelegation);
        }
        let rights: BTreeSet<&Right> = grant.rights.iter().collect();
        if rights.is_empty() || rights.len() > MAX_RIGHTS {
            return Err(DelegationError::RightsCount);
        }
        let exp = align_expiry(grant.not_after_ms);
        if exp <= now_ms || grant.not_before_ms >= exp {
            return Err(DelegationError::InvalidExpiry);
        }
        if grant.redelegate.saturating_add(depth) > MAX_DELEGATION_DEPTH {
            return Err(DelegationError::TooDeep(grant.redelegate.saturating_add(depth)));
        }
        if binding.iter().any(|p| p.kind() != EntityKind::Person) {
            return Err(DelegationError::Binding("a token can only act for persons".into()));
        }
        if grant.holder.kind() == EntityKind::Ai && binding.is_empty() {
            return Err(DelegationError::Binding(format!("say for whom {} may use the right", grant.holder)));
        }
        if grant.holder.kind() != EntityKind::Ai && !binding.is_empty() {
            return Err(DelegationError::Binding(format!("{} acts for nobody but itself", grant.holder)));
        }
        let build_err = |e: biscuit_auth::error::Token| DelegationError::Build(e.to_string());

        let params = HashMap::from([
            ("fmt".to_string(), Term::from(TOKEN_FORMAT)),
            ("holder".to_string(), Term::from(grant.holder.to_string())),
            ("holder_key".to_string(), Term::from(hex::encode(grant.holder_key))),
            ("issuer".to_string(), Term::from(grant.issuer.to_string())),
            ("depth".to_string(), Term::from(depth as i64)),
            ("redelegate".to_string(), Term::from(grant.redelegate as i64)),
            ("nbf_ms".to_string(), Term::from(grant.not_before_ms as i64)),
            ("exp_ms".to_string(), Term::from(exp as i64)),
            ("epoch".to_string(), Term::from(grant.issued_epoch as i64)),
            ("nbf".to_string(), Term::from(date(grant.not_before_ms))),
            ("exp".to_string(), Term::from(date(exp))),
        ]);
        let mut builder = Biscuit::builder()
            .code_with_params(
                r#"
                chitala_token({fmt});
                holder({holder});
                holder_key({holder_key});
                issuer({issuer});
                depth({depth});
                redelegate({redelegate});
                not_before_ms({nbf_ms});
                expires_ms({exp_ms});
                issued_epoch({epoch});
                check if time($t), $t >= {nbf}, $t < {exp};
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
        for p in binding {
            builder = builder.fact(fact("for", &[string(&p.to_string())])).map_err(build_err)?;
        }
        for c in chain {
            builder = builder.fact(fact("chain", &[string(&c.to_string())])).map_err(build_err)?;
        }
        for p in parents {
            builder = builder.fact(fact("parent", &[string(p)])).map_err(build_err)?;
        }
        let next = ephemeral(&*self.entropy);
        let biscuit = builder.build_with_key_pair(&self.kp, SymbolTable::new(), &next).map_err(build_err)?;
        let bytes = biscuit.to_vec().map_err(build_err)?;
        let base64 = biscuit.to_base64().map_err(build_err)?;
        let revocation_id = hex::encode(&biscuit.revocation_identifiers()[0]);
        Ok(IssuedToken {
            bytes,
            base64,
            revocation_id,
            expires_at_ms: exp,
            depth,
            for_persons: binding.to_vec(),
            redelegate: grant.redelegate,
        })
    }
}

fn names(ids: &[EntityId]) -> String {
    ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
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

pub fn attenuate(
    token: &[u8],
    domain_key: &PublicKey,
    restriction: &Restriction,
    entropy: &dyn Entropy,
) -> Result<Vec<u8>, TokenError> {
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
    biscuit.append_with_keypair(&ephemeral(entropy), block).and_then(|b| b.to_vec()).map_err(invalid)
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
        let not_before_ms = u64::try_from(one_int(&mut a, "data($v) <- not_before_ms($v)")?)
            .map_err(|_| TokenError::Invalid("negative start".into()))?;
        let issued_epoch = u64::try_from(one_int(&mut a, "data($v) <- issued_epoch($v)")?)
            .map_err(|_| TokenError::Invalid("negative epoch".into()))?;
        let redelegate = u8::try_from(one_int(&mut a, "data($v) <- redelegate($v)")?)
            .ok()
            .filter(|r| r.saturating_add(depth) <= MAX_DELEGATION_DEPTH)
            .ok_or_else(|| TokenError::Invalid("bad re-delegation budget".into()))?;
        let holder_key: KeyId = hex::decode(one_str(&mut a, "data($v) <- holder_key($v)")?)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| TokenError::Invalid("bad holder key".into()))?;
        let ids = |a: &mut biscuit_auth::Authorizer, rule: &str| -> Result<Vec<EntityId>, TokenError> {
            let raw: Vec<(String,)> = a.query(rule).map_err(invalid)?;
            let mut out = raw.into_iter().map(|(v,)| parse_id(v)).collect::<Result<Vec<_>, _>>()?;
            out.sort();
            Ok(out)
        };
        let for_persons = ids(&mut a, "data($v) <- for($v)")?;
        if for_persons.iter().any(|p| p.kind() != EntityKind::Person) {
            return Err(TokenError::Invalid("a token can only act for persons".into()));
        }
        let chain = ids(&mut a, "data($v) <- chain($v)")?;
        if chain.is_empty() || chain.len() > MAX_DELEGATION_DEPTH as usize {
            return Err(TokenError::Invalid("bad issuer chain".into()));
        }
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
            holder_key,
            issuer,
            depth,
            redelegate,
            for_persons,
            not_before_ms,
            expires_at_ms,
            issued_epoch,
            chain,
            rights,
            parents,
        })
    }
}

/// One use of a token: who presents it, with which key, for whom, for what.
#[derive(Debug, Clone, Copy)]
pub struct Presentation<'a> {
    pub actor: &'a EntityId,
    /// Key id of the key that signed the message carrying the token.
    pub key_id: &'a KeyId,
    /// The person the actor acts for in this message, if it represents one.
    pub on_behalf_of: Option<&'a EntityId>,
    pub target: &'a EntityId,
    pub capability: &'a CapabilityId,
    pub now_ms: u64,
}

/// A token whose signature chain has been verified. Authorization of a concrete
/// request is a separate step ([`VerifiedToken::authorize`]).
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    biscuit: Biscuit,
    pub holder: EntityId,
    /// The holder's key the token is bound to (proof of possession).
    pub holder_key: KeyId,
    pub issuer: EntityId,
    pub depth: u8,
    /// Further hops the holder may delegate (0 = non-transferable).
    pub redelegate: u8,
    /// The persons the holder may act for with it (empty: unbound).
    pub for_persons: Vec<EntityId>,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    /// The domain's revocation epoch when the token was issued.
    pub issued_epoch: u64,
    /// Every issuer from the root grant down to this token's issuer.
    pub chain: Vec<EntityId>,
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
    /// Evaluate all blocks (authority + attenuations) for one concrete use.
    /// The token is bound to its holder, the holder's key, the persons it may
    /// act for, and its validity window.
    pub fn authorize(&self, p: &Presentation<'_>) -> Result<(), TokenError> {
        let (actor, target, capability, now_ms) = (p.actor, p.target, p.capability, p.now_ms);
        if *actor != self.holder {
            return Err(TokenError::Denied(format!("token is bound to {}, not {actor}", self.holder)));
        }
        if *p.key_id != self.holder_key {
            return Err(TokenError::Denied(format!(
                "token is bound to another key of {} (proof of possession failed)",
                self.holder
            )));
        }
        if !self.for_persons.is_empty() && !p.on_behalf_of.is_some_and(|who| self.for_persons.contains(who)) {
            return Err(TokenError::Denied(format!(
                "token acts only for {}{}",
                names(&self.for_persons),
                p.on_behalf_of.map(|w| format!(", not for {w}")).unwrap_or_default()
            )));
        }
        if now_ms < self.not_before_ms {
            return Err(TokenError::Denied("token is not valid yet".into()));
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

    /// What revocation needs to know about this token, to re-check it later
    /// without the token itself (in-flight orders, spec 19).
    pub fn reference(&self) -> TokenRef {
        let mut principals: Vec<EntityId> = self.chain.iter().chain([&self.holder, &self.issuer]).cloned().collect();
        principals.sort();
        principals.dedup();
        TokenRef {
            revocation_id: self.revocation_id.clone(),
            revocation_ids: self.revocation_ids().map(str::to_string).collect(),
            principals,
            issued_epoch: self.issued_epoch,
            expires_at_ms: self.expires_at_ms,
        }
    }

    /// Human-readable Datalog of all blocks (for `chitala token inspect`).
    pub fn print(&self) -> String {
        self.biscuit.print()
    }
}

/// A used token, as far as revocation is concerned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRef {
    /// The token's own id.
    pub revocation_id: String,
    /// Its blocks and ancestors (cascade).
    pub revocation_ids: Vec<String>,
    /// Holder, issuer and every issuer up to the root.
    pub principals: Vec<EntityId>,
    pub issued_epoch: u64,
    /// Nothing may be done with the token's authority from this time on.
    pub expires_at_ms: u64,
}

/// Key of the domain-wide revocation floor in [`RevocationList`].
pub const EVERYONE: &str = "*";

/// Revoked tokens of a domain. Persisted by the node; checked on every use.
///
/// Two mechanisms, both immediate:
///
/// - **ids**: one token and, by cascade, everything delegated from it;
/// - **floors** (revocation epochs): every token issued before epoch `N` that
///   was held, issued or passed on by a principal — or every token of the
///   domain — without having to know their ids (a lost phone, a compromised
///   agent, a panic button).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    revoked: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    floors: BTreeMap<String, u64>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `false` if the id was already revoked.
    pub fn revoke(&mut self, revocation_id: &str) -> bool {
        self.revoked.insert(revocation_id.to_ascii_lowercase())
    }

    /// Revoke every token issued before `epoch` that `principal` holds, issued
    /// or passed on — or, with `None`, every token of the domain. Returns
    /// `false` if an equal or higher floor was already set.
    pub fn revoke_before(&mut self, principal: Option<&EntityId>, epoch: u64) -> bool {
        let key = principal.map_or_else(|| EVERYONE.to_string(), ToString::to_string);
        let floor = self.floors.entry(key).or_insert(0);
        if *floor >= epoch {
            return false;
        }
        *floor = epoch;
        true
    }

    /// The floor that applies to `principal` (or to the whole domain with `None`).
    pub fn floor(&self, principal: Option<&EntityId>) -> u64 {
        let key = principal.map_or_else(|| EVERYONE.to_string(), ToString::to_string);
        self.floors.get(&key).copied().unwrap_or(0)
    }

    pub fn contains(&self, revocation_id: &str) -> bool {
        self.revoked.contains(&revocation_id.to_ascii_lowercase())
    }

    /// Why `token` is revoked, if it is.
    pub fn revoked_because(&self, token: &VerifiedToken) -> Option<String> {
        self.revokes(&token.reference())
    }

    /// Why the token `r` refers to is revoked, if it is.
    pub fn revokes(&self, r: &TokenRef) -> Option<String> {
        if let Some(id) = r.revocation_ids.iter().find(|id| self.revoked.contains(*id)) {
            let own = *id == r.revocation_id;
            return Some(if own {
                "the token was revoked".into()
            } else {
                "a token it derives from was revoked".into()
            });
        }
        let below = |key: &str| self.floors.get(key).is_some_and(|f| r.issued_epoch < *f);
        if below(EVERYONE) {
            return Some("every token issued before it was revoked".into());
        }
        r.principals
            .iter()
            .find(|p| below(&p.to_string()))
            .map(|p| format!("every token of {p} issued before it was revoked"))
    }

    pub fn is_revoked(&self, token: &VerifiedToken) -> bool {
        self.revoked_because(token).is_some()
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty() && self.floors.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.revoked.iter().map(String::as_str)
    }

    pub fn floors(&self) -> impl Iterator<Item = (&str, u64)> {
        self.floors.iter().map(|(k, v)| (k.as_str(), *v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_identity::{key_id_of, test_seed};
    use chitala_platform::memory::test_entropy;

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
    /// Key id of a principal's (test) key.
    fn kid(who: &str) -> KeyId {
        key_id_of(&Keypair::from_seed(&test_seed(who)).public_key())
    }
    fn authority() -> TokenAuthority {
        TokenAuthority::new(&Keypair::from_seed(&test_seed("domain:home/authority")), Arc::new(test_entropy()))
    }
    fn grant_from(issuer: &str, holder: &str, rights: Vec<Right>, ttl_ms: u64) -> Grant {
        Grant {
            holder: id(holder),
            holder_key: kid(holder),
            issuer: id(issuer),
            rights,
            not_before_ms: 0,
            not_after_ms: NOW + ttl_ms,
            redelegate: 0,
            issued_epoch: 1,
            // an agent acts for the person who gave it the right
            for_persons: if holder.starts_with("ai:") { vec![id(issuer)] } else { vec![] },
        }
    }
    fn grant(holder: &str, rights: Vec<Right>, ttl_ms: u64) -> Grant {
        grant_from("person:alice", holder, rights, ttl_ms)
    }
    fn transferable(mut g: Grant, hops: u8) -> Grant {
        g.redelegate = hops;
        g
    }

    /// `actor` presents `v` with its own key, acting for `obo`.
    fn use_for(
        v: &VerifiedToken,
        actor: &str,
        obo: Option<&str>,
        target: &str,
        c: &str,
        now: u64,
    ) -> Result<(), TokenError> {
        let (actor, key, obo, target, c) = (id(actor), kid(actor), obo.map(id), id(target), cap(c));
        v.authorize(&Presentation {
            actor: &actor,
            key_id: &key,
            on_behalf_of: obo.as_ref(),
            target: &target,
            capability: &c,
            now_ms: now,
        })
    }
    /// Like [`use_for`], acting for the person the token is bound to (or nobody).
    fn use_(v: &VerifiedToken, actor: &str, target: &str, c: &str, now: u64) -> Result<(), TokenError> {
        let obo = v.for_persons.first().map(ToString::to_string);
        use_for(v, actor, obo.as_deref(), target, c, now)
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
        assert_eq!((v.redelegate, v.issued_epoch), (0, 1));
        assert_eq!(v.chain, vec![id("person:alice")]);
        let ai = "ai:assistant";
        assert!(use_(&v, ai, "device:light-1", "light.turn_on", NOW).is_ok());
        // other capability, other target, other actor, after expiry
        assert!(use_(&v, ai, "device:light-1", "light.turn_off", NOW).is_err());
        assert!(use_(&v, ai, "device:light-2", "light.turn_on", NOW).is_err());
        assert!(use_(&v, "ai:other", "device:light-1", "light.turn_on", NOW).is_err());
        assert!(use_(&v, ai, "device:light-1", "light.turn_on", NOW + 600_000).is_err());
        assert!(use_(&v, ai, "device:light-1", "light.turn_on", NOW + 599_999).is_ok());
    }

    #[test]
    fn proof_of_possession() {
        let auth = authority();
        let t =
            auth.issue(&grant("ai:assistant", vec![right("device:light-1", "light.turn_on")], 600_000), NOW).unwrap();
        let v = auth.verifier().verify(&t.bytes).unwrap();
        assert_eq!(v.holder_key, kid("ai:assistant"));
        // the right holder name, but a message signed with another key (a thief
        // with the token, or the agent after it was re-enrolled with a new key)
        let (ai, other_key, alice) = (id("ai:assistant"), kid("ai:assistant/rotated"), id("person:alice"));
        let err = v
            .authorize(&Presentation {
                actor: &ai,
                key_id: &other_key,
                on_behalf_of: Some(&alice),
                target: &id("device:light-1"),
                capability: &cap("light.turn_on"),
                now_ms: NOW,
            })
            .unwrap_err();
        assert!(err.to_string().contains("proof of possession"), "{err}");
    }

    #[test]
    fn an_agents_token_acts_only_for_the_person_who_gave_it() {
        let auth = authority();
        let t =
            auth.issue(&grant("ai:assistant", vec![right("device:light-1", "light.turn_on")], 600_000), NOW).unwrap();
        let v = auth.verifier().verify(&t.bytes).unwrap();
        assert_eq!(v.for_persons, vec![id("person:alice")]);
        assert!(use_for(&v, "ai:assistant", Some("person:alice"), "device:light-1", "light.turn_on", NOW).is_ok());
        let err = use_for(&v, "ai:assistant", Some("person:bob"), "device:light-1", "light.turn_on", NOW).unwrap_err();
        assert!(err.to_string().contains("acts only for person:alice"), "{err}");
        assert!(use_for(&v, "ai:assistant", None, "device:light-1", "light.turn_on", NOW).is_err());
        // a person's token is not bound: they act for themselves
        let t = auth.issue(&grant("person:bob", vec![right("device:light-1", "light.turn_on")], 600_000), NOW).unwrap();
        assert!(auth.verifier().verify(&t.bytes).unwrap().for_persons.is_empty());
    }

    #[test]
    fn a_validity_window() {
        let auth = authority();
        let mut g = grant("person:bob", vec![right("device:door", "lock.unlock")], 3_600_000);
        g.not_before_ms = NOW + 600_000;
        let v = auth.verifier().verify(&auth.issue(&g, NOW).unwrap().bytes).unwrap();
        assert!(use_(&v, "person:bob", "device:door", "lock.unlock", NOW).is_err(), "not yet");
        assert!(use_(&v, "person:bob", "device:door", "lock.unlock", NOW + 600_000).is_ok());
        assert!(use_(&v, "person:bob", "device:door", "lock.unlock", NOW + 3_600_000).is_err(), "over");
        // an empty window is refused
        g.not_before_ms = NOW + 3_600_000;
        assert_eq!(auth.issue(&g, NOW).unwrap_err(), DelegationError::InvalidExpiry);
    }

    #[test]
    fn tokens_of_another_format_are_refused() {
        let auth = authority();
        let old = Biscuit::builder()
            .code(
                r#"chitala_token(1); holder("ai:assistant"); issuer("person:alice"); depth(1);
                   expires_ms(1); right("device:light-1", "light.turn_on");"#,
            )
            .unwrap()
            .build_with_key_pair(&auth.kp, SymbolTable::new(), &ephemeral(test_entropy()))
            .unwrap()
            .to_vec()
            .unwrap();
        let err = auth.verifier().verify(&old).unwrap_err();
        assert!(err.to_string().contains("unsupported token format 1"), "{err}");
    }

    #[test]
    fn foreign_or_tampered_tokens_are_invalid() {
        let auth = authority();
        let other =
            TokenAuthority::new(&Keypair::from_seed(&test_seed("domain:evil/authority")), Arc::new(test_entropy()));
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
            test_entropy(),
        )
        .unwrap();
        let v = auth.verifier().verify(&narrowed).unwrap();
        let ai = "ai:assistant";
        assert_eq!(v.block_count, 2);
        assert!(use_(&v, ai, "device:light-1", "light.turn_on", NOW).is_ok());
        assert!(use_(&v, ai, "device:light-1", "light.set_brightness", NOW).is_err());

        // a shorter expiry in an attenuation block is enforced
        let short = attenuate(
            &t.bytes,
            &pk,
            &Restriction { not_after_ms: Some(NOW + 10_000), ..Default::default() },
            test_entropy(),
        )
        .unwrap();
        let v = auth.verifier().verify(&short).unwrap();
        assert!(use_(&v, ai, "device:light-1", "light.turn_on", NOW + 9_000).is_ok());
        assert!(use_(&v, ai, "device:light-1", "light.turn_on", NOW + 11_000).is_err());
    }

    #[test]
    fn attenuation_block_cannot_inject_rights_holder_key_or_binding() {
        let auth = authority();
        let t =
            auth.issue(&grant("ai:assistant", vec![right("device:light-1", "light.turn_on")], 600_000), NOW).unwrap();
        let b = Biscuit::from(&t.bytes, to_biscuit_public(&auth.public_key())).unwrap();
        let evil = BlockBuilder::new()
            .code(
                r#"
                right("device:front-door", "lock.unlock");
                holder("ai:intruder");
                holder_key("0000000000000000");
                for("person:mallory");
                redelegate(2);
                right($t, $c) <- target($t), capability($c);
                "#,
            )
            .unwrap();
        let forged = b.append(evil).unwrap().to_vec().unwrap();
        let v = auth.verifier().verify(&forged).unwrap();
        assert_eq!(v.holder, id("ai:assistant"));
        assert_eq!(v.holder_key, kid("ai:assistant"));
        assert_eq!(v.for_persons, vec![id("person:alice")]);
        assert_eq!(v.redelegate, 0);
        assert_eq!(v.rights, vec![right("device:light-1", "light.turn_on")]);
        assert!(use_(&v, "ai:assistant", "device:front-door", "lock.unlock", NOW).is_err());
        assert!(use_(&v, "ai:intruder", "device:light-1", "light.turn_on", NOW).is_err());
    }

    #[test]
    fn delegation_rules() {
        let auth = authority();
        let v = auth.verifier();
        let rights = vec![right("device:light-1", "light.turn_on"), right("device:light-1", "light.turn_off")];
        let parent = auth.issue(&transferable(grant("person:bob", rights, 3_600_000), 1), NOW).unwrap();
        let parent = v.verify(&parent.bytes).unwrap();
        let bob = id("person:bob");
        let bob_key = kid("person:bob");

        // subset with a longer ttl → expiry clipped to the parent's
        let mut for_bob = grant("ai:assistant", vec![right("device:light-1", "light.turn_on")], 7_200_000);
        for_bob.for_persons = vec![bob.clone()];
        let child = auth.delegate(&parent, &bob, &bob_key, &for_bob, NOW).unwrap();
        assert_eq!(child.expires_at_ms, parent.expires_at_ms);
        assert_eq!(child.depth, 2);
        let child_v = v.verify(&child.bytes).unwrap();
        assert_eq!(child_v.issuer, bob);
        assert_eq!(child_v.parents, vec![parent.revocation_id.clone()]);
        assert_eq!(child_v.chain, vec![id("person:alice"), bob.clone()]);
        // bob's agent acts for bob, not for alice who started the chain
        assert_eq!(child_v.for_persons, vec![bob.clone()]);
        assert_eq!(child_v.redelegate, 0, "the budget shrinks with every hop");

        // amplification
        let err = auth
            .delegate(
                &parent,
                &bob,
                &bob_key,
                &grant("ai:assistant", vec![right("device:door", "lock.unlock")], 60_000),
                NOW,
            )
            .unwrap_err();
        assert!(matches!(err, DelegationError::NotSubset(_)));
        // only the holder may delegate, and only with the holder's key
        let err = auth
            .delegate(
                &parent,
                &id("person:mallory"),
                &kid("person:mallory"),
                &grant("ai:assistant", parent.rights.clone(), 60_000),
                NOW,
            )
            .unwrap_err();
        assert!(matches!(err, DelegationError::NotHolder(_)));
        let err = auth
            .delegate(&parent, &bob, &kid("person:mallory"), &grant("ai:assistant", parent.rights.clone(), 60_000), NOW)
            .unwrap_err();
        assert!(matches!(err, DelegationError::ParentUnusable(_)), "{err}");
        // no self delegation
        let err = auth
            .delegate(&parent, &bob, &bob_key, &grant("person:bob", parent.rights.clone(), 60_000), NOW)
            .unwrap_err();
        assert_eq!(err, DelegationError::SelfDelegation);
        // expired parent
        let err = auth
            .delegate(&parent, &bob, &bob_key, &grant("ai:assistant", parent.rights.clone(), 60_000), NOW + 3_600_000)
            .unwrap_err();
        assert_eq!(err, DelegationError::ParentExpired);
        // attenuated parents cannot be re-delegated (their checks would be lost)
        let att = attenuate(
            &parent.biscuit.to_vec().unwrap(),
            &auth.public_key(),
            &Restriction { not_after_ms: Some(NOW + 1_000), ..Default::default() },
            test_entropy(),
        )
        .unwrap();
        let att = v.verify(&att).unwrap();
        let err =
            auth.delegate(&att, &bob, &bob_key, &grant("ai:helper", att.rights.clone(), 60_000), NOW).unwrap_err();
        assert_eq!(err, DelegationError::AttenuatedParent);
    }

    #[test]
    fn non_transferable_by_default() {
        let auth = authority();
        let v = auth.verifier();
        let rights = vec![right("device:door", "lock.unlock")];
        // the owner lets the guest in, but the guest cannot pass the key on
        let guest = v.verify(&auth.issue(&grant("person:guest", rights.clone(), 600_000), NOW).unwrap().bytes).unwrap();
        assert_eq!(guest.redelegate, 0);
        let err = auth
            .delegate(
                &guest,
                &id("person:guest"),
                &kid("person:guest"),
                &grant("person:friend", rights.clone(), 60_000),
                NOW,
            )
            .unwrap_err();
        assert_eq!(err, DelegationError::NotTransferable);
        // a budget is spent hop by hop and can never exceed the depth limit
        assert!(matches!(
            auth.issue(&transferable(grant("person:guest", rights.clone(), 600_000), MAX_DELEGATION_DEPTH), NOW),
            Err(DelegationError::TooDeep(_))
        ));
    }

    #[test]
    fn an_agents_binding_never_widens() {
        // were an agent ever allowed to hand a right on (C11 forbids it today),
        // the child would still act for the same person, and never for itself
        let auth = authority();
        let v = auth.verifier();
        let rights = vec![right("device:light-1", "light.turn_on")];
        let ai = v
            .verify(&auth.issue(&transferable(grant("ai:assistant", rights.clone(), 600_000), 2), NOW).unwrap().bytes)
            .unwrap();
        let (a, k) = (id("ai:assistant"), kid("ai:assistant"));
        let err = auth.delegate(&ai, &a, &k, &grant("person:mallory", rights.clone(), 60_000), NOW).unwrap_err();
        assert!(matches!(err, DelegationError::BindingWidened(_)), "{err}");
        let child = auth.delegate(&ai, &a, &k, &grant("ai:helper", rights.clone(), 60_000), NOW).unwrap();
        assert_eq!(v.verify(&child.bytes).unwrap().for_persons, vec![id("person:alice")]);
        let mut for_bob = grant("ai:helper", rights.clone(), 60_000);
        for_bob.for_persons = vec![id("person:bob")];
        assert!(matches!(auth.delegate(&ai, &a, &k, &for_bob, NOW), Err(DelegationError::BindingWidened(_))));
        // agents must be bound, everyone else must not be
        let mut unbound = grant("ai:helper", rights.clone(), 60_000);
        unbound.for_persons.clear();
        assert!(matches!(auth.issue(&unbound, NOW), Err(DelegationError::Binding(_))));
        let mut bound_person = grant("person:bob", rights, 60_000);
        bound_person.for_persons = vec![id("person:alice")];
        assert!(matches!(auth.issue(&bound_person, NOW), Err(DelegationError::Binding(_))));
    }

    #[test]
    fn depth_is_bounded() {
        let auth = authority();
        let v = auth.verifier();
        let rights = vec![right("device:light-1", "light.turn_on")];
        let names = ["person:p0", "person:p1", "person:p2", "person:p3", "person:p4"];
        let root = transferable(grant_from(names[0], names[1], rights.clone(), 60_000), MAX_DELEGATION_DEPTH - 1);
        let mut tok = v.verify(&auth.issue(&root, NOW).unwrap().bytes).unwrap();
        for i in 2..=MAX_DELEGATION_DEPTH as usize {
            let g = transferable(grant(names[i], rights.clone(), 60_000), MAX_DELEGATION_DEPTH);
            let next = auth.delegate(&tok, &id(names[i - 1]), &kid(names[i - 1]), &g, NOW).unwrap();
            tok = v.verify(&next.bytes).unwrap();
            assert_eq!(tok.depth as usize, i);
        }
        assert_eq!(tok.chain.len(), MAX_DELEGATION_DEPTH as usize);
        let last = id(names[MAX_DELEGATION_DEPTH as usize]);
        let err = auth
            .delegate(&tok, &last, &kid(names[MAX_DELEGATION_DEPTH as usize]), &grant(names[4], rights, 60_000), NOW)
            .unwrap_err();
        assert_eq!(err, DelegationError::NotTransferable, "the budget runs out with the depth");
    }

    #[test]
    fn revocation_cascades_to_children() {
        let auth = authority();
        let v = auth.verifier();
        let parent = v
            .verify(
                &auth
                    .issue(
                        &transferable(grant("person:bob", vec![right("device:light-1", "light.turn_on")], 60_000), 1),
                        NOW,
                    )
                    .unwrap()
                    .bytes,
            )
            .unwrap();
        let mut g = grant("ai:assistant", parent.rights.clone(), 60_000);
        g.for_persons = vec![id("person:bob")];
        let child = auth.delegate(&parent, &id("person:bob"), &kid("person:bob"), &g, NOW).unwrap();
        let child = v.verify(&child.bytes).unwrap();
        let mut rl = RevocationList::new();
        assert!(!rl.is_revoked(&child));
        assert!(rl.revoke(&parent.revocation_id.to_uppercase()));
        assert!(!rl.revoke(&parent.revocation_id));
        assert!(rl.is_revoked(&parent));
        assert_eq!(rl.revoked_because(&child).unwrap(), "a token it derives from was revoked");
    }

    #[test]
    fn revocation_floors_cut_everything_issued_before() {
        let auth = authority();
        let v = auth.verifier();
        let rights = vec![right("device:light-1", "light.turn_on")];
        let at = |epoch: u64, issuer: &str, holder: &str, hops: u8| {
            let mut g = transferable(grant_from(issuer, holder, rights.clone(), 60_000), hops);
            g.issued_epoch = epoch;
            v.verify(&auth.issue(&g, NOW).unwrap().bytes).unwrap()
        };
        let old_ai = at(5, "person:alice", "ai:assistant", 0);
        let new_ai = at(9, "person:alice", "ai:assistant", 0);
        let bobs = at(5, "person:alice", "person:bob", 1);
        let mut g = grant("ai:helper", rights.clone(), 60_000);
        g.for_persons = vec![id("person:bob")];
        let through_bob =
            v.verify(&auth.delegate(&bobs, &id("person:bob"), &kid("person:bob"), &g, NOW).unwrap().bytes).unwrap();

        let mut rl = RevocationList::new();
        // the agent's phone is lost: everything it holds from before epoch 8 dies
        assert!(rl.revoke_before(Some(&id("ai:assistant")), 8));
        assert!(rl.is_revoked(&old_ai));
        assert!(!rl.is_revoked(&new_ai), "tokens issued after the floor live");
        assert!(!rl.is_revoked(&bobs));
        // a floor on an issuer reaches everything handed on through them
        assert!(rl.revoke_before(Some(&id("person:bob")), 8));
        assert!(rl.is_revoked(&bobs));
        assert!(rl.revoked_because(&through_bob).unwrap().contains("person:bob"));
        // floors only rise
        assert!(!rl.revoke_before(Some(&id("person:bob")), 3));
        assert_eq!(rl.floor(Some(&id("person:bob"))), 8);
        // the panic button
        assert!(rl.revoke_before(None, 10));
        assert!(rl.is_revoked(&new_ai));
        // floors survive persistence
        let text = serde_json::to_string(&rl).unwrap();
        assert_eq!(serde_json::from_str::<RevocationList>(&text).unwrap(), rl);
        // and a list written before floors existed still reads
        assert!(serde_json::from_str::<RevocationList>(r#"{"revoked":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn tokens_draw_randomness_only_from_the_platform() {
        // Same authority key + same deterministic entropy ⇒ identical bytes. If
        // any code path fell back to the OS RNG (e.g. Biscuit's own `build` or
        // `append`), the bytes would differ: this is the behavioural half of the
        // core-purity check (scripts/core-purity.py, spec 18).
        use chitala_platform::memory::SeededEntropy;
        let key = Keypair::from_seed(&test_seed("domain:home/authority"));
        let g = grant("ai:assistant", vec![Right::new(id("device:light"), cap("light.turn_on"))], 60_000);
        let issue =
            |seed: &str| TokenAuthority::new(&key, Arc::new(SeededEntropy::new(seed))).issue(&g, NOW).unwrap().bytes;
        assert_eq!(issue("platform"), issue("platform"));
        assert_ne!(issue("platform"), issue("other"), "the block key chain comes from the given entropy");
        let token = issue("platform");
        let narrow = Restriction { not_after_ms: Some(NOW + 10_000), ..Default::default() };
        let att = |seed: &str| attenuate(&token, &key.public_key(), &narrow, &SeededEntropy::new(seed)).unwrap();
        assert_eq!(att("a"), att("a"));
        assert_ne!(att("a"), att("b"));
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

            /// v8 §8: child_scope ⊆ parent_scope, child window ⊆ parent window,
            /// and a delegated token never authorizes anything the parent does not.
            #[test]
            fn delegation_never_amplifies(parent_mask in 1u16..512, child_mask in 1u16..512,
                                          parent_ttl in 1u64..100_000, child_ttl in 1u64..200_000,
                                          child_start in 0u64..50_000) {
                let auth = authority();
                let v = auth.verifier();
                let parent_rights = subset(parent_mask);
                let child_rights = subset(child_mask);
                let parent = v.verify(&auth.issue(
                    &transferable(grant("person:bob", parent_rights.clone(), parent_ttl * 1000), 1), NOW,
                ).unwrap().bytes).unwrap();
                let mut g = grant("ai:assistant", child_rights.clone(), child_ttl * 1000);
                g.not_before_ms = NOW + child_start;
                g.for_persons = vec![id("person:bob")];
                let res = auth.delegate(&parent, &id("person:bob"), &kid("person:bob"), &g, NOW);
                let is_subset = child_rights.iter().all(|r| parent_rights.contains(r));
                let window = NOW + child_start < (NOW + parent_ttl * 1000).min(NOW + child_ttl * 1000) / 1000 * 1000;
                prop_assert_eq!(res.is_ok(), is_subset && window);
                if let Ok(child) = res {
                    prop_assert!(child.expires_at_ms <= parent.expires_at_ms);
                    let child = v.verify(&child.bytes).unwrap();
                    prop_assert!(child.not_before_ms >= parent.not_before_ms);
                    prop_assert_eq!(child.redelegate, 0);
                    for r in all_rights() {
                        let at = child.not_before_ms;
                        let allowed = use_(&child, "ai:assistant", &r.target.to_string(), r.capability.as_str(), at).is_ok();
                        prop_assert!(!allowed || parent_rights.contains(&r));
                        prop_assert_eq!(allowed, child_rights.contains(&r));
                    }
                }
            }
        }
    }
}
