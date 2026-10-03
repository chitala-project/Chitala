//! Identity (spec `specs/02-identity.md`).
//!
//! Every principal (person, AI, service, device) has its own Ed25519 key. There is
//! no shared secret and no global master key. The key id (`kid`) is the first 16
//! bytes of SHA-256 over the raw 32-byte public key.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};

use chitala_model::{EntityId, EntityKind, SecurityState};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const KEY_ID_LEN: usize = 16;
pub type KeyId = [u8; KEY_ID_LEN];
pub type PublicKey = [u8; 32];

/// Prefix used to derive deterministic test keys (spec §02 "Test keys").
pub const TEST_SEED_PREFIX: &str = "chitala-test-vector:";

/// Deterministic 32-byte seed for test vectors: `SHA-256("chitala-test-vector:" || label)`.
/// MUST NOT be used outside tests and conformance vectors.
pub fn test_seed(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TEST_SEED_PREFIX.as_bytes());
    h.update(label.as_bytes());
    h.finalize().into()
}

pub fn key_id_of(public_key: &PublicKey) -> KeyId {
    let digest = Sha256::digest(public_key);
    let mut kid = [0u8; KEY_ID_LEN];
    kid.copy_from_slice(&digest[..KEY_ID_LEN]);
    kid
}

/// Verify an Ed25519 signature over `msg`. Returns `false` on any malformed input.
pub fn verify(public_key: &PublicKey, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

#[derive(Clone)]
pub struct Keypair {
    sk: SigningKey,
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never print private material
        write!(f, "Keypair(kid={})", hex::encode(self.key_id()))
    }
}

impl Keypair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { sk: SigningKey::from_bytes(seed) }
    }

    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    pub fn public_key(&self) -> PublicKey {
        self.sk.verifying_key().to_bytes()
    }

    pub fn key_id(&self) -> KeyId {
        key_id_of(&self.public_key())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sk.sign(msg).to_bytes()
    }

    /// Raw private seed. Exposed only so the token crate can derive a Biscuit key
    /// from the same seed; never log it.
    pub fn seed(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Principal {
    pub id: EntityId,
    #[serde(with = "hex_bytes")]
    pub public_key: PublicKey,
    #[serde(with = "hex_bytes")]
    pub key_id: KeyId,
    pub roles: Vec<String>,
    pub state: SecurityState,
}

mod hex_bytes {
    pub fn serialize<S: serde::Serializer, const N: usize>(b: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnrollError {
    #[error("{0} is already enrolled")]
    DuplicateId(EntityId),
    #[error("key {0} is already bound to another principal")]
    DuplicateKey(String),
    #[error("entity kind {0} cannot be a principal")]
    NotAPrincipal(EntityKind),
    #[error("invalid role name {0:?}")]
    InvalidRole(String),
    #[error("role {role:?} is not allowed for {kind} principals")]
    ForbiddenRole { kind: EntityKind, role: String },
    #[error("{0} is not enrolled")]
    Unknown(EntityId),
}

/// Roles that only a human may hold (Security Constitution C1/C11: an AI never
/// becomes owner or admin of a domain).
pub const HUMAN_ONLY_ROLES: &[&str] = &["owner", "admin"];

fn valid_role(r: &str) -> bool {
    let b = r.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b[1..].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

#[derive(Debug, Default, Clone)]
pub struct IdentityRegistry {
    by_id: BTreeMap<EntityId, Principal>,
    by_kid: HashMap<KeyId, EntityId>,
}

impl IdentityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enroll(&mut self, id: EntityId, public_key: PublicKey, roles: &[&str]) -> Result<&Principal, EnrollError> {
        if id.kind() == EntityKind::Domain {
            return Err(EnrollError::NotAPrincipal(id.kind()));
        }
        for r in roles {
            if !valid_role(r) {
                return Err(EnrollError::InvalidRole(r.to_string()));
            }
            if id.kind() != EntityKind::Person && HUMAN_ONLY_ROLES.contains(r) {
                return Err(EnrollError::ForbiddenRole { kind: id.kind(), role: r.to_string() });
            }
        }
        if self.by_id.contains_key(&id) {
            return Err(EnrollError::DuplicateId(id));
        }
        let kid = key_id_of(&public_key);
        if self.by_kid.contains_key(&kid) {
            return Err(EnrollError::DuplicateKey(hex::encode(kid)));
        }
        let principal = Principal {
            id: id.clone(),
            public_key,
            key_id: kid,
            roles: roles.iter().map(|r| r.to_string()).collect(),
            state: SecurityState::Trusted,
        };
        self.by_kid.insert(kid, id.clone());
        Ok(self.by_id.entry(id).or_insert(principal))
    }

    pub fn get(&self, id: &EntityId) -> Option<&Principal> {
        self.by_id.get(id)
    }

    pub fn by_key_id(&self, kid: &[u8]) -> Option<&Principal> {
        let kid: KeyId = kid.try_into().ok()?;
        self.by_kid.get(&kid).and_then(|id| self.by_id.get(id))
    }

    pub fn set_state(&mut self, id: &EntityId, state: SecurityState) -> Result<(), EnrollError> {
        let p = self.by_id.get_mut(id).ok_or_else(|| EnrollError::Unknown(id.clone()))?;
        p.state = state;
        Ok(())
    }

    pub fn principals(&self) -> impl Iterator<Item = &Principal> {
        self.by_id.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }

    #[test]
    fn test_seed_is_stable() {
        // Pinned value: implementations in other languages must derive the same seed.
        assert_eq!(
            hex::encode(test_seed("person:alice")),
            hex::encode(Sha256::digest(b"chitala-test-vector:person:alice"))
        );
        let kp = Keypair::from_seed(&test_seed("person:alice"));
        assert_eq!(kp.key_id(), key_id_of(&kp.public_key()));
    }

    #[test]
    fn sign_and_verify() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"hello");
        assert!(verify(&kp.public_key(), b"hello", &sig));
        assert!(!verify(&kp.public_key(), b"hellO", &sig));
        assert!(!verify(&kp.public_key(), b"hello", &sig[..63]));
    }

    #[test]
    fn ai_cannot_be_owner() {
        let mut reg = IdentityRegistry::new();
        let err = reg.enroll(id("ai:assistant"), Keypair::generate().public_key(), &["owner"]).unwrap_err();
        assert!(matches!(err, EnrollError::ForbiddenRole { .. }));
        assert!(reg.enroll(id("person:alice"), Keypair::generate().public_key(), &["owner"]).is_ok());
    }

    #[test]
    fn duplicate_ids_and_keys_rejected() {
        let mut reg = IdentityRegistry::new();
        let k = Keypair::generate();
        reg.enroll(id("person:alice"), k.public_key(), &[]).unwrap();
        assert!(matches!(
            reg.enroll(id("person:alice"), Keypair::generate().public_key(), &[]),
            Err(EnrollError::DuplicateId(_))
        ));
        assert!(matches!(reg.enroll(id("person:bob"), k.public_key(), &[]), Err(EnrollError::DuplicateKey(_))));
        assert!(reg.by_key_id(&k.key_id()).is_some());
        assert!(reg.by_key_id(&[0u8; 3]).is_none());
    }
}
