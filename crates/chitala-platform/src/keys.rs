//! Keys (v20 §4 SecureKeyStore, §12 hardware-backed non-exportable credentials).
//!
//! The Trusted Core signs through [`Signer`] and never needs the private key
//! bytes. A software key store keeps seeds in protected storage; a TPM, Secure
//! Element or enclave backend keeps keys non-exportable and only signs.

use std::fmt;
use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};

use crate::{PlatformError, Result};

/// Name of a key inside a key store (`domain-authority`, `person-alice`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyRef(String);

impl KeyRef {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let b = name.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 128
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'));
        if ok {
            Ok(Self(name))
        } else {
            Err(PlatformError::Invalid(format!("key name {name:?}")))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Something that signs with an Ed25519 identity key.
pub trait Signer: Send + Sync {
    fn public_key(&self) -> [u8; 32];
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStoreInfo {
    /// Keys live in dedicated hardware (TPM, Secure Element, enclave).
    pub hardware_backed: bool,
    /// Private key material can leave the store ([`SecureKeyStore::export_seed`]).
    pub exportable: bool,
}

pub trait SecureKeyStore: Send + Sync {
    fn info(&self) -> KeyStoreInfo;

    fn contains(&self, key: &KeyRef) -> Result<bool>;

    /// Create a new key inside the store; `AlreadyExists` if the name is taken.
    /// Returns the public key.
    fn generate(&self, key: &KeyRef) -> Result<[u8; 32]>;

    /// A signer for an existing key; `NotFound` otherwise, `Insecure` if the
    /// stored key is not adequately protected.
    fn signer(&self, key: &KeyRef) -> Result<Arc<dyn Signer>>;

    fn public_key(&self, key: &KeyRef) -> Result<[u8; 32]> {
        Ok(self.signer(key)?.public_key())
    }

    /// The raw Ed25519 seed — `Unsupported` for non-exportable stores. Needed
    /// today only by the token authority (spec 14, decision D3).
    fn export_seed(&self, key: &KeyRef) -> Result<[u8; 32]>;
}

/// An Ed25519 key held in memory (software key stores, tests).
pub struct SeedSigner {
    sk: SigningKey,
}

impl SeedSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { sk: SigningKey::from_bytes(seed) }
    }

    pub fn generate(entropy: &dyn crate::Entropy) -> Self {
        Self { sk: SigningKey::from_bytes(&crate::random_array(entropy)) }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
}

impl fmt::Debug for SeedSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never print private material
        write!(f, "SeedSigner(public={:02x?})", &self.public_key()[..4])
    }
}

impl Signer for SeedSigner {
    fn public_key(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sk.sign(msg).to_bytes()
    }
}

/// Verify an Ed25519 signature (contract tests, backends).
pub fn verify(public_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier;
    ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map(|vk| vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok())
        .unwrap_or(false)
}
