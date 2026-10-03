//! A software key store on top of any [`Storage`]: Ed25519 seeds as hex in
//! private objects `keys/<name>.key`. Exportable, not hardware-backed — the
//! honest description of what a key file is (v20 §12 asks to move to
//! hardware-backed keys over time; that is another `SecureKeyStore`).

use std::sync::Arc;

use crate::{
    Entropy, KeyRef, KeyStoreInfo, PlatformError, Result, SecureKeyStore, SeedSigner, Signer, Storage, StoragePath,
    Visibility,
};

pub struct SoftwareKeyStore {
    storage: Arc<dyn Storage>,
    entropy: Arc<dyn Entropy>,
    dir: StoragePath,
}

impl SoftwareKeyStore {
    /// Keys live under `dir` (created private if missing).
    pub fn new(storage: Arc<dyn Storage>, entropy: Arc<dyn Entropy>, dir: StoragePath) -> Result<Self> {
        storage.ensure_dir(&dir, Visibility::Private)?;
        Ok(Self { storage, entropy, dir })
    }

    fn path(&self, key: &KeyRef) -> Result<StoragePath> {
        self.dir.join(&format!("{key}.key"))
    }

    fn seed(&self, key: &KeyRef) -> Result<[u8; 32]> {
        let bytes = self
            .storage
            .read(&self.path(key)?, Visibility::Private)?
            .ok_or_else(|| PlatformError::NotFound(format!("key {key}")))?;
        let text = std::str::from_utf8(&bytes).map_err(|_| PlatformError::Invalid(format!("key {key} is not text")))?;
        decode_hex32(text.trim()).ok_or_else(|| PlatformError::Invalid(format!("key {key} must hold 32 bytes of hex")))
    }

    /// Store a known seed (domain setup from an existing key, test vectors).
    pub fn import(&self, key: &KeyRef, seed: &[u8; 32]) -> Result<[u8; 32]> {
        self.storage.create_new(&self.path(key)?, format!("{}\n", encode_hex(seed)).as_bytes(), Visibility::Private)?;
        Ok(SeedSigner::from_seed(seed).public_key())
    }
}

impl SecureKeyStore for SoftwareKeyStore {
    fn info(&self) -> KeyStoreInfo {
        KeyStoreInfo { hardware_backed: false, exportable: true }
    }
    fn contains(&self, key: &KeyRef) -> Result<bool> {
        self.storage.exists(&self.path(key)?)
    }
    fn generate(&self, key: &KeyRef) -> Result<[u8; 32]> {
        let seed = crate::random_array(&*self.entropy);
        self.import(key, &seed)
    }
    fn signer(&self, key: &KeyRef) -> Result<Arc<dyn Signer>> {
        Ok(Arc::new(SeedSigner::from_seed(&self.seed(key)?)))
    }
    fn export_seed(&self, key: &KeyRef) -> Result<[u8; 32]> {
        self.seed(key)
    }
}

fn encode_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryStorage, SeededEntropy};

    #[test]
    fn software_key_store_passes_the_contract_and_refuses_weak_keys() {
        let storage = Arc::new(MemoryStorage::new());
        let ks = SoftwareKeyStore::new(
            storage.clone(),
            Arc::new(SeededEntropy::new("ks")),
            StoragePath::new("keys").unwrap(),
        )
        .unwrap();
        crate::contract::key_store(&ks);
        let k = KeyRef::new("person-alice").unwrap();
        ks.generate(&k).unwrap();
        storage.weaken(&StoragePath::new("keys/person-alice.key").unwrap());
        assert!(matches!(ks.signer(&k), Err(PlatformError::Insecure(_))));
        assert_eq!(decode_hex32("zz"), None);
    }
}
