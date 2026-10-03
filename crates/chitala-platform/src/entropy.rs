//! Randomness (v20 §4 Entropy).

/// A source of cryptographically secure random bytes.
///
/// `fill` cannot fail: a platform that cannot produce secure randomness must
/// panic rather than return weak bytes — the Trusted Core fails closed.
pub trait Entropy: Send + Sync {
    fn fill(&self, buf: &mut [u8]);
}

/// A shared reference to a source is a source (lets `Arc::new(&STATIC)` be an
/// `Arc<dyn Entropy>`).
impl<E: Entropy + ?Sized> Entropy for &E {
    fn fill(&self, buf: &mut [u8]) {
        (**self).fill(buf)
    }
}

pub fn random_array<const N: usize>(entropy: &dyn Entropy) -> [u8; N] {
    let mut out = [0u8; N];
    entropy.fill(&mut out);
    out
}

/// Adapter for libraries that want a `rand_core` RNG (Ed25519 key generation,
/// Biscuit token construction) so they draw from the platform's entropy.
pub struct EntropyRng<'a>(pub &'a dyn Entropy);

impl rand_core::RngCore for EntropyRng<'_> {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(random_array(self.0))
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(random_array(self.0))
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for EntropyRng<'_> {}
