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

/// What a source of randomness is and where its bytes come from (spec 20):
/// the identity a qualification report names (spec 33) and, later, typed
/// evidence. It describes; whether a provider is admitted is the platform's
/// rule, not this type's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntropyProvenance {
    /// A stable identifier: `arm-rndr`, `x86-rdseed`, `os-csprng`, `test-seeded`.
    pub provider_id: &'static str,
    pub source_class: SourceClass,
    /// The bytes come from a hardware noise source, not from software alone.
    pub hardware_backed: bool,
    /// The source in words, for people reading a log or a report.
    pub source: &'static str,
}

/// The kind of thing a provider draws from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceClass {
    /// An instruction of the CPU (`RNDR`, `RDSEED`).
    CpuInstruction,
    /// A random number generator of the board, through a driver.
    BoardDevice,
    /// A security module: a TPM, a secure element.
    SecurityModule,
    /// The host operating system's CSPRNG (Hosted).
    OperatingSystem,
    /// A deterministic generator: tests only, never admitted on a platform.
    Deterministic,
}

impl SourceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceClass::CpuInstruction => "cpu-instruction",
            SourceClass::BoardDevice => "board-device",
            SourceClass::SecurityModule => "security-module",
            SourceClass::OperatingSystem => "operating-system",
            SourceClass::Deterministic => "deterministic",
        }
    }
}

/// The outcome of a provider's health test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntropyHealth {
    Ok,
    Failed(String),
}

/// A source of entropy that says what it is, and tests itself before it is
/// trusted (spec 20). `fill` keeps the `Entropy` contract: it panics rather
/// than return weak bytes.
pub trait EntropyProvider: Entropy {
    fn provenance(&self) -> EntropyProvenance;
    /// Run before the first key is generated. A provider that fails it is not
    /// used, and a platform with no other admitted provider does not start.
    fn health(&self) -> EntropyHealth;
}

/// A start-up test any provider can run on its own output (spec 20): draws
/// `words` 64-bit words and fails on two equal words in a row (a stuck
/// source; for a working one the chance is 2⁻⁶⁴ per pair) or on an all-zero
/// word. It detects a broken source, and cannot prove a good one.
pub fn repetition_test(source: &dyn Entropy, words: usize) -> EntropyHealth {
    let mut previous = None;
    for i in 0..words {
        let word = u64::from_le_bytes(random_array(source));
        if word == 0 {
            return EntropyHealth::Failed(format!("word {i} of {words} is all zeros"));
        }
        if previous == Some(word) {
            return EntropyHealth::Failed(format!("words {} and {i} of {words} are equal: the source is stuck", i - 1));
        }
        previous = Some(word);
    }
    EntropyHealth::Ok
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Constant(u64);
    impl Entropy for Constant {
        fn fill(&self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                chunk.copy_from_slice(&self.0.to_le_bytes()[..chunk.len()]);
            }
        }
    }

    struct Counter(AtomicU64);
    impl Entropy for Counter {
        fn fill(&self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let n = self.0.fetch_add(1, Ordering::SeqCst);
                chunk.copy_from_slice(&n.to_le_bytes()[..chunk.len()]);
            }
        }
    }

    #[test]
    fn a_stuck_source_fails_its_health_test() {
        assert!(
            matches!(repetition_test(&Constant(0x5a5a_5a5a_5a5a_5a5a), 16), EntropyHealth::Failed(m) if m.contains("stuck"))
        );
        assert!(matches!(repetition_test(&Constant(0), 16), EntropyHealth::Failed(m) if m.contains("all zeros")));
    }

    #[test]
    fn a_source_that_changes_passes_the_repetition_test() {
        // the test detects a broken source; it does not judge a weak one
        assert_eq!(repetition_test(&Counter(AtomicU64::new(1)), 64), EntropyHealth::Ok);
        assert_eq!(repetition_test(crate::memory::test_entropy(), 64), EntropyHealth::Ok);
    }

    #[test]
    fn source_classes_have_stable_names() {
        let names: Vec<&str> = [
            SourceClass::CpuInstruction,
            SourceClass::BoardDevice,
            SourceClass::SecurityModule,
            SourceClass::OperatingSystem,
            SourceClass::Deterministic,
        ]
        .iter()
        .map(|c| c.as_str())
        .collect();
        assert_eq!(names, ["cpu-instruction", "board-device", "security-module", "operating-system", "deterministic"]);
    }
}
