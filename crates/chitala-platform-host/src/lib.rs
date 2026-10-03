//! Hosted backend of the Chitala PAL (spec `specs/18-platform.md`, Blueprint v20 §3.1).
//!
//! The only crate allowed to call host-OS APIs on behalf of the Trusted Core:
//! files and permission bits, Unix sockets, processes, the system clock, the OS
//! RNG, HTTP and configured character devices. Everything here implements a `chitala-platform` trait and
//! passes `chitala_platform::contract`.
//!
//! Supported hosts: Unix (Linux, macOS). Private storage, IPC and process
//! isolation rely on Unix semantics; other hosts need their own backend
//! (named pipes, ACLs) rather than a weaker fallback.

#![forbid(unsafe_code)]

mod device;
mod exec;
mod fs;
mod ipc;
mod net;

use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use chitala_platform::{Entropy, Platform, Result, SoftwareKeyStore, StoragePath, TimeSource};

pub use device::HostDevices;
pub use exec::ProcessHost;
pub use fs::FsStorage;
pub use ipc::{UnixIpc, MAX_SOCKET_PATH};
pub use net::UreqNetwork;

/// System clock: wall time from the OS, monotonic time from `Instant`.
pub struct SystemTimeSource {
    origin: Instant,
}

impl SystemTimeSource {
    pub fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

impl Default for SystemTimeSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for SystemTimeSource {
    fn wall_ms(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
    fn monotonic_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
}

/// The operating system's CSPRNG. Panics if it fails (fail closed).
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&self, buf: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(buf);
    }
}

/// Storage directory of the key store inside the platform root.
pub const KEYS_DIR: &str = "keys";

/// A hosted platform rooted at `root` (the domain directory): storage and keys
/// under `root`, IPC endpoints next to it (or in a private per-user directory
/// when the path is too long for a Unix socket).
pub fn platform(root: &Path) -> Result<Platform> {
    let entropy: Arc<dyn Entropy> = Arc::new(OsEntropy);
    let storage = Arc::new(FsStorage::new(root)?);
    let keys = SoftwareKeyStore::new(storage.clone(), Arc::clone(&entropy), StoragePath::new(KEYS_DIR)?)?;
    Ok(Platform {
        name: "hosted-unix",
        time: Arc::new(SystemTimeSource::new()),
        entropy,
        keys: Arc::new(keys),
        storage,
        ipc: Arc::new(UnixIpc::new(root)?),
        exec: Arc::new(ProcessHost),
        network: Arc::new(UreqNetwork),
        devices: Arc::new(chitala_platform::NoDevices),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_platform::{contract, ComponentSpec};
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn temp_root(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "chitala-pal-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn hosted_backend_passes_the_contract() {
        let root = temp_root("contract");
        let p = platform(&root).unwrap();
        contract::time(&*p.time);
        contract::entropy(&*p.entropy);
        contract::key_store(&*p.keys);
        let weaken_root = root.clone();
        contract::storage(&*p.storage, &move |path| {
            let f = weaken_root.join(path.as_str());
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644)).unwrap();
        });
        contract::ipc(&*p.ipc);
        let echo = root.join("echo.sh");
        std::fs::write(&echo, "#!/bin/sh\nwhile read l; do echo \"$l\"; done\n").unwrap();
        std::fs::set_permissions(&echo, std::fs::Permissions::from_mode(0o700)).unwrap();
        contract::exec(&*p.exec, &ComponentSpec { program: echo.display().to_string(), env: vec![] });
        // a plain file stands in for a character device
        let dev = chitala_platform::DeviceAddress::new("serial:test").unwrap();
        std::fs::write(root.join("tty"), b"").unwrap();
        let devices = HostDevices::new([(dev.clone(), root.join("tty"), "test line".to_string())]);
        contract::devices(&devices, &dev, false);
        assert_eq!(std::fs::read(root.join("tty")).unwrap(), b"ping\n");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn existing_key_files_keep_working() {
        // domains created before the PAL: keys/<kind>-<local>.key, hex seed + newline
        let root = temp_root("compat");
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::set_permissions(root.join("keys"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let f = root.join("keys/person-alice.key");
        std::fs::write(&f, format!("{}\n", "11".repeat(32))).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let p = platform(&root).unwrap();
        let k = chitala_platform::KeyRef::new("person-alice").unwrap();
        let expected = chitala_platform::SeedSigner::from_seed(&[0x11; 32]);
        use chitala_platform::Signer;
        assert_eq!(p.keys.public_key(&k).unwrap(), expected.public_key());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
